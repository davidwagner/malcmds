"""Published Wazuh annotations survive CSV ingestion and storage."""
import csv
import json
from pathlib import Path

import duckdb
from test_ingest_batches import invoke


def test_native_annotations_and_unannotated_inventory(tmp_path):
    """Rule fallback and missing tags must keep their documented label meanings."""
    examples = json.loads((Path(__file__).parent/'fixtures/windows-apt/labels.json').read_text())
    rows = list(examples.values())
    prefix = '_source.data.win.eventdata.'
    for tags in ['', '[]']:
        rows.append({'_id': 'empty-'+tags, prefix+'commandLine': 'cmd.exe', '_source.rule.mitre.id': tags, '_source.rule.id': '11'})
    rows.append({'_id': 'inventory', '_source.data.process.cmd': '/bin/ls', '_source.data.process.args': '-l', '_source.rule.id': '92031'})
    (tmp_path/'source').mkdir()
    with (tmp_path/'source/combined.csv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=sorted(set().union(*(r.keys() for r in rows))))
        writer.writeheader()
        writer.writerows(rows)
    database = tmp_path/'commands.duckdb'
    source = 'from _ingest_misc import windows_apt as records\n'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        saved = con.execute('SELECT record_id,label,group_id,session_id FROM COMMANDS').fetchall()
    by_id = {row[0]: row[1:] for row in saved}
    for name, row in examples.items():
        rid = row['_index']+':'+row['_id']+':0'
        assert by_id[rid][0] == ('unknown' if name == 'rule-11' else 'malicious')
    assert all(label == 'unknown' for rid, label, _, _ in saved if rid.startswith(':'))
    assert all(group is None and session for _, _, group, session in saved)
    again = invoke(tmp_path, database, source)
    assert again.returncode == 0, again.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone()[0] == len(rows)
