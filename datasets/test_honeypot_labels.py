"""Remote honeypot inputs retain attack labels and shell syntax in storage."""
import gzip
import json
import zipfile
from pathlib import Path

import duckdb
import pytest
from test_ingest_batches import invoke


@pytest.mark.parametrize('dataset', ['microsoft', 'cyberlab'])
def test_published_honeypot_commands(tmp_path, dataset):
    """Archive and Bash parser upgrades must preserve remote input and suppress echoes."""
    data = json.loads((Path(__file__).parent/f'fixtures/honeypot/{dataset}.json').read_text())
    if dataset == 'microsoft':
        with zipfile.ZipFile(tmp_path/'Microsoft.IoT-Dump-pwd-infected.zip', 'w') as archive:
            archive.writestr('Microsoft.IoT-Dump1.json', json.dumps(data))
        source = 'from _ingest_misc import microsoft_iot as records\n'
        inputs = data[0]['Commands']
    else:
        # Also retain a useful handler-only observation without claiming complete input.
        data.append({'fallback': [{'eventid': 'cowrie.command.failed', 'message': 'Command not found: missing'}]})
        (tmp_path/'sample.json.gz').write_bytes(gzip.compress(json.dumps(data).encode()))
        source = 'from _ingest_misc import cyberlab as records\n'
        inputs = [e.get('input') or e['message'].removeprefix('CMD: ') for e in next(iter(data[0].values())) if e['eventid']=='cowrie.command.input']
    database = tmp_path/'commands.duckdb'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute('SELECT pgm,args,label,group_id,session_id,shell_input,other_tokens FROM COMMANDS ORDER BY record_id').fetchall()
    assert rows and all(r[2]=='malicious' and r[3] is None and r[4] for r in rows)
    assert set(r[5] for r in rows if r[5] is not None) == set(inputs)
    assert any(';' in r[6] for r in rows), 'Bash parser lost multi-command input syntax'
    if dataset == 'cyberlab':
        assert sum(r[0]=='system' for r in rows) == 1, 'A failed handler echo must not duplicate original input'
        assert [(r[0],r[5],r[6]) for r in rows if r[0]=='missing'] == [('missing',None,[])]
        assert len({r[4] for r in rows if r[0]!='missing'}) == 1
    else:
        assert len({r[4] for r in rows}) == 1
    again = invoke(tmp_path, database, source)
    assert again.returncode == 0, again.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone()[0] == len(rows)
