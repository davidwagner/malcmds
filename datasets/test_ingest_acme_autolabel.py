"""Exercise released ACME and AutoLabel records through the database CLI.

Fixtures retain original published process fields. Network/disk failure paths
require external fault injection and are not represented by fabricated events.
"""

import io
import json
import tarfile
from pathlib import Path

import duckdb
import pyarrow as pa
import pytest
from pyarrow import parquet
from test_ingest_batches import invoke

FIXTURES = Path(__file__).parent / 'fixtures' / 'issue57'


@pytest.mark.parametrize('dataset', ['acme3', 'acme4'])
def test_acme_released_arguments_labels_and_duplicates(tmp_path, dataset):
    """Publisher argument-only fields retain options and browser labels improve."""
    root = tmp_path / dataset
    root.mkdir()
    rows = json.loads((FIXTURES / f'{dataset}.json').read_text())
    parquet.write_table(pa.Table.from_pylist(rows + rows[:2]), root / 'process_uber_summary.parquet')
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_acme import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone()[0] == len({row['pid_hash'] for row in rows})
        assert con.execute("SELECT count(*) FROM COMMANDS WHERE record_id NOT LIKE dataset || ':%'").fetchone() == (0,)
        args = con.execute("SELECT args FROM COMMANDS WHERE pgm_base='svchost.exe'").fetchall()
        assert args and all(row[0][:2] == ['-k', 'unistacksvcgroup'] for row in args), 'ACME args is argument-only: dropping argv[0] loses -k'
        assert con.execute("SELECT DISTINCT label FROM COMMANDS WHERE pgm_base IN ('chrome.exe','msedge.exe')").fetchall() == [('benign',)]
        assert con.execute("SELECT count(*) FROM COMMANDS WHERE label='malicious'").fetchone()[0] >= 1
        assert con.execute('SELECT count(*) FROM COMMANDS WHERE shell_input IS NOT NULL OR len(other_tokens)>0').fetchone() == (0,)
        assert con.execute("SELECT count(*) FROM COMMANDS WHERE session_id != dataset || ':record:' || record_id").fetchone() == (0,)
        if dataset == 'acme4':
            assert con.execute("SELECT count(*) FROM COMMANDS WHERE label='malicious-group' AND group_id LIKE 'acme4:%'").fetchone()[0] >= 1
        assert con.execute("SELECT count(*) FROM COMMANDS WHERE (label='malicious-group') != (group_id IS NOT NULL)").fetchone() == (0,)
    rerun = invoke(root, database, 'from _ingest_acme import records\n')
    assert rerun.returncode == 0 and json.loads(rerun.stdout)['skipped'] is True


def test_autolabel_real_export_nested_archives_and_process_lifetimes(tmp_path):
    """The real exporter has no evt.dir and retains the malicious no-arg id."""
    root = tmp_path / 'autolabel'
    root.mkdir()
    source = (FIXTURES / 'autolabel-sysdig.jsonl').read_bytes()
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode='w:gz') as archive:
        member = tarfile.TarInfo('./sysdig/events.log')
        member.size = len(source)
        archive.addfile(member, io.BytesIO(source))
        # A second representation of the same export cannot add attempts.
        member = tarfile.TarInfo('./sysdig/repeated.log')
        member.size = len(source)
        archive.addfile(member, io.BytesIO(source))
    with tarfile.open(root / 'scenario.tar', 'w') as archive:
        member = tarfile.TarInfo('scenario/run.tar.gz')
        member.size = len(inner.getvalue())
        archive.addfile(member, io.BytesIO(inner.getvalue()))
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_autolabel import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT label,count(*) FROM COMMANDS GROUP BY label ORDER BY label::VARCHAR').fetchall() == [('benign', 362), ('malicious', 2)], 'AutoLabel exporter emits one combined observation per exec, without evt.dir'
        assert con.execute("SELECT pgm,args FROM COMMANDS WHERE label='malicious' ORDER BY pgm").fetchall() == [('/bin/dash', ['-c', 'id']), ('/usr/bin/id', [])]
        assert con.execute("SELECT count(DISTINCT session_id) FROM COMMANDS WHERE label='malicious'").fetchone() == (1,), 'clone ancestry should connect the malicious shell and its id child'
        assert con.execute('SELECT count(*) FROM COMMANDS WHERE shell_input IS NOT NULL OR len(other_tokens)>0 OR group_id IS NOT NULL').fetchone() == (0,)
    rerun = invoke(root, database, 'from _ingest_autolabel import records\n')
    assert rerun.returncode == 0 and json.loads(rerun.stdout)['skipped'] is True

    bounded = tmp_path / 'bounded.duckdb'
    result = invoke(root, bounded, 'from _ingest_autolabel import records\n', '--max-records', '7')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(bounded)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (1,)
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)


def _write_autolabel_events(root, events):
    payload = ''.join(json.dumps(event) + '\n' for event in events).encode()
    with tarfile.open(root / 'events.tar', 'w') as archive:
        member = tarfile.TarInfo('sysdig/events.log')
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))


def test_autolabel_failed_attempts_and_uncertain_labels(tmp_path):
    """Variants of real exporter rows exercise failure metadata and label rules."""
    root = tmp_path / 'autolabel'
    root.mkdir()
    original = next(event for line in (FIXTURES / 'autolabel-sysdig.jsonl').read_text().splitlines() if (event := json.loads(line))['evt.type'] == 'execve')
    events = []
    changes = [
        {'evt.type': 'execveat', 'evt.rawres': -2, 'evt.arg.filename': '/missing/program', 'evt.arg.argv': ['/missing/program', '--probe'], 'malicious': 'Suspicious'},
        {'evt.rawres': -13, 'evt.arg.filename': '/forbidden/program', 'evt.arg.args': '--literal value', 'malicious': None},
        {'evt.rawres': -2, 'evt.arg.filename': '/missing/program', 'evt.arg.args': '"unterminated'},
        {'evt.rawres': -2, 'evt.arg.filename': None},
        {'evt.rawres': -2, 'evt.arg.filename': None, 'evt.arg.argv': ['--probe']},
        {'proc.cmdline': '', 'proc.exepath': '/usr/bin/id', 'malicious': True},
        {'proc.cmdline': 'chrome --type=renderer', 'proc.exepath': '/usr/bin/chrome', 'malicious': 'Suspicious'},
        {'proc.cmdline': 'python A#t#k#F#1#gen.py', 'proc.vpid': None, 'proc.pid': None, 'thread.vtid': None},
        {'evt.rawres': -2, 'evt.arg.filename': None, 'proc.cmdline': ''},
        {'evt.type': 'procexit'},
        {'evt.type': 'read'},
    ]
    for index, change in enumerate(changes):
        events.append(original | {'evt.num': 1000000 + index} | change)
    _write_autolabel_events(root, events)
    (root / 'release.json').write_text(json.dumps([{'name': 'events.tar'}]))
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_autolabel import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (9,)
        assert con.execute("SELECT pgm,args,label,group_id FROM COMMANDS WHERE record_id LIKE '%:1000000'").fetchone() == ('/missing/program', ['--probe'], 'malicious-group', 'events.tar')
        assert con.execute("SELECT pgm,args,label FROM COMMANDS WHERE record_id LIKE '%:1000001'").fetchone() == ('/forbidden/program', ['--literal', 'value'], 'unknown')
        assert con.execute("SELECT label FROM COMMANDS WHERE pgm='/usr/bin/id'").fetchone() == ('malicious',)
        assert con.execute("SELECT label,group_id FROM COMMANDS WHERE pgm='/usr/bin/chrome'").fetchone() == ('benign', None)
        assert con.execute("SELECT args,session_id FROM COMMANDS WHERE record_id LIKE '%:1000007'").fetchone() == (['gen.py'], 'autolabel:record:events.tar:f146f0498642:1000007')


@pytest.mark.parametrize('change,message', [
    ({'evt.num': ''}, 'missing evt.num'),
    ({'evt.rawres': -2, 'proc.exepath': None, 'proc.name': None, 'proc.cmdline': '', 'evt.arg.argv': ['--probe']}, 'has no executable'),
])
def test_autolabel_missing_required_identity_is_retryable(tmp_path, change, message):
    """An incompatible exporter must fail before declaring the dataset complete."""
    original = next(event for line in (FIXTURES / 'autolabel-sysdig.jsonl').read_text().splitlines() if (event := json.loads(line))['evt.type'] == 'execve')
    _write_autolabel_events(tmp_path, [original | change])
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_autolabel import records\n')
    assert result.returncode != 0 and message in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)


def test_autolabel_missing_partition_cannot_complete(tmp_path):
    """A local subset of the manifest must not masquerade as the full release."""
    _write_autolabel_events(tmp_path, [])
    (tmp_path / 'release.json').write_text(json.dumps([{'name': 'events.tar'}, {'name': 'missing.tar'}]))
    result = invoke(tmp_path, tmp_path / 'commands.duckdb', 'from _ingest_autolabel import records\n')
    assert result.returncode != 0 and 'release is incomplete' in result.stderr


def test_acme_schema_change_and_bounded_inspection(tmp_path):
    """Argument-only assumptions and incomplete samples remain explicit."""
    rows = json.loads((FIXTURES / 'acme3.json').read_text())
    source = tmp_path / 'process_uber_summary.parquet'
    parquet.write_table(pa.Table.from_pylist(rows), source)
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_acme import records\n', '--max-records', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (1,)
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
    parquet.write_table(pa.Table.from_pylist([{'renamed_hash': 'value', 'args': '-k unistacksvcgroup'}]), source)
    result = invoke(tmp_path, database, 'from _ingest_acme import records\n')
    assert result.returncode != 0 and 'ACME summary changed' in result.stderr


def test_autolabel_without_archives_is_retryable(tmp_path):
    """Missing downloads cannot be marked as a completed empty release."""
    result = invoke(tmp_path, tmp_path / 'commands.duckdb', 'from _ingest_autolabel import records\n')
    assert result.returncode != 0 and 'No AutoLabel archives' in result.stderr


def test_acme_reviewed_gold_flag_without_graph_summary(tmp_path):
    """The explicit gold flag remains usable when detailed annotations are absent."""
    rows = json.loads((FIXTURES / 'acme4.json').read_text())
    row = next(row for row in rows if row['red_team'] == 1 and row['label_num_hits'] and row['process_name'] == 'powershell.exe')
    row.pop('label_num_hits')
    parquet.write_table(pa.Table.from_pylist([row]), tmp_path / 'process_uber_summary.parquet')
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_acme import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT label FROM COMMANDS').fetchone() == ('malicious',)
