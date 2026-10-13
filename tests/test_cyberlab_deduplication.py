"""Copied CyberLab observations are removed before command parsing.

The compressed fixtures contain complete published event lists. Other outer
entries are replaced with empty objects, preserving all source positions and
all fields (including decimal numbers). June/November contain copied records;
September contains legitimate repeated automation; May contains observations
shared across entries/files; December contains separate connections with the
same command and timestamp. Locations are from issue #136 and its investigation:
https://github.com/davidwagner/malcmds/issues/136

The unsupported-value error cannot be reached through gzip JSON ingestion:
the JSON reader only returns objects, arrays, strings, numbers, booleans and null.
Exercising that error would require replacing the real reader with a test double.
"""

import gzip
import json
import shutil
from pathlib import Path

import duckdb
import pytest
from test_ingest_batches import invoke

FIXTURES = Path(__file__).parent / 'fixtures/cyberlab-dedup'
READER = 'from _ingest_misc import cyberlab as records\n'


def _ingest(root):
    database = root / 'commands.duckdb'
    result = invoke(root, database, READER, timeout=180)
    assert result.returncode == 0, result.stderr
    return duckdb.connect(str(database))


def _write(root, records, name='events.json.gz'):
    (root / name).write_bytes(gzip.compress(json.dumps(records).encode()))


@pytest.mark.parametrize(('date', 'index', 'sid', 'count'), [
    ('2019-06-03', 4656, 'de7261b1', 4997),
    ('2019-06-01', 9902, 'aa09a67c', 4702),
    ('2019-06-02', 70, '59ffc7c2', 4701),
    ('2019-11-12', 131, '7e70fbc4c525', None),
    ('2019-09-15', None, 'ea5db584ab99', 8974),
])
def test_published_copies_and_automation(tmp_path, date, index, sid, count):
    """Keep first source positions and the published process counts."""
    name = f'cyberlab_{date}.json.gz'
    shutil.copyfile(FIXTURES / name, tmp_path / name)
    records = json.loads(gzip.decompress((tmp_path / name).read_bytes()))
    if index is None:
        index = next(i for i, row in enumerate(records) if sid in row)
    events = records[index][sid]
    has_input = any(e.get('eventid') == 'cowrie.command.input' for e in events)
    selected = []
    seen = []
    for position, event in enumerate(events):
        if event.get('timestamp') and event in seen:
            continue
        seen.append(event)
        if event.get('eventid') in (['cowrie.command.input'] if has_input else
                                   ['cowrie.command.success', 'cowrie.command.failed']):
            selected.append((position, event))
    with _ingest(tmp_path) as con:
        rows = con.execute('SELECT record_id,pgm,args,dataset_label,group_id,session_id FROM PROCESS_LAUNCHES').fetchall()
        if count is not None:
            assert len(rows) == count
        assert all(r[3:5] == ('malicious', None) for r in rows)
        assert all(r[5].endswith(':' + sid) for r in rows)
        assert {r[0].rsplit(':', 1)[0] for r in rows} == {
            f'{name}:{index}:{sid}:{position}' for position, _ in selected}
        if has_input:
            shells = dict(con.execute('SELECT record_id,shell_input FROM SHELL_INPUTS').fetchall())
            assert shells == {f'{name}:{index}:{sid}:{position}':
                              event.get('input') or event['message'].removeprefix('CMD: ')
                              for position, event in selected}
            if date == '2019-11-12':
                assert sum(e.get('eventid') == 'cowrie.command.input' for e in events) - len(shells) == 19
                assert shells[f'{name}:{index}:{sid}:8'] == 'cat /proc/cpuinfo | grep name | wc -l'
                assert f'{name}:{index}:{sid}:9' not in shells
            else:
                assert len(shells) == 4486
        else:
            expected = {f'{name}:{index}:{sid}:{position}':
                        event['message'].removeprefix('Command found: ').removeprefix('Command not found: ')
                        for position, event in selected}
            assert all(' '.join([r[1], *r[2]]) == expected[r[0].rsplit(':', 1)[0]].strip() for r in rows)


def test_full_record_equality_and_missing_timestamps(tmp_path):
    """Every field participates; object order, JSON type and precision matter."""
    base = {'eventid': 'cowrie.command.input', 'timestamp': '2019-01-01T00:00:00Z',
            'input': 'echo same', 'nested': {'a': [1, 2], 'b': None}}
    reordered = dict(reversed(list(base.items())))
    reordered['nested'] = {'b': None, 'a': [1, 2]}
    events = [base, reordered]
    changes = [{'timestamp': '2019-01-01T00:00:01Z'}, {'src_port': 1234},
               {'dst_host_identifier': 'other'}, {'sensor': 'other'},
               {'nested': {'a': [2, 1], 'b': None}}, {'nested': {'a': [True, 2], 'b': None}},
               {'nested': {'a': ['1', 2], 'b': None}}, {'nested': {'a': [1, 2]}},
               {'message': 'different'}, {'input': 'echo different'},
               {'eventid': 'cowrie.command.failed'}]
    events.extend(base | change for change in changes)
    for timestamp in [None, '']:
        event = base | {'timestamp': timestamp}
        events.extend([event, event])
    untimed = {k: v for k, v in base.items() if k != 'timestamp'}
    events.extend([untimed, untimed])
    # Write numeric tokens directly so ijson really receives exact Decimal values.
    raw = json.dumps([{'session': events}])
    decimals = ['1.0000000000000000001', '1.0000000000000000002',
                '"1.0000000000000000001"', '1', 'true', '1.0']
    extra = [json.dumps(base)[:-1] + ',"number":' + number + '}' for number in decimals]
    decimal_equivalent = json.dumps(base)[:-1] + ',"number":1.00}'
    raw = raw[:-3] + ',' + ','.join(extra + [extra[0], decimal_equivalent]) + ']}]'
    (tmp_path / 'events.json.gz').write_bytes(gzip.compress(raw.encode()))
    with _ingest(tmp_path) as con:
        positions = {int(r[0].rsplit(':', 1)[1]) for r in con.execute('SELECT record_id FROM SHELL_INPUTS').fetchall()}
        expected = set(range(len(events) + len(decimals))) - {1, 12}
        assert positions == expected
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (len(expected),)


def test_scope_continuations_and_input_preference(tmp_path):
    """Deduplicate before joining fragments, resetting for each published list."""
    first = {'eventid': 'cowrie.command.input', 'timestamp': 'one', 'input': 'echo \\'}
    second = {'eventid': 'cowrie.command.input', 'timestamp': 'two', 'input': 'hello; id'}
    handler = {'eventid': 'cowrie.command.success', 'timestamp': 'three', 'message': 'Command found: echo ignored'}
    events = [first, first, second, second, handler, handler]
    records = [{}, {'same': events, 'other': events}, {'same': events}]
    _write(tmp_path, records, 'a.json.gz')
    _write(tmp_path, records, 'b.json.gz')
    with _ingest(tmp_path) as con:
        shells = con.execute('SELECT record_id,shell_input FROM SHELL_INPUTS').fetchall()
        assert set(shells) == {(f'{name}.json.gz:{entry}:{sid}:0', 'echo \\\nhello; id')
                               for name in ['a', 'b'] for entry, sid in [(1, 'same'), (1, 'other'), (2, 'same')]}
        rows = con.execute('SELECT pgm,args FROM PROCESS_LAUNCHES').fetchall()
        assert len(rows) == 12
        assert rows.count(('echo', ['hello'])) == rows.count(('id', [])) == 6


def test_published_cross_entry_file_and_distinct_connections(tmp_path):
    """Published shared non-command records stay harmless; separate commands stay."""
    dates = ['2019-05-14', '2019-05-19', '2019-05-23', '2019-12-08']
    for date in dates:
        name = f'cyberlab_{date}.json.gz'
        shutil.copyfile(FIXTURES / name, tmp_path / name)
    with _ingest(tmp_path) as con:
        rows = con.execute("SELECT record_id,session_id FROM PROCESS_LAUNCHES WHERE pgm='uname'").fetchall()
        assert {r[0].split(':')[1] for r in rows} == {'24645', '25388'}
        assert len({r[1] for r in rows}) == 2
        assert con.execute("SELECT count(*) FROM PROCESS_LAUNCHES WHERE record_id LIKE 'cyberlab_2019-05-%'").fetchone() == (0,)


def test_handler_types_and_nested_container_types(tmp_path):
    """Different handler types and containers retain separate observations."""
    base = {'eventid': 'cowrie.command.success', 'timestamp': 'one', 'input': 'uname'}
    failed = base | {'eventid': 'cowrie.command.failed'}
    events = [base, base, failed, failed, base | {'details': []},
              base | {'details': {}}, base | {'details': None}]
    _write(tmp_path, [{'same': events}])
    with _ingest(tmp_path) as con:
        rows = con.execute('SELECT record_id,pgm,args,dataset_label,group_id FROM PROCESS_LAUNCHES').fetchall()
        assert {r[0] for r in rows} == {f'events.json.gz:0:same:{index}:0' for index in [0, 2, 4, 5, 6]}
        assert all(r[1:] == ('uname', [], 'malicious', None) for r in rows)
