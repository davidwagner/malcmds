"""Exercise bounded OpTC reads and gzip compatibility through the real CLI."""

import gzip
import json

import pytest
from test_ingest_optc_parallel import event, ingest, rows, write_stream


def test_limit_does_not_parse_the_rest_of_a_file(tmp_path):
    """A command limit must stop parsing before malformed later observations."""
    root = tmp_path / 'optc'
    write_stream(root / 'ecar' / 'a.json.gz', [
        json.dumps(event('first', 'cmd /c first')),
        '{"object": "PROCESS", broken JSON',
    ])
    write_stream(root / 'ecar' / 'b.json.gz', [json.dumps(event('later', 'cmd /c later'))])
    database = tmp_path / 'limited.duckdb'
    result = ingest(root, database, '--workers', '2', '--limit', '1')
    assert result.returncode == 0, result.stderr
    assert [row[4] for row in rows(database)] == ['first:0']
    assert not list((tmp_path / 'tmp' / 'ingest').glob('optc-*'))
    complete = ingest(root, tmp_path / 'complete.duckdb', '--workers', '2')
    assert complete.returncode != 0
    assert 'JSONDecodeError' in complete.stderr


@pytest.mark.parametrize('damage', ['none', 'crc', 'truncated'])
def test_gzip_members_unicode_and_integrity(tmp_path, damage):
    """The decoder must preserve concatenated members and reject damaged streams."""
    root = tmp_path / 'optc'
    directory = root / 'ecar'
    directory.mkdir(parents=True)
    first = json.dumps(event('first', 'cmd /c café'), ensure_ascii=False)
    second = json.dumps(event('second', 'whoami')).replace('PROCESS', r'\u0050ROCESS')
    payload = gzip.compress((first + '\r\n').encode()) + gzip.compress(second.encode())
    if damage == 'crc':
        payload = payload[:-8] + bytes([payload[-8] ^ 1]) + payload[-7:]
    elif damage == 'truncated':
        payload = payload[:-4]
    (directory / 'events.json.gz').write_bytes(payload)
    database = tmp_path / 'commands.duckdb'
    result = ingest(root, database, '--workers', '1')
    if damage != 'none':
        assert result.returncode != 0, 'gzip decoder silently accepted a damaged trailer'
        assert 'CRC' in result.stderr or 'EOFError' in result.stderr, result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert [(row[4], row[2]) for row in rows(database)] == [
            ('first:0', ['/c', 'café']), ('second:0', []),
        ]


def test_attack_window_endpoints_and_unknown_hosts(tmp_path):
    """Host indexing retains inclusive windows, timezone conversion and group IDs."""
    root = tmp_path / 'optc'
    cases = [
        ('start', 'sysclient0201', '2019-09-23T15:23:29Z', 'malicious-group'),
        ('end', 'sysclient0201', '2019-09-23T15:30:00-04:00', 'malicious-group'),
        ('after', 'sysclient0201', '2019-09-23T15:30:00.000001-04:00', 'unknown'),
        ('other', 'unreported', '2019-09-23T12:00:00-04:00', 'unknown'),
        ('missing', 'sysclient0201', None, 'unknown'),
        ('naive', 'sysclient0201', '2019-09-23T12:00:00', 'malicious-group'),
        ('numeric', 'sysclient0201', 1569254400000, 'malicious-group'),
    ]
    events = []
    for record, host, timestamp, _ in cases:
        observation = event(record, 'whoami')
        observation.update(hostname=host, timestamp=timestamp)
        events.append(json.dumps(observation))
    write_stream(root / 'ecar' / 'events.json.gz', events)
    database = tmp_path / 'commands.duckdb'
    result = ingest(root, database)
    assert result.returncode == 0, result.stderr
    actual = {row[4]: (row[5], row[6]) for row in rows(database)}
    group = ('optc:empire-day1:sysclient0201:2019-09-23T11:23:29/'
             '2019-09-23T15:30:00:America_New_York')
    assert actual == {record + ':0': (label, group if label == 'malicious-group' else None)
                      for record, _, _, label in cases}


def test_missing_streams_reports_the_input_error(tmp_path):
    """An empty source directory must fail instead of marking ingestion complete."""
    root = tmp_path / 'optc'
    root.mkdir()
    result = ingest(root, tmp_path / 'empty.duckdb')
    assert result.returncode != 0
    assert 'No completed OpTC eCAR gzip files' in result.stderr
