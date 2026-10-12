"""Exercise preliminary lifetime scans through the real OpTC ingestion CLI.

These fixtures protect text buffering, JSON decoder compatibility, and global
lifetime merging when gzip, simdjson, or multiprocessing dependencies change.
"""

import gzip
import json

import pytest
from test_ingest_optc_parallel import ingest, rows, write_stream
from test_optc_labels import install_labels, labels, synthetic_event


START = '2019-09-23T11:23:55.100-04:00'
REBOOT = '2019-09-23T11:24:00-04:00'
AFTER = '2019-09-23T11:24:01-04:00'


def boot():
    """Return a host reboot that separates otherwise identical process IDs."""
    return dict(object='HOST', action='REBOOT', hostname='SYSCLIENT0201', timestamp=REBOOT)


def test_six_worker_lifetimes_match_serial_across_encodings(tmp_path):
    """Merge PID reuse and reboot evidence across six files and gzip members."""
    root = tmp_path / 'optc'
    install_labels(root, [], intervals=[('sysclient0201', '5452', START, 'Infinity')])
    first = synthetic_event('first', START, 'first-process')
    first['properties']['command_line'] = 'cmd.exe /c café'
    reused = synthetic_event('reused', '2019-09-23T11:23:56-04:00', 'reused-process')
    before = synthetic_event('before', START, 'persistent-process', pid=42)
    after = synthetic_event('after', AFTER, 'persistent-process', pid=42)
    long_event = synthetic_event('long', START, 'long-process', pid=88)
    long_event['padding'] = 'x' * (2 * 1024 * 1024 + 31)
    # Reuse is in a lexically earlier file than the original launch. Include
    # escapes in the object value and field name, plus duplicate JSON keys.
    payloads = [
        json.dumps(reused).replace('"PROCESS"', r'"\u0050ROCESS"'),
        json.dumps(boot()).replace('"object"', r'"\u006fbject"'),
        json.dumps(first, ensure_ascii=False),
        json.dumps(before),
        json.dumps(after),
        json.dumps(long_event),
        '{"object":"FLOW",' + json.dumps(synthetic_event('duplicate', START, 'duplicate-process', pid=99))[1:],
        json.dumps(dict(synthetic_event('fallback', START, 'fallback-process', pid=100),
                        large=10 ** 100, nonfinite=float('nan'))),
    ]
    directory = root / 'ecar' / 'evaluation'
    directory.mkdir(parents=True)
    for number, payload in enumerate(payloads):
        # Bare CR, CRLF, blank lines and no final newline must retain records.
        # Splitting a member inside a record verifies concatenated gzip support.
        raw = ('\r\n\r' + payload).encode('utf-8')
        midpoint = len(raw) // 2
        (directory / f'{number}.json.gz').write_bytes(
            gzip.compress(raw[:midpoint]) + gzip.compress(raw[midpoint:]))
    outputs = []
    for workers in ('1', '6'):
        database = tmp_path / f'{workers}.duckdb'
        result = ingest(root, database, '--workers', workers)
        assert result.returncode == 0, result.stderr
        assert 'optc: starting preliminary lifetime scan' in result.stderr
        actual = labels(database)
        assert set(actual) == {'first', 'reused', 'before', 'after', 'long', 'duplicate', 'fallback'}
        assert actual['first'] == ('malicious', None)
        assert actual['reused'][0] == 'malicious-group', 'Cross-file PID reuse did not cap the published interval'
        assert actual['before'][0] == actual['after'][0] == 'malicious-group'
        output = rows(database)
        assert next(row[2] for row in output if row[4] == 'first:0') == ['/c', 'café']
        outputs.append(output)
        assert not list((root / 'tmp').glob('optc-*'))
    assert outputs[0] == outputs[1], 'Parallel lifetime merging changed stored process commands'
    for workers in ('1', '6'):
        database = tmp_path / f'limited-{workers}.duckdb'
        result = ingest(root, database, '--workers', workers, '--limit', '1')
        assert result.returncode == 0, result.stderr
        assert list(labels(database)) == ['reused']
        assert labels(database)['reused'][0] == 'malicious-group', (
            'A command limit must still scan later files for earlier PID lifetimes')


@pytest.mark.parametrize('max_records', [1, 2, 3])
def test_record_budget_counts_blank_lines_and_excludes_late_reboots(tmp_path, max_records):
    """Each file has its own physical-line budget, including blank lines."""
    root = tmp_path / 'optc'
    install_labels(root, [])
    for number in range(6):
        event = synthetic_event(f'event-{number}', START if number < 3 else AFTER, 'same-process', pid=42)
        write_stream(root / 'ecar' / 'evaluation' / f'{number}.json.gz',
                     ['', json.dumps(event), json.dumps(boot())])
    outputs = []
    for workers in ('1', '6'):
        database = tmp_path / f'{workers}.duckdb'
        result = ingest(root, database, '--workers', workers, '--max-records', str(max_records))
        assert result.returncode == 0, result.stderr
        assert 'optc: starting preliminary lifetime scan' in result.stderr
        output = rows(database)
        assert len(output) == {1: 0, 2: 1, 3: 2}[max_records], (
            'The preliminary scan read reboot evidence past the per-file record budget, '
            'or failed to separate process identity at a selected reboot')
        outputs.append(output)
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize('workers', ['1', '6'])
@pytest.mark.parametrize('failure', ['json', 'gzip'])
def test_preliminary_failure_announced_without_publishing_rows(tmp_path, workers, failure):
    """Real decode failures stop both worker modes before any rows are stored.

    OS-level pool-start and I/O failures cannot be induced portably without
    test doubles; real malformed gzip and JSON exercise worker error transport.
    """
    root = tmp_path / 'optc'
    install_labels(root, [])
    for number in range(6):
        write_stream(root / 'ecar' / 'evaluation' / f'{number}.json.gz',
                     [json.dumps(synthetic_event(f'event-{number}', START, f'process-{number}'))])
    corrupt = root / 'ecar' / 'evaluation' / '5.json.gz'
    if failure == 'json':
        write_stream(corrupt, ['{"object":"HOST",'])
        expected = 'JSONDecodeError'
    else:
        corrupt.write_bytes(b'not a gzip stream')
        expected = 'BadGzipFile'
    database = tmp_path / 'commands.duckdb'
    result = ingest(root, database, '--workers', workers)
    assert result.returncode != 0
    assert expected in result.stderr
    assert result.stderr.index('optc: starting preliminary lifetime scan') < result.stderr.index(expected)
    assert rows(database) == [], 'A failed lifetime scan must not publish incomplete process selection'
    assert not list((root / 'tmp').glob('optc-*'))
