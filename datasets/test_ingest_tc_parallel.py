"""Exercise ordered TC decoding through real Avro containers and DuckDB."""

import gzip
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import duckdb
import fastavro
import pytest

DATASETS = Path(__file__).resolve().parent
SCHEMA = {
    'type': 'record', 'name': 'Observation',
    'fields': [
        {'name': 'hostId', 'type': 'string', 'default': 'host'},
        {'name': 'sessionNumber', 'type': 'int', 'default': 0},
        {'name': 'datum', 'type': [
            {'type': 'record', 'name': 'Subject', 'fields': [
                {'name': 'uuid', 'type': 'string'},
                {'name': 'type', 'type': 'string', 'default': 'SUBJECT_PROCESS'},
                {'name': 'parentSubject', 'type': 'string', 'default': ''},
                {'name': 'cmdLine', 'type': 'string', 'default': ''},
                {'name': 'startTimestampNanos', 'type': 'long', 'default': 1},
            ]},
            {'type': 'record', 'name': 'Event', 'fields': [
                {'name': 'uuid', 'type': 'string'},
                {'name': 'type', 'type': 'string', 'default': 'EVENT_EXECUTE'},
                {'name': 'subject', 'type': 'string', 'default': 'child'},
                {'name': 'predicateObject', 'type': 'string', 'default': 'child'},
                {'name': 'timestampNanos', 'type': 'long', 'default': 1},
                {'name': 'properties', 'type': {'type': 'map', 'values': 'string'}, 'default': {}},
            ]},
            {'type': 'record', 'name': 'Other', 'fields': [
                {'name': 'uuid', 'type': 'string'},
            ]},
        ]},
    ],
}


def observation(kind, uuid, host='host', session=0, **fields):
    """Build an explicitly tagged Avro union observation."""
    return {'hostId': host, 'sessionNumber': session,
            'datum': (kind, {'uuid': uuid, **fields})}


def event(uuid, command, **fields):
    """Build a command-bearing event."""
    return observation('Event', uuid, properties={'cmdLine': command}, **fields)


def write_avro(path, observations):
    """Write native Avro, gzip, or a streaming archive with two Avro members."""
    buffer = io.BytesIO()
    fastavro.writer(buffer, SCHEMA, observations)
    payload = buffer.getvalue()
    if path.name.endswith('.tar.gz'):
        with tarfile.open(path, 'w:gz') as archive:
            directory = tarfile.TarInfo('nested')
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            for name, content in [('README.txt', b'ignored'),
                                  ('nested/first.bin', payload),
                                  ('nested/second.bin.1', payload)]:
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    elif path.suffix == '.gz':
        path.write_bytes(gzip.compress(payload))
    else:
        path.write_bytes(payload)


def make_root(tmp_path, collector):
    """Create a spawn-safe CLI entry point in a temporary dataset."""
    root = tmp_path / 'datasets' / f'tc-e5-{collector}'
    (root / 'data').mkdir(parents=True)
    (root / 'ingest').write_text(
        'import sys\nfrom pathlib import Path\n'
        f'sys.path.insert(0, {str(DATASETS)!r})\n'
        'from _ingest import run\nfrom _ingest_tc import records\n'
        'if __name__ == "__main__":\n'
        '    run(Path(__file__).resolve().parent, records)\n'
    )
    return root


def ingest(root, workers, *options):
    """Run the real CLI and return every persisted column and progress output."""
    database = root / f'commands-{workers}.duckdb'
    result = subprocess.run(
        [sys.executable, str(root / 'ingest'), '--db', str(database),
         '--tc-workers', str(workers), '--batch-size', '2', *options],
        capture_output=True, text=True, check=True, timeout=60,
    )
    with duckdb.connect(str(database), read_only=True) as connection:
        rows = connection.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall()
    assert json.loads(result.stdout)['stored'] == len(rows)
    assert not list((root.parents[1] / 'tmp').glob('tc-ingest-*'))
    return rows, result.stderr


@pytest.mark.parametrize('collector', ['fivedirections', 'theia'])
def test_parallel_preserves_order_parents_and_deduplication(tmp_path, collector):
    """File workers preserve cross-file parents, scope, and first-observation IDs."""
    root = make_root(tmp_path, collector)
    write_avro(root / 'data' / 'a.bin', [
        observation('Other', 'ignored'),
        observation('Subject', 'child', parentSubject='old', cmdLine='echo created'),
        event('irrelevant', 'echo ignored', type='EVENT_READ'),
        event('blank', ''),
    ])
    write_avro(root / 'data' / 'b.bin.gz', [
        event('duplicate', 'echo created'),
        event('before', 'echo before'),
        observation('Subject', 'child', parentSubject='new'),
        event('after', 'echo after'),
        observation('Subject', 'child', session=1, parentSubject='restart'),
        event('restart', 'echo restart', session=1),
        event('other-host', 'echo other-host', host='other'),
        event('other-session', 'echo other-session', session=2),
        event('fork', 'echo fork', type='EVENT_FORK', subject='unrelated'),
        event('exit', 'echo exit', type='EVENT_EXIT'),
    ])
    write_avro(root / 'data' / 'c.tar.gz', [
        event('archive', 'echo archive'),
        event('archive-duplicate', 'echo before'),
    ])
    serial, _ = ingest(root, 1)
    parallel, progress = ingest(root, 2)
    assert parallel == serial
    expected = {
        'created': 'host:0:parent:old', 'before': 'host:0:parent:old',
        'after': 'host:0:parent:new', 'restart': 'host:1:parent:restart',
        'other-host': 'other:0:parent:child',
        'other-session': 'host:2:parent:child', 'archive': 'host:0:parent:new',
    }
    if collector == 'fivedirections':
        expected.update(fork='host:0:parent:new', exit='host:0:parent:new')
    assert {row[2][0]: row[7] for row in parallel} == {
        command: f'{root.name}:{session}' for command, session in expected.items()
    }
    assert len(parallel) == len(expected)
    assert all(row[8] == ('windows' if collector == 'fivedirections' else 'linux')
               for row in parallel)
    assert next(row[4] for row in parallel if row[2] == ['created']).startswith('host:Subject:child:')
    for name in ('a.bin', 'b.bin.gz', 'c.tar.gz'):
        assert any(name in line and 'finished scanning' in line
                   and 'retained' in line for line in progress.splitlines())


def test_max_records_counts_source_records_per_file(tmp_path):
    """Filtering must not change the meaning of the source-record cap."""
    root = make_root(tmp_path, 'fivedirections')
    for index, name in enumerate(('a.bin', 'b.bin.gz', 'c.tar.gz')):
        write_avro(root / 'data' / name, [
            observation('Other', 'ignored'),
            event(f'keep-{index}', f'echo keep-{index}'),
            event(f'drop-{index}', f'echo drop-{index}'),
        ])
    serial, _ = ingest(root, 1, '--max-records', '2')
    parallel, _ = ingest(root, 2, '--max-records', '2')
    assert serial == parallel
    assert sorted(row[2] for row in parallel) == [['keep-0'], ['keep-1'], ['keep-2']]


def test_limit_closes_reader_before_unread_corrupt_file(tmp_path):
    """Early limits clean scratch state and avoid speculative reads of later input."""
    root = make_root(tmp_path, 'fivedirections')
    write_avro(root / 'data' / 'a.bin', [event('first', 'echo first')])
    (root / 'data' / 'b.bin').write_bytes(b'invalid Avro container')
    rows, _ = ingest(root, 2, '--limit', '1')
    assert [row[2] for row in rows] == [['first']]


@pytest.mark.parametrize('workers', [1, 2])
def test_failed_scan_cleans_workers_and_preserves_committed_batch(tmp_path, workers):
    """A corrupt later file surfaces its error without losing durable commands."""
    root = make_root(tmp_path, 'fivedirections')
    write_avro(root / 'data' / 'a.bin', [
        event('first', 'echo first'), event('second', 'echo second'),
    ])
    (root / 'data' / 'b.bin').write_bytes(b'invalid Avro container')
    database = root / 'commands.duckdb'
    result = subprocess.run(
        [sys.executable, str(root / 'ingest'), '--db', str(database),
         '--tc-workers', str(workers), '--batch-size', '2'],
        capture_output=True, text=True, check=False, timeout=60,
    )
    assert result.returncode != 0
    assert 'Traceback' in result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT args FROM COMMANDS ORDER BY args').fetchall() == [
            (['first'],), (['second'],),
        ]
    assert not list((root.parents[1] / 'tmp').glob('tc-ingest-*'))


@pytest.mark.parametrize('workers', ['0', '-1'])
def test_workers_must_be_positive(tmp_path, workers):
    """Reject worker counts that cannot execute the scan."""
    root = make_root(tmp_path, 'fivedirections')
    result = subprocess.run(
        [sys.executable, str(root / 'ingest'), '--tc-workers', workers],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 2
    assert 'must be positive' in result.stderr


def test_empty_dataset_finishes_without_workers(tmp_path):
    """No source files still yields an empty database and cleans scratch state."""
    root = make_root(tmp_path, 'fivedirections')
    rows, progress = ingest(root, 2)
    assert rows == []
    assert 'finished in' in progress
