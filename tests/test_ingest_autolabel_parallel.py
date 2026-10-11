"""Exercise independent AutoLabel runs through real workers, archives and DuckDB.

Network and disk exhaustion require external fault injection. These tests use
real malformed exports for worker failures and close live generators to exercise
cancellation without substituting workers or archive readers.
"""

import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import duckdb
import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def event(number, **changes):
    """Build a Sysdig event with stable attempt and process identifiers."""
    return {'evt.type': 'execve', 'evt.num': number, 'container.id': 'container',
            'proc.vpid': 10, 'evt.rawres': 0, 'proc.cmdline': 'id --user',
            'proc.exepath': '/usr/bin/id', 'malicious': False} | changes


def log(*events):
    """Encode events as the exporter's newline-delimited JSON format."""
    return b''.join(json.dumps(item).encode() + b'\n' for item in events)


def tar_bytes(members, compressed=False):
    """Build real tar members in source order, optionally gzip compressed."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz' if compressed else 'w') as archive:
        for name, payload in members:
            member = tarfile.TarInfo(name)
            if payload is None:
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def archive_root(tmp_path, members, name='scenario.tar', compressed=False):
    """Write an outer scenario into a dataset directory recognized by the CLI."""
    root = tmp_path / 'datasets' / 'autolabel'
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_bytes(tar_bytes(members, compressed))
    return root


def ingest(root, database, workers, *extra, check=True):
    """Run the actual ingestion driver and worker processes in a fresh Python."""
    driver = ('import sys; from pathlib import Path; '
              f'sys.path.insert(0, {str(SCRIPTS)!r}); '
              'from _ingest import run; from _ingest_autolabel import records; '
              f'run(Path({str(root)!r}), records)')
    return subprocess.run(
        [sys.executable, '-c', driver, '--db', str(database), '--workers', str(workers),
         '--batch-size', '2', *extra], capture_output=True, text=True,
        check=check, timeout=90,
    )


def rows(database):
    """Read every persisted field in insertion order, including list arguments."""
    with duckdb.connect(str(database), read_only=True) as connection:
        return connection.execute('SELECT * FROM COMMANDS ORDER BY rowid').fetchall()


def completed(database):
    """Read the retry marker written by the production database driver."""
    with duckdb.connect(str(database), read_only=True) as connection:
        return connection.execute('SELECT * FROM INGESTED').fetchall()


def assert_clean(root):
    """Ensure cancellation and completion remove worker and database scratch."""
    scratch = root.parent.parent / 'tmp' / 'ingest'
    assert not list(scratch.glob('autolabel-*'))
    assert not list(scratch.rglob('*.arrow'))
    assert not list(scratch.glob('duckdb-spill/duckdb-*'))


def test_parallel_progress_and_order(tmp_path):
    """Parallel execution must be observable and preserve every stored column."""
    shell = event(3, **{'proc.cmdline': "sh -c printf '%s' safe; id",
                       'proc.exepath': '/bin/sh'})
    root = archive_root(tmp_path, [
        ('first.tar.gz', tar_bytes([('sysdig/events.log', log(event(1), event(2), shell))], True)),
        ('second.tar', tar_bytes([('sysdig/events.log', log(event(1)))])),
    ])
    serial, parallel = tmp_path / 'serial.db', tmp_path / 'parallel.db'
    ingest(root, serial, 1)
    result = ingest(root, parallel, 3)
    assert 'completed run 2/2' in result.stderr, 'Requested workers must execute independent runs and report run completion'
    assert rows(parallel) == rows(serial), 'PyArrow IPC must preserve every command column and source order for the shared DuckDB writer'
    assert len(rows(parallel)) == 4
    assert rows(parallel)[2][2] == ['-c', "printf '%s' safe; id"], 'Parallel IPC must retain flat Sysdig shell payload quotes and operators'
    assert completed(parallel) == [('autolabel', True)]
    assert_clean(root)


def test_nested_formats_cross_log_state_labels_and_failed_attempts(tmp_path):
    """Rotated logs share ancestry and duplicates; independent runs keep IDs."""
    parent = event(1, malicious=True)
    first = log(parent, event(2, **{'evt.type': 'clone', 'evt.rawres': 20}))
    second = log(
        parent,
        event(3, **{'proc.vpid': 20, 'malicious': 'Suspicious',
                    'proc.cmdline': 'id A#t#k#F#1#--user'}),
        event(4, **{'evt.type': 'execveat', 'evt.rawres': -2,
                    'evt.arg.filename': '/missing/tool',
                    'evt.arg.argv': ['/missing/tool', 'A#t#k#F#2#--probe'],
                    'malicious': None}),
        event(5, **{'evt.type': 'exit', 'proc.vpid': 20}),
        event(6, **{'proc.vpid': 20}),
    )
    run = [('sysdig', None), ('sysdig/one.log', first), ('sysdig/two.log', second)]
    root = archive_root(tmp_path, [
        ('scenario', None),
        ('./scenario/run.tar.gz', tar_bytes(run, True)),
        ('scenario/run.tgz', tar_bytes(run, True)),
        ('scenario/run.tar', tar_bytes(run)),
        ('scenario/deep.tar', tar_bytes([('child.tar.gz', tar_bytes(run, True))])),
        ('ignored.txt', b'not an export'),
    ])
    serial, parallel = tmp_path / 'serial.db', tmp_path / 'parallel.db'
    ingest(root, serial, 1)
    result = ingest(root, parallel, 3)
    assert 'completed run 4/4' in result.stderr
    assert rows(parallel) == rows(serial)
    assert len(rows(parallel)) == 16
    with duckdb.connect(str(parallel), read_only=True) as connection:
        attempts = connection.execute(
            'SELECT record_id,args,label,group_id,session_id FROM COMMANDS ORDER BY rowid'
        ).fetchall()
    for offset in range(0, 16, 4):
        a, b, c, d = attempts[offset:offset + 4]
        assert a[2] == 'malicious'
        assert b[1] == ['--user'] and b[2] == 'malicious-group'
        assert b[3] == b[0].rsplit(':container:', 1)[0]
        assert a[4] == b[4], 'Clone ancestry must survive log rotation in each worker'
        assert c[1:3] == (['--probe'], 'unknown')
        assert d[4] != b[4], 'A reused PID must begin a new process lifetime'
    assert len({row[0] for row in attempts}) == 16
    assert len({attempts[index][4] for index in range(0, 16, 4)}) == 4
    assert_clean(root)


def test_max_records_counts_each_log(tmp_path):
    """The event budget restarts for each log, including logs in one run."""
    root = archive_root(tmp_path, [
        (f'run-{index}.tar', tar_bytes([
            ('sysdig/one.log', log(event(1), event(2))),
            ('sysdig/two.log', log(event(3), event(4))),
        ])) for index in range(3)
    ])
    for workers in (1, 3):
        result = ingest(root, tmp_path / f'{workers}.db', workers, '--max-records', '1')
        if workers == 3:
            assert 'completed run 3/3' in result.stderr
        assert completed(tmp_path / f'{workers}.db') == [('autolabel', False)]
    assert rows(tmp_path / '1.db') == rows(tmp_path / '3.db')
    assert len(rows(tmp_path / '3.db')) == 6
    assert_clean(root)


def test_limit_stops_before_corrupt_unread_run(tmp_path):
    """A limited request must retain streaming fallback and avoid unread errors."""
    root = archive_root(tmp_path, [
        ('valid.tar', tar_bytes([('sysdig/events.log', log(event(1)))])),
        ('corrupt.tar.gz', b'this is not a compressed archive'),
    ])
    for workers in (1, 3):
        result = ingest(root, tmp_path / f'{workers}.db', workers, '--limit', '1')
        assert 'completed run' not in result.stderr
        assert completed(tmp_path / f'{workers}.db') == [('autolabel', False)]
    assert rows(tmp_path / '1.db') == rows(tmp_path / '3.db')
    assert len(rows(tmp_path / '3.db')) == 1
    assert_clean(root)


@pytest.mark.parametrize('layout', ['gzip', 'tgz', 'compressed-tar-suffix', 'mixed', 'direct'])
def test_unsupported_outer_layout_uses_serial_fallback(tmp_path, layout):
    """Compression and direct outer logs preserve the established serial reader."""
    members = [('run.tar', tar_bytes([('sysdig/events.log', log(event(1)))]))]
    if layout in {'mixed', 'direct'}:
        direct = ('sysdig/direct.log', log(event(1), event(2)))
        members = [direct, *members] if layout == 'mixed' else [direct]
    compressed = layout in {'gzip', 'tgz', 'compressed-tar-suffix'}
    name = {'gzip': 'scenario.tar.gz', 'tgz': 'scenario.tgz'}.get(layout, 'scenario.tar')
    root = archive_root(tmp_path, members, name=name, compressed=compressed)
    ingest(root, tmp_path / 'serial.db', 1)
    result = ingest(root, tmp_path / 'parallel.db', 3)
    assert 'completed run' not in result.stderr
    assert rows(tmp_path / 'parallel.db') == rows(tmp_path / 'serial.db')
    assert completed(tmp_path / 'parallel.db') == [('autolabel', True)]
    assert_clean(root)


def test_outer_sampling_and_incomplete_manifest(tmp_path):
    """Sampling selects whole outer archives and incomplete releases cannot pass."""
    for index in range(3):
        root = archive_root(tmp_path, [
            ('first.tar', tar_bytes([('sysdig/events.log', log(event(1)))])),
            ('second.tar', tar_bytes([('sysdig/events.log', log(event(2)))])),
        ], name=f'scenario-{index}.tar')
    (root / 'release.json').write_text(json.dumps([
        {'name': f'scenario-{index}.tar'} for index in range(4)
    ]))
    for workers in (1, 3):
        database = tmp_path / f'sample-{workers}.db'
        result = ingest(root, database, workers, '--sample-files', '1', '--seed', '5')
        if workers == 3:
            assert 'completed run 2/2' in result.stderr
        assert len(rows(database)) == 2
        assert completed(database) == [('autolabel', False)]
        missing = tmp_path / f'missing-{workers}.db'
        failed = ingest(root, missing, workers, check=False)
        assert failed.returncode != 0 and 'release is incomplete' in failed.stderr
        assert completed(missing) == [('autolabel', False)]
        assert rows(missing) == []
    assert rows(tmp_path / 'sample-1.db') == rows(tmp_path / 'sample-3.db')
    assert_clean(root)


def test_worker_error_retains_prior_runs_and_retry_replaces_attempt(tmp_path):
    """A malformed run fails visibly without discarding earlier committed runs."""
    good = ('first.tar', tar_bytes([('sysdig/events.log', log(event(1), event(2)))]))
    root = archive_root(tmp_path, [
        good,
        ('second.tar', tar_bytes([('sysdig/events.log', log(event(3)) + b'{broken}\n')])),
        ('third.tar', tar_bytes([('sysdig/events.log', log(event(4)))])),
    ])
    database = tmp_path / 'retry.db'
    result = ingest(root, database, 2, check=False)
    assert result.returncode != 0 and 'JSONDecodeError' in result.stderr
    assert 'completed run 1/3' in result.stderr
    assert completed(database) == [('autolabel', False)]
    assert len(rows(database)) == 2
    assert all('first.tar:' in row[6] for row in rows(database))
    assert_clean(root)
    driver = f"""
import json
import multiprocessing
import sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, {str(SCRIPTS)!r})
from _ingest_autolabel import records
options = SimpleNamespace(workers=2, max_records=None, limit=None,
                          batch_size=2, sample_files=None, seed=0)
reader = records(Path({str(root)!r}), options)
assert next(reader).num_rows == 2
try:
    next(reader)
except json.JSONDecodeError:
    pass
else:
    raise AssertionError('A malformed run must report its worker error')
assert not multiprocessing.active_children(), 'Worker failures must reap children before propagating'
"""
    subprocess.run([sys.executable, '-c', driver], check=True, capture_output=True,
                   text=True, timeout=90)
    assert_clean(root)
    archive_root(tmp_path, [good, ('second.tar', tar_bytes([('sysdig/events.log', log(event(3)))]))])
    ingest(root, database, 2)
    assert completed(database) == [('autolabel', True)]
    assert len(rows(database)) == 3, 'Retry must replace the incomplete attempt without duplicating earlier batches'
    assert_clean(root)


@pytest.mark.parametrize('members', [[], [('empty.tar', tar_bytes([]))],
                                      [('ignored.tar', tar_bytes([('readme.txt', b'no logs')]))],
                                      [('silent.tar', tar_bytes([('sysdig/events.log', log(event(1, **{'evt.type': 'read'})))]))]])
def test_empty_runs_complete_and_clean_up(tmp_path, members):
    """Empty archives and runs with no commands still complete without leaks."""
    root = archive_root(tmp_path, members)
    database = tmp_path / 'empty.db'
    result = ingest(root, database, 3)
    if members:
        assert 'completed run 1/1' in result.stderr
    assert rows(database) == []
    assert completed(database) == [('autolabel', True)]
    assert_clean(root)


def test_arrow_batches_and_early_close_stop_worker_processes(tmp_path):
    """Arrow batch sizes stay bounded and closing iteration reaps live workers."""
    root = archive_root(tmp_path, [
        (f'run-{index}.tar.gz', tar_bytes([
            ('sysdig/events.log', log(*(event(number) for number in range(1, 8))))
        ], True)) for index in range(5)
    ])
    driver = ('import sys, multiprocessing; from pathlib import Path; '
              'from types import SimpleNamespace; import pyarrow as pa; '
              f'sys.path.insert(0, {str(SCRIPTS)!r}); '
              'from _ingest_autolabel import records; '
              'options=SimpleNamespace(workers=2,max_records=None,limit=None,'
              'batch_size=2,sample_files=None,seed=0); '
              f'root=Path({str(root)!r}); reader=records(root,options); '
              'first=next(reader); assert isinstance(first,pa.Table), "Worker IPC must yield Arrow tables accepted by the shared DuckDB writer"; '
              'assert first.num_rows==2, "PyArrow IPC must preserve the configured batch row count"; '
              'assert 0<len(multiprocessing.active_children())<=2; '
              'scratch=root.parent.parent / "tmp" / "ingest"; '
              'assert 0<len(list(scratch.rglob("*.arrow")))<=2; '
              'reader.close(); assert not multiprocessing.active_children(); '
              'batches=list(records(root,options)); '
              'assert all(isinstance(batch,pa.Table) and 0<batch.num_rows<=2 for batch in batches), '
              '"PyArrow IPC must preserve Arrow tables and configured batch row bounds for the shared DuckDB writer"; '
              'assert sum(batch.num_rows for batch in batches)==35; '
              'assert not multiprocessing.active_children()')
    subprocess.run([sys.executable, '-c', driver], check=True, capture_output=True,
                   text=True, timeout=90)
    assert_clean(root)


def test_multiple_outer_archives_mix_serial_and_arrow_outputs(tmp_path):
    """Outer order survives transitions between commands and worker Arrow batches."""
    root = archive_root(tmp_path, [('sysdig/direct.log', log(event(1)))], name='a.tar')
    archive_root(tmp_path, [
        ('first.tar', tar_bytes([('sysdig/events.log', log(event(1), event(2)))])),
        ('second.tar', tar_bytes([('sysdig/events.log', log(event(1)))])),
    ], name='b.tar')
    archive_root(tmp_path, [('sysdig/compressed.log', log(event(1)))],
                 name='c.tar.gz', compressed=True)
    serial, parallel = tmp_path / 'serial.db', tmp_path / 'parallel.db'
    ingest(root, serial, 1)
    result = ingest(root, parallel, 3)
    assert 'b.tar: completed run 2/2' in result.stderr
    assert rows(parallel) == rows(serial), 'The shared DuckDB writer must commit pending serial commands before worker Arrow tables'
    assert [row[6] for row in rows(parallel)] == [
        'a.tar:container:1',
        'b.tar/first.tar:container:1',
        'b.tar/first.tar:container:2',
        'b.tar/second.tar:container:1',
        'c.tar.gz:container:1',
    ]
    assert completed(parallel) == [('autolabel', True)]
    assert_clean(root)
