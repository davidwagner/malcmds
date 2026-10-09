"""End-to-end checks for parallel OpTC parsing and the PROCESS line prefilter."""

import gzip
import json
import subprocess
import sys
from pathlib import Path

import duckdb
import pyarrow as pa
import pytest

DATASETS = Path(__file__).resolve().parent
sys.path.insert(0, str(DATASETS))
from _ingest import SCHEMA, Command, command_table


def event(record, command, image='cmd.exe', obj='PROCESS'):
    """Return one eCAR event dict for a process observation."""
    return {
        'action': 'CREATE', 'actorID': 'parent-' + record, 'hostname': 'SysClient0201.systemia.com',
        'id': record, 'object': obj, 'objectID': 'process-' + record,
        'principal': 'user', 'properties': {'command_line': command, 'image_path': image},
        'timestamp': '2019-09-23T12:00:00.000-04:00',
    }


def write_stream(path, lines):
    """Write raw JSON lines to a gzip file, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, 'wt', encoding='utf-8') as stream:
        stream.write(''.join(line + '\n' for line in lines))


def ingest(root, database, *options):
    """Run the OpTC reader through the real writer in a separate interpreter.

    The driver needs a __main__ guard because worker processes are started with
    the spawn method, which re-imports the main module.
    """
    driver = root / 'driver.py'
    driver.write_text(
        f'import sys\nfrom pathlib import Path\nsys.path.insert(0, {str(DATASETS)!r})\n'
        'from _ingest import run\nfrom _ingest_optc import records\n'
        "if __name__ == '__main__':\n    run(Path(__file__).parent, records)\n"
    )
    return subprocess.run([sys.executable, str(driver), '--db', str(database), *options],
                          capture_output=True, text=True, check=False)


def rows(database):
    """Return every stored row in a stable order."""
    with duckdb.connect(str(database), read_only=True) as con:
        return con.execute('SELECT pgm,pgm_base,args,dataset,record_id,label,group_id,session_id,os,shell_input,other_tokens FROM COMMANDS ORDER BY record_id, args').fetchall()


def build_dataset(root):
    """Create four streams with a cross-file duplicate and prefilter edge cases."""
    ecar = root / 'ecar'
    escaped = json.dumps(event('escaped', 'whoami /all')).replace('"PROCESS"', '"\\u0050ROCESS"')
    write_stream(ecar / 'benign' / 'h1' / 'a.json.gz', [
        json.dumps(event('shared', 'cmd /c benign-copy')),
        json.dumps({'object': 'FLOW', 'id': 'flow', 'properties': {'command_line': 'ignored'}}),
        json.dumps(event('b1', 'cmd /c one')),
        json.dumps(event('b2', 'cmd /c two')),
    ])
    write_stream(ecar / 'benign' / 'h2' / 'b.json.gz', [
        escaped,
        json.dumps(event('unicode', 'cmd /c echo caf\u00e9')),
        json.dumps(event('file-event', 'PROCESS', obj='FILE')),
        '',
    ])
    write_stream(ecar / 'evaluation' / 'h3' / 'c.json.gz', [
        json.dumps(event('shared', 'cmd /c evaluation-copy')),
        json.dumps(event('e1', 'cmd /c three')),
    ])
    write_stream(ecar / 'short' / 'h4' / 'd.json.gz', [
        json.dumps(event(f's{i}', f'cmd /c short {i}')) for i in range(5)
    ])


def test_parallel_rows_match_serial_rows(tmp_path):
    """Worker processes must store exactly the rows a single process stores."""
    root = tmp_path / 'optc'
    build_dataset(root)
    serial, parallel = tmp_path / 'serial.duckdb', tmp_path / 'parallel.duckdb'
    for database, workers in ((serial, '1'), (parallel, '3')):
        result = ingest(root, database, '--workers', workers, '--batch-size', '2')
        assert result.returncode == 0, result.stderr
    expected = rows(serial)
    assert rows(parallel) == expected
    by_id = {row[4]: row for row in expected}
    # Duplicate source records are retained, including their original labels.
    assert [(row[2], row[5]) for row in expected if row[4] == 'shared:0'] == [
        (['/c', 'benign-copy'], 'benign'), (['/c', 'evaluation-copy'], 'malicious-group'),
    ]
    # The prefilter must not drop a PROCESS event spelled with \u escapes.
    assert by_id['escaped:0'][2] == ['/all']
    assert by_id['unicode:0'][2] == ['/c', 'echo', 'caf\u00e9']
    assert 'file-event:0' not in by_id
    assert len(expected) == 12
    # Temporary Arrow files are removed after a successful run.
    assert not list((tmp_path / 'tmp' / 'ingest').glob('optc-*'))
    rerun = ingest(root, parallel, '--workers', '3')
    assert rerun.returncode == 0, rerun.stderr
    assert rows(parallel) == expected


def test_parallel_limits_match_serial_limits(tmp_path):
    """--limit and --max-records select the same commands with any worker count."""
    root = tmp_path / 'optc'
    build_dataset(root)
    for options in (('--limit', '3'), ('--max-records', '1'), ('--limit', '7', '--max-records', '3')):
        stored = []
        for workers in ('1', '4'):
            database = tmp_path / f'{workers}-{"-".join(options)}.duckdb'
            result = ingest(root, database, '--workers', workers, '--batch-size', '2', *options)
            assert result.returncode == 0, result.stderr
            stored.append(rows(database))
        assert stored[0] == stored[1], options
        assert stored[0]
    assert not list((tmp_path / 'tmp' / 'ingest').glob('optc-*'))


def test_worker_failure_keeps_earlier_files(tmp_path):
    """A corrupt file fails the run after earlier files' batches are committed."""
    root = tmp_path / 'optc'
    write_stream(root / 'ecar' / 'benign' / 'h' / 'a.json.gz',
                 [json.dumps(event('a', 'cmd /c fine'))])
    corrupt = root / 'ecar' / 'benign' / 'h' / 'b.json.gz'
    corrupt.write_bytes(b'not gzip data')
    database = tmp_path / 'commands.duckdb'
    result = ingest(root, database, '--workers', '2')
    assert result.returncode != 0
    assert 'BadGzipFile' in result.stderr
    assert [row[4] for row in rows(database)] == ['a:0']
    assert not list((tmp_path / 'tmp' / 'ingest').glob('optc-*'))


def test_real_process_events_pass_prefilter():
    """Every real PROCESS event must contain the text the prefilter looks for.

    If this fails, the eCAR files encode the object field differently than
    assumed, and _ingest_optc.file_commands would silently skip commands.
    """
    files = sorted((DATASETS / 'optc' / 'ecar').rglob('*.json.gz'))
    if not files:
        pytest.skip('Original OpTC data is not installed')
    checked = 0
    with gzip.open(files[0], 'rt', encoding='utf-8', errors='replace') as stream:
        for number, line in enumerate(stream):
            if number >= 200000:
                break
            if json.loads(line).get('object') == 'PROCESS':
                assert '"PROCESS"' in line or '\\u00' in line, line
                checked += 1
    assert checked > 0


def test_arrow_and_duckdb_assumptions(tmp_path):
    """Check library behavior that parallel ingestion relies on.

    Workers write lz4-compressed Arrow IPC streams, and the main process inserts
    the decoded tables into DuckDB's ENUM and VARCHAR[] columns. A pyarrow or
    DuckDB upgrade that drops lz4 IPC support or changes Arrow-to-ENUM casting
    breaks OpTC ingestion; these assertions name the broken assumption.
    """
    assert pa.Codec.is_available('lz4'), 'pyarrow build lacks lz4, used by _ingest_optc.write_file_tables'
    table = command_table([Command('C:\\Windows\\cmd.exe', ['/c', 'x'], 'r', 'malicious-group', 'g', '', 'windows'),
                           Command('cmd.exe', ['retained duplicate'], 'r', os='windows')], 'optc')
    path = tmp_path / 'batch.arrow'
    options = pa.ipc.IpcWriteOptions(compression='lz4')
    with pa.OSFile(str(path), 'wb') as sink, pa.ipc.new_stream(sink, SCHEMA, options=options) as writer:
        writer.write_table(table)
    with pa.OSFile(str(path), 'rb') as source:
        decoded = pa.ipc.open_stream(source).read_all()
    assert decoded.equals(table), 'Arrow IPC lz4 round trip changed the batch'
    with duckdb.connect() as con:
        con.execute("CREATE TYPE command_label AS ENUM ('malicious', 'benign', 'unknown', 'malicious-group')")
        con.execute("CREATE TYPE command_os AS ENUM ('windows', 'linux')")
        con.execute('CREATE TABLE t (pgm VARCHAR, pgm_base VARCHAR, args VARCHAR[], shell_input VARCHAR, other_tokens VARCHAR[], dataset VARCHAR, '
                    'record_id VARCHAR, label command_label, group_id VARCHAR, session_id VARCHAR, os command_os)')
        con.register('batch', decoded)
        con.execute('INSERT INTO t SELECT * FROM batch')
        assert con.execute('SELECT * FROM t').fetchall() == [
            ('C:\\Windows\\cmd.exe', 'cmd.exe', ['/c', 'x'], None, [], 'optc', 'r', 'malicious-group', 'g',
             'optc:record:r', 'windows'),
            ('cmd.exe', 'cmd.exe', ['retained duplicate'], None, [], 'optc', 'r', 'unknown', None,
             'optc:record:r', 'windows')], 'DuckDB no longer casts Arrow strings into the COMMANDS columns'
