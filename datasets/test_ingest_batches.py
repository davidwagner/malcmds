"""Exercise durable ingest batches with actual DuckDB errors and subprocesses."""

import json
import subprocess
import sys
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parent


def invoke(root, database, source, *options):
    """Run the shared writer over source commands in an isolated process."""
    driver = root / 'driver.py'
    driver.write_text(
        f'import sys\nfrom pathlib import Path\nsys.path.insert(0, {str(ROOT)!r})\n'
        'from _ingest import Command, run\n' + source
        + '\nrun(Path(__file__).parent, records)\n'
    )
    return subprocess.run(
        [sys.executable, str(driver), '--db', str(database), *options],
        capture_output=True, text=True, check=False,
    )


def test_failed_batch_preserves_commits_and_retry_replaces(tmp_path):
    """A real constraint failure loses only its batch; corrected retries finish."""
    database = tmp_path / 'commands.duckdb'
    source = """
def records(root, options):
    for i in range(7):
        yield Command('echo', [str(i)], str(i), label='malicious-group' if i == 5 else 'unknown')
"""
    result = invoke(tmp_path, database, source, '--batch-size', '3')
    assert result.returncode != 0
    assert 'ConstraintException' in result.stderr
    assert 'cannot rollback' not in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT record_id FROM COMMANDS ORDER BY record_id').fetchall() == [('0',), ('1',), ('2',)]
    corrected = source.replace("label='malicious-group' if i == 5 else 'unknown'", "label='unknown'")
    for attempt in range(2):
        result = invoke(tmp_path, database, corrected, '--batch-size', '3')
        assert result.returncode == 0, result.stderr
        if attempt == 0:
            assert json.loads(result.stdout)['stored'] == 7
        else:
            assert json.loads(result.stdout)['skipped'] is True


def test_large_ingest_under_small_memory_limit(tmp_path):
    """Plain inserts fit a small memory budget even with large record identifiers."""
    source = """
def records(root, options):
    for i in range(300000):
        yield Command('echo', [str(i)], f'{i:09d}:' + 'x' * 500)
"""
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, source, '--memory-limit', '64MB', '--batch-size', '1000')
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['stored'] == 300000
    # Repeat with a different batch size and a bounded source sample.
    result = invoke(tmp_path, database, source, '--memory-limit', '64MB', '--batch-size', '777', '--limit', '3000')
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['skipped'] is True
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (300000,)


def test_write_oom_reports_original_error(tmp_path):
    """A real write OOM is reported without a secondary rollback exception."""
    source = """
def records(root, options):
    for i in range(100000):
        yield Command('echo', [str(i)], f'{i:09d}:' + 'x' * 500)
"""
    result = invoke(tmp_path, tmp_path / 'commands.duckdb', source, '--memory-limit', '4MB')
    assert result.returncode != 0
    assert 'Memory' in result.stderr or 'memory' in result.stderr
    assert 'cannot rollback' not in result.stderr


def test_empty_iterable_and_invalid_commands(tmp_path):
    """Readers may return lists; invalid identities fail without database rows."""
    database = tmp_path / 'commands.duckdb'
    source = "def records(root, options):\n    return []\n"
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['stored'] == 0
    for command in ("Command('', [], 'id')", "Command('echo', [], '')"):
        with duckdb.connect(str(database)) as con:
            con.execute("DELETE FROM INGESTED")
        result = invoke(tmp_path, database, source.replace('[]', f'[{command}]'))
        assert result.returncode != 0
        assert 'Command requires nonempty pgm and record_id' in result.stderr
        assert 'cannot rollback' not in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (0,)


def test_mixed_command_and_arrow_batches_report_timing(tmp_path):
    """Both reader formats preserve order and report shared writer timings."""
    source = """
from _ingest import command_table

def records(root, options):
    yield Command('echo', ['first'], 'duplicate')
    yield command_table([
        Command('echo', ['later'], 'duplicate'),
        Command('echo', ['arrow'], 'arrow'),
    ], root.name)
    yield Command('echo', ['full-1'], 'full-1')
    yield Command('echo', ['full-2'], 'full-2')
    yield Command('echo', ['tail'], 'tail')
"""
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, source, '--batch-size', '2')
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['processed'] == 6
    assert json.loads(result.stdout)['stored'] == 6
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT record_id, args FROM COMMANDS ORDER BY record_id, args').fetchall() == [
            ('arrow', ['arrow']), ('duplicate', ['first']), ('duplicate', ['later']),
            ('full-1', ['full-1']), ('full-2', ['full-2']), ('tail', ['tail']),
        ]
    progress = [line for line in result.stderr.splitlines() if 'batches committed' in line]
    assert len(progress) == 3
    for line in progress:
        assert 'commands/s' in line
        assert 'batch write' in line
        assert 'total write' in line
    assert 'read/normalize' in result.stderr
    assert 'finished in' in result.stderr
