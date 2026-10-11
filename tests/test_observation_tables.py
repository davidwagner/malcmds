"""Exercise the two observation tables through the actual ingest CLI and DuckDB."""

import json

import duckdb
import pytest
from test_ingest_batches import invoke


def test_shell_observations_are_atomic_and_keep_all_tokens(tmp_path):
    """Parser and Arrow upgrades must preserve source order and repeated programs."""
    database = tmp_path / 'observations.duckdb'
    source = '''
from _ingest import ShellInput, shell_commands
def records(root, options):
    text = '/bin/ls "dir name" > out; ./go; ./go'
    commands = [Command(pgm, args, f'line:{i}')
                for i, (pgm, args, _) in enumerate(shell_commands(text))]
    yield ShellInput(text, 'line', commands)
    yield ShellInput('X=one >out', 'assignment', [])
    yield Command('/usr/bin/id', [], 'native')
'''
    result = invoke(tmp_path, database, source, '--batch-size', '1')
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert (summary['processed'], summary['stored'], summary['process_launches'], summary['shell_inputs']) == (3, 6, 4, 2)
    with duckdb.connect(str(database)) as con:
        assert con.execute('SHOW TABLES').fetchall() == [
            ('INGESTED',), ('PROCESS_LAUNCHES',), ('SHELL_INPUTS',)]
        assert con.execute('SELECT pgm, args FROM PROCESS_LAUNCHES ORDER BY record_id').fetchall() == [
            ('/bin/ls', ['dir name']), ('./go', []), ('./go', []), ('/usr/bin/id', [])]
        assert con.execute('SELECT record_id, pgms, tokens FROM SHELL_INPUTS ORDER BY record_id').fetchall() == [
            ('assignment', [], ['X=one', '>', 'out']),
            ('line', ['ls', 'go', 'go'], ['/bin/ls', '"dir name"', '>', 'out', ';', './go', ';', './go'])]
        assert con.execute('SELECT DISTINCT dataset_label FROM SHELL_INPUTS').fetchall() == [('unknown',)]


def test_failed_shell_batch_rolls_back_both_tables(tmp_path):
    """A real enum failure must never leave a launch without its shell observation."""
    database = tmp_path / 'observations.duckdb'
    source = '''
from _ingest import ShellInput
def records(root, options):
    yield ShellInput('id', 'good', [Command('id', [], 'good:0')])
    yield ShellInput('ls', 'bad', [Command('ls', [], 'bad:0')], label='invalid')
'''
    result = invoke(tmp_path, database, source, '--batch-size', '1')
    assert result.returncode != 0
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT record_id FROM PROCESS_LAUNCHES').fetchall() == [('good:0',)]
        assert con.execute('SELECT record_id FROM SHELL_INPUTS').fetchall() == [('good',)]
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
    result = invoke(tmp_path, database, source.replace("label='invalid'", "label='benign'"))
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (2,)
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone() == (2,)


def test_limit_keeps_complete_observation_and_retry_replaces_both_tables(tmp_path):
    """A limit cannot split a compound input or permanently mark it complete."""
    database = tmp_path / 'observations.duckdb'
    source = '''
from _ingest import ShellInput, command_table
def records(root, options):
    yield ShellInput('ls; id', 'line', [Command('ls', [], 'line:0'), Command('id', [], 'line:1')])
    yield command_table([Command('echo', ['x'], 'native')], root.name)
'''
    result = invoke(tmp_path, database, source, '--limit', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (2,)
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone() == (1,)
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (3,)
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone() == (1,)
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (True,)


def test_invalid_shell_identity_cannot_be_stored(tmp_path):
    """Reject observations that cannot be traced to a dataset record."""
    source = '''
from _ingest import ShellInput
def records(root, options):
    yield ShellInput('id', '', [Command('id', [], 'child')])
'''
    database = tmp_path / 'observations.duckdb'
    result = invoke(tmp_path, database, source)
    assert result.returncode != 0
    assert 'ShellInput requires nonempty record_id' in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (0,)
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone() == (0,)


def test_unfinished_shell_input_is_still_an_observation(tmp_path):
    """A capture ending within a here-document must retain the submitted text."""
    source = '''
from _ingest import ShellInput, shell_commands
from _shell_input import complete_inputs
def records(root, options):
    for index, text in complete_inputs(['cat <<END', 'captured body']):
        commands = [Command(pgm, args, str(i)) for i, (pgm, args, _) in enumerate(shell_commands(text))]
        yield ShellInput(text, str(index), commands)
'''
    database = tmp_path / 'observations.duckdb'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT shell_input,pgms FROM SHELL_INPUTS').fetchall() == [('cat <<END\ncaptured body', [])]
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (0,)


@pytest.mark.parametrize('table', ['PROCESS_LAUNCHES', 'SHELL_INPUTS'])
def test_incompatible_observation_schema_cannot_be_skipped(tmp_path, table):
    """Completion flags must not hide an incompatible table after an upgrade."""
    database = tmp_path / 'incompatible.duckdb'
    with duckdb.connect(str(database)) as con:
        con.execute(f'CREATE TABLE {table}(record_id VARCHAR)')
        con.execute(f"INSERT INTO {table} VALUES ('preserve')")
        con.execute('CREATE TABLE INGESTED(dataset VARCHAR, ingested BOOLEAN)')
        con.execute('INSERT INTO INGESTED VALUES (?, true)', [tmp_path.name])
    result = invoke(tmp_path, database, 'def records(root, options):\n    return []\n')
    assert result.returncode != 0
    assert f'{table} uses an incompatible schema' in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute(f'SELECT * FROM {table}').fetchall() == [('preserve',)]
