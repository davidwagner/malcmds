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


def test_session_inheritance_preserves_objects_and_explicit_ids(tmp_path):
    """Persist repeated conversions and reused children without changing the inputs."""
    from copy import deepcopy

    from _ingest import Command, ShellInput, _initialize, _insert, observation_tables

    shared = Command('echo', ['hello'], 'unrelated-child', label='benign')
    explicit = Command('id', [], 'explicit-child', session_id='ssh:99')
    observations = [
        ShellInput('echo hello; id', 'first', [shared, explicit]),
        ShellInput('echo hello', 'second', [shared]),
        ShellInput('echo hello; id', 'native-shell', [shared, explicit], session_id='ssh:42'),
        ShellInput('VALUE=one', 'empty', []),
        Command('id', [], 'standalone'),
        Command('id', [], 'standalone-again'),
        Command('id', [], 'native-process', session_id='native:7'),
    ]
    original = deepcopy(observations)
    with duckdb.connect(str(tmp_path / 'sessions.duckdb')) as con:
        _initialize(con)
        previous = None
        for dataset in ('example', 'example', 'other'):
            batch = observation_tables(observations, dataset)
            if dataset == 'example' and previous is not None:
                assert all(a.equals(b) for a, b in zip(batch, previous))
            previous = batch
            _insert(con, batch)
            assert con.execute('SELECT record_id,session_id FROM PROCESS_LAUNCHES ORDER BY rowid').fetchall() == [
                ('unrelated-child', f'{dataset}:record:first'),
                ('explicit-child', 'ssh:99'),
                ('unrelated-child', f'{dataset}:record:second'),
                ('unrelated-child', 'ssh:42'),
                ('explicit-child', 'ssh:99'),
                ('standalone', f'{dataset}:record:standalone'),
                ('standalone-again', f'{dataset}:record:standalone-again'),
                ('native-process', 'native:7'),
            ]
            assert con.execute('SELECT record_id,session_id FROM SHELL_INPUTS ORDER BY rowid').fetchall() == [
                ('first', f'{dataset}:record:first'),
                ('second', f'{dataset}:record:second'),
                ('native-shell', 'ssh:42'),
                ('empty', f'{dataset}:record:empty'),
            ]
            assert observations == original
            con.execute('DELETE FROM PROCESS_LAUNCHES')
            con.execute('DELETE FROM SHELL_INPUTS')


def test_quasarnix_shell_sessions_through_ingest(tmp_path):
    """Repeated real shell syntax keeps occurrence IDs, text, labels and groups."""
    from _ingest_quasarnix import FILES

    root = tmp_path / 'quasarnix'
    root.mkdir()
    inputs = ['echo hello; id', 'echo hello; id', 'VALUE=one']
    for name in FILES:
        (root / name).write_text(json.dumps(inputs if name == FILES[0] else []))
    database = tmp_path / 'quasarnix.duckdb'
    result = invoke(root, database, 'from _ingest_quasarnix import records\n', '--batch-size', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        shells = con.execute('SELECT record_id,shell_input,dataset_label,group_id,session_id FROM SHELL_INPUTS ORDER BY record_id').fetchall()
        assert shells == [
            (f'{FILES[0]}:{i}', text, 'malicious', None, f'quasarnix:record:{FILES[0]}:{i}')
            for i, text in enumerate(inputs)
        ]
        processes = con.execute('SELECT record_id,pgm,args,dataset_label,group_id,session_id FROM PROCESS_LAUNCHES ORDER BY record_id').fetchall()
        assert processes == [
            (f'{FILES[0]}:{i}:{j}', pgm, args, 'malicious-group',
             f'quasarnix:{FILES[0]}:{i}', f'quasarnix:record:{FILES[0]}:{i}')
            for i in range(2) for j, (pgm, args) in enumerate([('echo', ['hello']), ('id', [])])
        ]
