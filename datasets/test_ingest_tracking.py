"""Exercise dataset completion and retries through subprocesses and real DuckDB.

Disk failures during marker commits require external fault injection;
these tests exercise ordinary SQL failures and reader failures without mocks.
"""

import json

import duckdb
import pytest
from test_ingest_batches import invoke


@pytest.mark.parametrize('markers', [None, [False, False], [None]])
def test_retry_replaces_dataset_and_preserves_other_datasets(tmp_path, markers):
    """Replace all stale rows and incomplete markers."""
    root = tmp_path / "dataset'quoted"
    root.mkdir()
    database = tmp_path / 'commands.duckdb'
    with duckdb.connect(str(database)) as con:
        con.execute("CREATE TYPE command_label AS ENUM ('malicious', 'benign', 'unknown', 'malicious-group')")
        con.execute("CREATE TYPE command_os AS ENUM ('windows', 'linux')")
        con.execute("""CREATE TABLE COMMANDS (
            pgm VARCHAR NOT NULL, pgm_base VARCHAR NOT NULL, args VARCHAR[] NOT NULL,
            dataset VARCHAR NOT NULL, record_id VARCHAR NOT NULL, label command_label NOT NULL,
            group_id VARCHAR, session_id VARCHAR NOT NULL, os command_os NOT NULL,
            CHECK ((label = 'malicious-group') = (group_id IS NOT NULL)))""")
        for dataset in (root.name, 'other'):
            con.execute("INSERT INTO COMMANDS VALUES ('old', 'old', [], ?, 'stale', 'unknown', NULL, 'session', 'linux')", [dataset])
        if markers is not None:
            con.execute('CREATE TABLE INGESTED (dataset VARCHAR, ingested BOOLEAN)')
            con.executemany('INSERT INTO INGESTED VALUES (?, ?)', [(root.name, value) for value in markers])
            con.execute("INSERT INTO INGESTED VALUES ('other', true)")
    source = """
def records(root, options):
    yield Command('echo', ['new'], 'new')
    yield Command('echo', ['another'], 'new')
"""
    result = invoke(root, database, source, '--batch-size', '1')
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['stored'] == 2
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT dataset,record_id FROM COMMANDS ORDER BY dataset,record_id').fetchall() == [
            (root.name, 'new'), (root.name, 'new'), ('other', 'stale'),
        ]
        assert con.execute('SELECT ingested FROM INGESTED WHERE dataset=?', [root.name]).fetchall() == [(True,)]
        assert con.execute("SELECT ingested FROM INGESTED WHERE dataset='other'").fetchall() == ([] if markers is None else [(True,)])
        constraints = con.execute("SELECT constraint_type FROM duckdb_constraints() WHERE table_name='COMMANDS'").fetchall()
        assert ('PRIMARY KEY',) not in constraints, 'COMMANDS must not require a primary-key index'
        assert ('CHECK',) in constraints and ('NOT NULL',) in constraints
        assert con.execute("SELECT typeof(label),typeof(os),typeof(args) FROM COMMANDS LIMIT 1").fetchone() == (
            "ENUM('malicious', 'benign', 'unknown', 'malicious-group')", "ENUM('windows', 'linux')", 'VARCHAR[]',
        )


def test_completed_dataset_skips_before_initializing_commands_or_reader(tmp_path):
    """A true marker exits even if the source is unavailable or COMMANDS absent."""
    database = tmp_path / 'commands.duckdb'
    with duckdb.connect(str(database)) as con:
        con.execute('CREATE TABLE INGESTED (dataset VARCHAR, ingested BOOLEAN)')
        con.execute('INSERT INTO INGESTED VALUES (?, true), (?, false)', [tmp_path.name, tmp_path.name])
    result = invoke(tmp_path, database, "def records(root, options):\n    raise RuntimeError('reader must not run')\n")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['skipped'] is True
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT ingested FROM INGESTED ORDER BY ingested').fetchall() == [(False,), (True,)]
        assert con.execute('SHOW TABLES').fetchall() == [('INGESTED',)]


@pytest.mark.parametrize('failure', ['open', 'read', 'close', 'tail'])
def test_failures_remain_incomplete_and_retry_starts_over(tmp_path, failure):
    """Reader startup, iteration, cleanup, and final writes cannot mark success."""
    database = tmp_path / 'commands.duckdb'
    sources = {
        'open': "def records(root, options):\n    raise ValueError('source failure')\n",
        'read': "def records(root, options):\n    yield Command('old', [], 'stale')\n    raise ValueError('source failure')\n",
        'close': "def records(root, options):\n    try:\n        yield Command('old', [], 'stale')\n    finally:\n        raise ValueError('source failure')\n",
        'tail': "def records(root, options):\n    yield Command('old', [], 'stale', label='malicious-group')\n",
    }
    options = ['--limit', '1'] if failure == 'close' else []
    batch_size = '2' if failure == 'tail' else '1'
    result = invoke(tmp_path, database, sources[failure], '--batch-size', batch_size, *options)
    assert result.returncode != 0
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(False,)]
        assert con.execute('SELECT record_id FROM COMMANDS').fetchall() == ([('stale',)] if failure in ('read', 'close') else [])
    result = invoke(tmp_path, database, "def records(root, options):\n    return [Command('new', [], 'replacement')]\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT record_id FROM COMMANDS').fetchall() == [('replacement',)]
        assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(True,)]


def test_empty_dataset_is_completed(tmp_path):
    """Even a reader producing zero rows is skipped on its next invocation."""
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'def records(root, options):\n    return []\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT * FROM INGESTED').fetchall() == [(tmp_path.name, True)]
    result = invoke(tmp_path, database, "def records(root, options):\n    raise ValueError('must skip')\n")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['skipped'] is True


def test_dataset_reset_failure_rolls_back(tmp_path):
    """An invalid tracking schema must not commit deletion of existing commands."""
    database = tmp_path / 'commands.duckdb'
    source = "def records(root, options):\n    return [Command('echo', [], 'saved')]\n"
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        con.execute('DROP TABLE INGESTED')
        con.execute('CREATE TABLE INGESTED (dataset VARCHAR, ingested BOOLEAN CHECK (ingested IS NULL))')
        con.execute('INSERT INTO INGESTED VALUES (?, NULL)', [tmp_path.name])
    result = invoke(tmp_path, database, source)
    assert result.returncode != 0
    assert 'ConstraintException' in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT record_id FROM COMMANDS').fetchall() == [('saved',)]
        assert con.execute('SELECT * FROM INGESTED').fetchall() == [(tmp_path.name, None)]
