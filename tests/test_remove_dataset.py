"""Exercise dataset removal through the CLI against real DuckDB databases."""

import shutil
import subprocess
import sys
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/remove-dataset'


def run_script(*args, script=SCRIPT, cwd=None):
    """Run the command with the test interpreter and capture its output."""
    return subprocess.run([sys.executable, str(script), *map(str, args)],
                          cwd=cwd, capture_output=True, text=True, check=False)


def test_removes_all_dataset_rows_and_preserves_other_data(tmp_path):
    """Remove observations and metadata, using literal names even with SQL syntax."""
    database = tmp_path / 'cmds.duckdb'
    names = ['remove', "quote'); DROP TABLE INGESTED; --", 'keep', 'remove-more']
    tables = ['PROCESS_LAUNCHES', 'SHELL_INPUTS', 'SESSION_LABELS', 'INGESTED']
    with duckdb.connect(str(database)) as con:
        for table in tables:
            con.execute(f'CREATE TABLE {table}(dataset VARCHAR, value INTEGER)')
            con.executemany(f'INSERT INTO {table} VALUES (?, ?)',
                            [(name, i) for i, name in enumerate(names)] + [(None, 9)])
        con.execute('CREATE SCHEMA extra')
        con.execute('CREATE TABLE extra."odd""table"(dataset VARCHAR)')
        con.execute("INSERT INTO extra.\"odd\"\"table\" VALUES ('remove'), ('keep')")
        con.execute('CREATE TABLE unrelated(value INTEGER)')
        con.execute('INSERT INTO unrelated VALUES (42)')
        con.execute('CREATE VIEW observations AS SELECT * FROM PROCESS_LAUNCHES')
    for _ in range(2):
        result = run_script('--db', database, *names[:2], names[0], 'missing')
        assert result.returncode == 0, result.stderr
        with duckdb.connect(str(database)) as con:
            for table in tables:
                assert con.execute(f'SELECT * FROM {table} ORDER BY value').fetchall() == [
                    ('keep', 2), ('remove-more', 3), (None, 9)]
            assert con.execute('SELECT * FROM extra."odd""table"').fetchall() == [('keep',)]
            assert con.execute('SELECT * FROM unrelated').fetchall() == [(42,)]
            assert con.execute('SELECT count(*) FROM observations').fetchone() == (3,)


def test_default_database_is_relative_to_script(tmp_path):
    """The default database location must work from another working directory."""
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    script = scripts / 'remove-dataset'
    shutil.copy2(SCRIPT, script)
    database = tmp_path / 'cmds.duckdb'
    with duckdb.connect(str(database)) as con:
        con.execute('CREATE TABLE COMMANDS(dataset VARCHAR)')
        con.execute("INSERT INTO COMMANDS VALUES ('remove'), ('keep')")
    result = run_script('remove', script=script, cwd=scripts)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT * FROM COMMANDS').fetchall() == [('keep',)]
    assert not (scripts / 'cmds.duckdb').exists()


def test_requires_names(tmp_path):
    """No arguments must fail before opening or creating a database."""
    database = tmp_path / 'missing.duckdb'
    result = run_script('--db', database)
    assert result.returncode != 0
    assert 'required' in result.stderr
    assert not database.exists()


def test_missing_database_is_not_created(tmp_path):
    """A typo in --db must not create an empty database."""
    database = tmp_path / 'missing.duckdb'
    result = run_script('--db', database, 'remove')
    assert result.returncode != 0
    assert 'Database does not exist' in result.stderr
    assert not database.exists()


def test_database_without_dataset_tables(tmp_path):
    """An empty database has no rows to remove."""
    database = tmp_path / 'empty.duckdb'
    duckdb.connect(str(database)).close()
    result = run_script('--db', database, 'remove')
    assert result.returncode == 0, result.stderr


def test_failure_rolls_back_previous_deletions(tmp_path):
    """A real foreign-key error must roll back earlier table deletions."""
    database = tmp_path / 'cmds.duckdb'
    with duckdb.connect(str(database)) as con:
        con.execute('CREATE TABLE a_first(dataset VARCHAR)')
        con.execute("INSERT INTO a_first VALUES ('remove')")
        con.execute('CREATE TABLE z_parent(dataset VARCHAR PRIMARY KEY)')
        con.execute("INSERT INTO z_parent VALUES ('remove')")
        con.execute('CREATE TABLE references_parent(parent VARCHAR REFERENCES z_parent(dataset))')
        con.execute("INSERT INTO references_parent VALUES ('remove')")
    result = run_script('--db', database, 'remove')
    assert result.returncode != 0
    assert 'foreign key' in result.stderr.lower()
    with duckdb.connect(str(database)) as con:
        for table in ('a_first', 'z_parent'):
            assert con.execute(f'SELECT * FROM {table}').fetchall() == [('remove',)]
