"""Run the final-label CLI against real on-disk DuckDB databases."""

import itertools
import shutil
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/compute_final_labels'
LABELS = (None, 'benign', 'malicious', 'unknown')
TABLES = ('SHELL_INPUTS', 'PROCESS_LAUNCHES')


def database(path, rows=()):
    """Create enum-backed observation tables and unrelated session labels."""
    with duckdb.connect(str(path)) as con:
        con.execute('BEGIN')
        con.execute("CREATE TYPE final_label AS ENUM ('malicious', 'benign', 'unknown')")
        con.execute("CREATE TYPE command_label AS ENUM ('malicious', 'benign', 'unknown', 'malicious-group')")
        for table in TABLES:
            con.execute(f'''CREATE TABLE {table} (
                record_id INTEGER, dataset_label command_label,
                ai_label final_label, override_label final_label, label final_label)''')
            if rows:
                con.executemany(f'INSERT INTO {table} VALUES (?, ?, ?, ?, ?)', rows)
        con.execute("CREATE TABLE SESSION_LABELS AS SELECT 'benign' AS label")
        con.execute('COMMIT')


def run(*args, script=SCRIPT, cwd=None):
    """Execute the command with captured output and no shell interpolation."""
    return subprocess.run([sys.executable, str(script), *map(str, args)],
                          capture_output=True, text=True, cwd=cwd, check=False)


def test_all_label_combinations_and_recomputation(tmp_path):
    """All sources and old values obey precedence in both tables on every run."""
    db = tmp_path / 'cmds.duckdb'
    rows, expected = [], []
    for index, (dataset, ai, override, old) in enumerate(itertools.product(
            (*LABELS, 'malicious-group'), LABELS, LABELS, LABELS)):
        if override is not None:
            label = override
        elif ai in ('benign', 'malicious'):
            label = ai
        elif dataset in ('benign', 'malicious', 'unknown'):
            label = dataset
        else:
            label = 'unknown'
        rows.append((index, dataset, ai, override, old))
        expected.append((index, dataset, ai, override, label))
    database(db, rows)
    for _ in range(2):
        result = run('--db', db)
        assert result.returncode == 0, result.stderr
        assert result.stderr == ''
        with duckdb.connect(str(db)) as con:
            for table in TABLES:
                assert con.execute(f'SELECT * FROM {table} ORDER BY record_id').fetchall() == expected
            assert con.execute('SELECT * FROM SESSION_LABELS').fetchall() == [('benign',)]
    with duckdb.connect(str(db)) as con:
        for table in TABLES:
            con.execute(f"UPDATE {table} SET override_label = 'malicious'")
    result = run('--db', db)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ''
    with duckdb.connect(str(db)) as con:
        for table in TABLES:
            assert con.execute(f'SELECT DISTINCT label FROM {table}').fetchall() == [('malicious',)]


def test_empty_tables_and_default_database(tmp_path):
    """The default database belongs to the script's repository, regardless of cwd."""
    script = tmp_path / 'checkout/scripts/compute_final_labels'
    script.parent.mkdir(parents=True)
    shutil.copy2(SCRIPT, script)
    db = script.parent.parent / 'cmds.duckdb'
    database(db)
    result = run(script=script, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ''
    assert not (tmp_path / 'cmds.duckdb').exists()
    with duckdb.connect(str(db)) as con:
        for table in TABLES:
            assert con.execute(f'SELECT count(*) FROM {table}').fetchone() == (0,)


@pytest.mark.parametrize('failure', ['missing_table', 'constraint'])
def test_failed_second_update_rolls_back_both_tables(tmp_path, failure):
    """A real schema or constraint error cannot leave only one table updated."""
    db = tmp_path / 'cmds.duckdb'
    rows = [(0, 'malicious', None, None, 'benign')]
    database(db, rows)
    with duckdb.connect(str(db)) as con:
        con.execute('DROP TABLE PROCESS_LAUNCHES')
        if failure == 'constraint':
            con.execute('''CREATE TABLE PROCESS_LAUNCHES (
                dataset_label command_label, ai_label final_label,
                override_label final_label, label final_label CHECK (label = 'benign'))''')
            con.execute("INSERT INTO PROCESS_LAUNCHES VALUES ('malicious', NULL, NULL, 'benign')")
    result = run('--db', db)
    assert result.returncode == 1
    assert 'Traceback' not in result.stderr
    assert 'PROCESS_LAUNCHES' in result.stderr or 'CHECK constraint' in result.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT * FROM SHELL_INPUTS').fetchall() == rows
        if failure == 'constraint':
            assert con.execute('SELECT label FROM PROCESS_LAUNCHES').fetchall() == [('benign',)]


def test_missing_database_and_cli_help(tmp_path):
    """Missing paths fail without creating a database; the executable offers help."""
    db = tmp_path / 'missing.duckdb'
    result = run('--db', db)
    assert result.returncode == 1
    assert 'Database does not exist' in result.stderr
    assert 'Traceback' not in result.stderr
    assert not db.exists()
    result = subprocess.run([str(SCRIPT), '--help'], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert '--db' in result.stdout
