"""Run the label repair against real databases, including a transaction failure."""

import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/migrate_honeypot_labels'


def migrate(database):
    """Invoke the standalone migration without importing its implementation."""
    return subprocess.run([sys.executable, str(SCRIPT), '--db', str(database)],
                          capture_output=True, text=True, check=False)


@pytest.mark.parametrize('with_ai', [False, True])
def test_labels_only_and_idempotence(tmp_path, with_ai):
    """Repair both tables and preserve identities, AI decisions and other datasets."""
    database = tmp_path / 'commands.duckdb'
    with duckdb.connect(str(database)) as con:
        sys.path.insert(0, str(SCRIPT.parent))
        from _ingest import _initialize
        _initialize(con)
        for table in ('SHELL_INPUTS', 'PROCESS_LAUNCHES'):
            for index, dataset in enumerate(('cyberlab', 'microsoft-iot', 'other')):
                for label in ('malicious', 'benign', 'unknown', 'malicious-group'):
                    prefix = ['uname -a', ['uname'], ['uname', '-a']] if table == 'SHELL_INPUTS' else ['uname', 'uname', ['-a']]
                    con.execute(f'INSERT INTO {table} VALUES (?,?,?,?,?,?,?,?,?)',
                                prefix + [dataset, f'{index}:{label}', label,
                                          'old-group' if label == 'malicious-group' else None,
                                          f'session:{index}', 'linux'])
            if with_ai:
                con.execute(f"ALTER TABLE {table} ADD COLUMN ai_label VARCHAR DEFAULT 'benign'")
        con.execute('CREATE TABLE INGESTED AS SELECT \'cyberlab\' AS dataset, true AS ingested')
        con.execute("CREATE TABLE SESSION_LABELS AS SELECT 'cyberlab' AS dataset, 'session:0' AS session_id, 'malicious' AS ai_label")
        before = {table: con.execute(f'SELECT * FROM {table} ORDER BY dataset, record_id').fetchall()
                  for table in ('SHELL_INPUTS', 'PROCESS_LAUNCHES')}
    for _ in range(2):
        result = migrate(database)
        assert result.returncode == 0, result.stderr
        with duckdb.connect(str(database)) as con:
            for table, rows in before.items():
                expected = [row[:5] + ('unknown', None) + row[7:]
                            if row[3] in ('cyberlab', 'microsoft-iot') else row for row in rows]
                assert con.execute(f'SELECT * FROM {table} ORDER BY dataset, record_id').fetchall() == expected
            assert con.execute('SELECT * FROM INGESTED').fetchall() == [('cyberlab', True)]
            assert con.execute('SELECT * FROM SESSION_LABELS').fetchall() == [('cyberlab', 'session:0', 'malicious')]


def test_failure_rolls_back_both_tables(tmp_path):
    """An actual CHECK failure in the second table undoes the first table update."""
    database = tmp_path / 'invalid.duckdb'
    with duckdb.connect(str(database)) as con:
        for table in ('SHELL_INPUTS', 'PROCESS_LAUNCHES'):
            constraint = "CHECK (dataset_label = 'malicious')" if table == 'PROCESS_LAUNCHES' else ''
            con.execute(f'CREATE TABLE {table} (dataset VARCHAR, dataset_label VARCHAR {constraint}, group_id VARCHAR)')
            con.execute(f"INSERT INTO {table} VALUES ('cyberlab', 'malicious', NULL)")
    result = migrate(database)
    assert result.returncode != 0
    assert 'Constraint' in result.stderr
    with duckdb.connect(str(database)) as con:
        for table in ('SHELL_INPUTS', 'PROCESS_LAUNCHES'):
            assert con.execute(f'SELECT * FROM {table}').fetchall() == [('cyberlab', 'malicious', None)]


def test_missing_database_is_not_created(tmp_path):
    """A mistyped path cannot silently create an empty database."""
    database = tmp_path / 'missing.duckdb'
    result = migrate(database)
    assert result.returncode != 0
    assert not database.exists()
