"""Exercise the session migration on actual DuckDB files through its CLI."""
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/migrate_record_sessions'


@pytest.mark.parametrize('session_labels', [False, True])
def test_migrate_preserves_rows_and_is_idempotent(tmp_path, session_labels):
    """Only target session fields change, including children and empty inputs."""
    db = tmp_path / 'commands.duckdb'
    with duckdb.connect(str(db)) as con:
        for table in ['SHELL_INPUTS', 'PROCESS_LAUNCHES']:
            con.execute(f'CREATE TABLE {table} (dataset VARCHAR, record_id VARCHAR, session_id VARCHAR, dataset_label VARCHAR, ai_label VARCHAR, payload VARCHAR[])')
            for dataset in ['shellrisk-bench', 'shell-honeypot', 'other']:
                for record in ['source:0', 'source:1']:
                    ids = [record] if table == 'SHELL_INPUTS' else [record + ':0', record + ':1']
                    for identifier in ids:
                        con.execute(f'INSERT INTO {table} VALUES (?, ?, ?, ?, ?, ?)', [dataset, identifier, 'shared', 'benign', 'malicious', ['quoted text', '']])
        con.execute("INSERT INTO SHELL_INPUTS VALUES ('shell-honeypot','empty','shared','unknown','benign',[])")
        con.execute('CREATE TABLE INGESTED AS SELECT \'shell-honeypot\' dataset, true ingested')
        if session_labels:
            con.execute("CREATE TABLE SESSION_LABELS AS SELECT dataset, 'shared' session_id, 'malicious' ai_label FROM SHELL_INPUTS GROUP BY dataset")
        before = {table: con.execute(f'SELECT * EXCLUDE(session_id) FROM {table} ORDER BY dataset, record_id').fetchall() for table in ['SHELL_INPUTS', 'PROCESS_LAUNCHES']}
    for iteration in range(2):
        result = subprocess.run([sys.executable, str(SCRIPT), '--db', str(db)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        with duckdb.connect(str(db)) as con:
            for table in before:
                assert con.execute(f'SELECT * EXCLUDE(session_id) FROM {table} ORDER BY dataset, record_id').fetchall() == before[table]
                rows = con.execute(f'SELECT dataset,record_id,session_id FROM {table}').fetchall()
                for dataset, record, session in rows:
                    parent = record.rsplit(':', 1)[0] if table == 'PROCESS_LAUNCHES' else record
                    assert session == ('shared' if dataset == 'other' else f'{dataset}:record:{parent}')
            assert con.execute('SELECT * FROM INGESTED').fetchall() == [('shell-honeypot', True)]
            if session_labels:
                assert con.execute('SELECT * FROM SESSION_LABELS ORDER BY dataset').fetchall() == ([('other', 'shared', 'malicious')] + ([('shell-honeypot', 'shell-honeypot:record:empty', 'benign')] if iteration else []))
                if iteration == 0:
                    con.execute("INSERT INTO SESSION_LABELS VALUES ('shell-honeypot','shell-honeypot:record:empty','benign')")


@pytest.mark.parametrize('problem', ['orphan', 'duplicate', 'missing_suffix'])
def test_invalid_parent_relationship_rolls_back(tmp_path, problem):
    """Ambiguous or missing parents must leave the entire database unchanged."""
    db = tmp_path / 'commands.duckdb'
    with duckdb.connect(str(db)) as con:
        con.execute("CREATE TABLE SHELL_INPUTS AS SELECT 'shell-honeypot' dataset, 'row' record_id, 'old' session_id")
        con.execute("CREATE TABLE PROCESS_LAUNCHES AS SELECT 'shell-honeypot' dataset, ? record_id, 'old' session_id", [{'orphan': 'missing:0', 'duplicate': 'row:0', 'missing_suffix': 'row'}[problem]])
        if problem == 'duplicate':
            con.execute('INSERT INTO SHELL_INPUTS SELECT * FROM SHELL_INPUTS')
    result = subprocess.run([sys.executable, str(SCRIPT), '--db', str(db)], capture_output=True, text=True)
    assert result.returncode != 0
    with duckdb.connect(str(db)) as con:
        for table in ['SHELL_INPUTS', 'PROCESS_LAUNCHES']:
            assert con.execute(f'SELECT DISTINCT session_id FROM {table}').fetchall() == [('old',)]
