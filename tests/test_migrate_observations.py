"""Migrate real legacy databases without executing any captured shell commands."""

import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / 'scripts/migrate_observations'


def legacy_database(path, unexpected_shell=False):
    """Build the published legacy schema, including enums and the label check."""
    with duckdb.connect(str(path)) as con:
        con.execute("CREATE TYPE command_label AS ENUM ('malicious','benign','unknown','malicious-group')")
        con.execute("CREATE TYPE command_os AS ENUM ('windows','linux')")
        con.execute('''CREATE TABLE COMMANDS (
            pgm VARCHAR NOT NULL, pgm_base VARCHAR NOT NULL, args VARCHAR[] NOT NULL,
            shell_input VARCHAR, other_tokens VARCHAR[] NOT NULL,
            dataset VARCHAR NOT NULL, record_id VARCHAR NOT NULL, label command_label NOT NULL,
            group_id VARCHAR, session_id VARCHAR NOT NULL, os command_os NOT NULL,
            CHECK ((label = 'malicious-group') = (group_id IS NOT NULL)))''')
        con.execute('CREATE TABLE INGESTED(dataset VARCHAR, ingested BOOLEAN)')
        con.execute("INSERT INTO COMMANDS VALUES ('/bin/id','id',[],?,[], 'optc','keep','benign',NULL,'session','linux')",
                    ['id' if unexpected_shell else None])
        con.execute("INSERT INTO INGESTED VALUES ('optc',true)")
        for dataset in ('cyberlab', 'kypo', 'lade', 'microsoft-iot', 'quasarnix', 'shell-honeypot', 'splunk-bots'):
            con.execute("INSERT INTO COMMANDS VALUES ('echo','echo',['x'],'echo x',[],?,'old','unknown',NULL,'old-session','linux')", [dataset])
            con.execute('INSERT INTO INGESTED VALUES (?,true)', [dataset])


def migrate(path, *options):
    """Invoke the migration CLI against a test-owned database."""
    return subprocess.run([sys.executable, str(MIGRATE), '--db', str(path), *options],
                          capture_output=True, text=True, check=False)


def test_schema_migration_preserves_process_rows_and_constraints(tmp_path):
    """DuckDB ALTER must retain enums, NOT NULL and the renamed label constraint."""
    path = tmp_path / 'legacy.duckdb'
    legacy_database(path)
    result = migrate(path, '--schema-only')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(path)) as con:
        assert con.execute('SHOW TABLES').fetchall() == [('INGESTED',), ('PROCESS_LAUNCHES',), ('SESSION_LABELS',), ('SHELL_INPUTS',)]
        assert con.execute('SELECT * FROM PROCESS_LAUNCHES').fetchall() == [
            ('/bin/id', 'id', [], 'optc', 'keep', 'benign', None, 'session', 'linux', None, None, 'benign')]
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone() == (0,)
        assert con.execute('SELECT * FROM INGESTED ORDER BY dataset').fetchall() == [
            (name, name == 'optc') for name in sorted(('optc', 'cyberlab', 'kypo', 'lade',
             'microsoft-iot', 'quasarnix', 'shell-honeypot', 'splunk-bots'))]
        constraints = con.execute("SELECT constraint_type, constraint_text FROM duckdb_constraints() WHERE table_name='PROCESS_LAUNCHES'").fetchall()
        assert any(kind == 'CHECK' and 'dataset_label' in text for kind, text in constraints), \
            'DuckDB must rewrite the label constraint when renaming the column'
    again = migrate(path, '--schema-only')
    assert again.returncode == 0, again.stderr


def test_migration_refuses_unexpected_retained_shell_data(tmp_path):
    """An unlisted shell dataset must fail before any original rows are deleted."""
    path = tmp_path / 'legacy.duckdb'
    legacy_database(path, unexpected_shell=True)
    result = migrate(path, '--schema-only')
    assert result.returncode != 0
    assert 'outside the seven datasets' in result.stderr
    with duckdb.connect(str(path)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (8,)
        assert con.execute('SELECT count(*) FROM INGESTED WHERE ingested').fetchone() == (8,)


def test_missing_database_is_not_created(tmp_path):
    """A misspelled migration path must not create an empty database."""
    path = tmp_path / 'missing.duckdb'
    result = migrate(path, '--schema-only')
    assert result.returncode != 0
    assert not path.exists()


@pytest.mark.parametrize('sql, message', [
    ('CREATE TABLE unrelated(id INTEGER)', 'neither the legacy schema nor the migrated schema'),
    ('CREATE TABLE COMMANDS(pgm VARCHAR)', 'expected legacy schema'),
])
def test_migration_rejects_unrecognized_schemas(tmp_path, sql, message):
    """A migration cannot silently reinterpret an unrelated or older database."""
    path = tmp_path / 'incompatible.duckdb'
    with duckdb.connect(str(path)) as con:
        con.execute(sql)
    result = migrate(path, '--schema-only')
    assert result.returncode != 0
    assert message in result.stderr


def test_migration_rejects_mixed_old_and_new_tables(tmp_path):
    """Refuse to merge two independently populated versions of the schema."""
    path = tmp_path / 'mixed.duckdb'
    legacy_database(path)
    with duckdb.connect(str(path)) as con:
        con.execute('CREATE TABLE SHELL_INPUTS(shell_input VARCHAR)')
    result = migrate(path, '--schema-only')
    assert result.returncode != 0
    assert 'both legacy and new' in result.stderr
    with duckdb.connect(str(path)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (8,)


def test_migration_initializes_all_dataset_labels(tmp_path):
    """Retained native processes get NULL classifier labels and a final label."""
    path = tmp_path / 'legacy.duckdb'
    legacy_database(path)
    with duckdb.connect(str(path)) as con:
        for label in ('malicious', 'unknown', 'malicious-group'):
            con.execute("INSERT INTO COMMANDS VALUES ('id','id',[],NULL,[],'optc',?,?,?,'session','linux')",
                        [label, label, 'group' if label == 'malicious-group' else None])
    result = migrate(path, '--schema-only')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(path)) as con:
        assert con.execute('SELECT dataset_label,ai_label,override_label,label FROM PROCESS_LAUNCHES ORDER BY record_id').fetchall() == [
            ('benign', None, None, 'benign'), ('malicious', None, None, 'malicious'),
            ('malicious-group', None, None, 'unknown'), ('unknown', None, None, 'unknown')]
