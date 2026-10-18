"""Check label initialization through the shared ingestion CLI and real DuckDB."""

import duckdb
import pytest
from test_ingest_batches import invoke


def test_labels_for_native_shell_and_arrow_rows(tmp_path):
    """All writer paths retain source labels and start without AI/human labels."""
    database = tmp_path / 'labels.duckdb'
    source = '''
from _ingest import ShellInput, command_table

def records(root, options):
    for label in ('benign', 'malicious', 'unknown', 'malicious-group'):
        group = 'attack-session' if label == 'malicious-group' else None
        command = Command('id', [], label, label=label, group_id=group)
        yield command
        yield ShellInput('id', label, [command], label=label, group_id=group)
        yield command_table([command], root.name)
'''
    result = invoke(tmp_path, database, source, '--batch-size', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        for table, repetitions in (('PROCESS_LAUNCHES', 3), ('SHELL_INPUTS', 1)):
            assert con.execute(f'''SELECT dataset_label::VARCHAR AS dataset_label, ai_label, override_label, label,
                count(*) FROM {table} GROUP BY ALL ORDER BY dataset_label''').fetchall() == [
                ('benign', None, None, 'benign', repetitions),
                ('malicious', None, None, 'malicious', repetitions),
                ('malicious-group', None, None, 'unknown', repetitions),
                ('unknown', None, None, 'unknown', repetitions),
            ]
            for column in ('ai_label', 'override_label', 'label'):
                with pytest.raises(duckdb.ConversionException):
                    con.execute(f"UPDATE {table} SET {column}='malicious-group'")
                con.execute(f"UPDATE {table} SET {column}='benign'")
        assert con.execute('SELECT count(*) FROM SESSION_LABELS').fetchone() == (0,)
        con.execute("INSERT INTO SESSION_LABELS(dataset,session_id) VALUES ('example','session')")
        assert con.execute('SELECT ai_label,override_label,label FROM SESSION_LABELS').fetchall() == [
            (None, None, 'unknown')]
        for column in ('ai_label', 'override_label', 'label'):
            with pytest.raises(duckdb.ConversionException):
                con.execute(f"UPDATE SESSION_LABELS SET {column}='malicious-group'")


def test_old_schema_is_rejected_before_replacing_rows(tmp_path):
    """An existing database needs migration before even a completed ingest skips."""
    database = tmp_path / 'old.duckdb'
    with duckdb.connect(str(database)) as con:
        con.execute('''CREATE TABLE PROCESS_LAUNCHES (
            pgm VARCHAR, pgm_base VARCHAR, args VARCHAR[], dataset VARCHAR,
            record_id VARCHAR, dataset_label VARCHAR, group_id VARCHAR,
            session_id VARCHAR, os VARCHAR)''')
        con.execute("INSERT INTO PROCESS_LAUNCHES VALUES ('id','id',[],?,'old','benign',NULL,'s','linux')", [tmp_path.name])
        con.execute('CREATE TABLE INGESTED(dataset VARCHAR, ingested BOOLEAN)')
        con.execute('INSERT INTO INGESTED VALUES (?, true)', [tmp_path.name])
    result = invoke(tmp_path, database, 'def records(root, options):\n    return []\n')
    assert result.returncode != 0
    assert 'incompatible schema' in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT record_id,dataset_label FROM PROCESS_LAUNCHES').fetchall() == [('old', 'benign')]
        assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(True,)]
