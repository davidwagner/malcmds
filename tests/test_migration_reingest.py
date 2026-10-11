"""Resume migration through actual dataset launchers and native source files."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import duckdb
from test_migrate_observations import legacy_database

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ('cyberlab', 'kypo', 'lade', 'microsoft-iot', 'quasarnix', 'shell-honeypot', 'splunk-bots')


def test_default_migration_resumes_remaining_dataset_and_preserves_completed_work(tmp_path):
    """A retry must run the remaining reader and skip previously completed sources."""
    checkout = tmp_path / 'checkout'
    shutil.copytree(ROOT / 'scripts', checkout / 'scripts', ignore=shutil.ignore_patterns('__pycache__'))
    for dataset in DATASETS:
        folder = checkout / 'datasets' / dataset
        folder.mkdir(parents=True)
        shutil.copy2(ROOT / 'datasets' / dataset / 'ingest', folder / 'ingest')
    database = tmp_path / 'legacy.duckdb'
    legacy_database(database)
    invocation = [sys.executable, str(checkout / 'scripts/migrate_observations'), '--db', str(database)]
    converted = subprocess.run([*invocation, '--schema-only'], capture_output=True, text=True, check=False)
    assert converted.returncode == 0, converted.stderr
    # Represent a previous migration attempt that completed six real datasets.
    # Those launchers must skip before accessing source archives, which need not
    # remain available when a failed migration is resumed.
    with duckdb.connect(str(database)) as con:
        con.execute("UPDATE INGESTED SET ingested=true WHERE dataset != 'quasarnix'")
        con.execute("INSERT INTO PROCESS_LAUNCHES VALUES ('/bin/echo','echo',['previous'],'microsoft-iot','completed:0','malicious',NULL,'previous-session','linux')")
        con.execute("INSERT INTO SHELL_INPUTS (shell_input,pgms,tokens,dataset,record_id,dataset_label,group_id,session_id,os) VALUES ('/bin/echo previous',['echo'],['/bin/echo','previous'],'microsoft-iot','completed','malicious',NULL,'previous-session','linux')")
    interrupted = subprocess.run(invocation, capture_output=True, text=True, check=False)
    assert interrupted.returncode != 0
    assert 'quasarnix' in interrupted.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT ingested FROM INGESTED WHERE dataset='quasarnix'").fetchone() == (False,)
        assert con.execute("SELECT record_id FROM PROCESS_LAUNCHES WHERE dataset='microsoft-iot'").fetchall() == [('completed:0',)]
    from _ingest_quasarnix import FILES
    for name in FILES:
        values = ['VALUE=one', '/bin/echo resumed; /usr/bin/id'] if name == 'nl2bash.json' else []
        (checkout / 'datasets/quasarnix' / name).write_text(json.dumps(values))
    resumed = subprocess.run(invocation, capture_output=True, text=True, check=False)
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT dataset,ingested FROM INGESTED ORDER BY dataset').fetchall() == [(name, True) for name in sorted((*DATASETS, 'optc'))]
        assert con.execute('SELECT dataset,record_id,pgm FROM PROCESS_LAUNCHES ORDER BY dataset,record_id').fetchall() == [
            ('microsoft-iot', 'completed:0', '/bin/echo'), ('optc', 'keep', '/bin/id'),
            ('quasarnix', 'nl2bash.json:1:0', '/bin/echo'), ('quasarnix', 'nl2bash.json:1:1', '/usr/bin/id')]
        shells = con.execute('SELECT dataset,record_id,shell_input,pgms FROM SHELL_INPUTS ORDER BY dataset,record_id').fetchall()
        assert shells == [('microsoft-iot', 'completed', '/bin/echo previous', ['echo']),
                          ('quasarnix', 'nl2bash.json:0', 'VALUE=one', []),
                          ('quasarnix', 'nl2bash.json:1', '/bin/echo resumed; /usr/bin/id', ['echo', 'id'])]
    repeated = subprocess.run(invocation, capture_output=True, text=True, check=False)
    assert repeated.returncode == 0, repeated.stdout + repeated.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (4,)
        assert con.execute('SELECT dataset,record_id,shell_input,pgms FROM SHELL_INPUTS ORDER BY dataset,record_id').fetchall() == shells
