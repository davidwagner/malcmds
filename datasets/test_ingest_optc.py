"""End-to-end checks using seeded samples of the actual OpTC eCAR streams."""

import gzip
import json
import random
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

DATASETS = Path(__file__).resolve().parent


@pytest.mark.parametrize('partition', ['benign', 'evaluation', 'short'])
def test_real_partition_ingestion_is_idempotent(partition, tmp_path):
    """Read real events, preserve target commands, and rerun without duplicates."""
    original = DATASETS / 'optc'
    files = sorted((original / 'ecar' / partition).rglob('*.json.gz'))
    if not files:
        pytest.skip('Original OpTC partition is not installed')
    selected = random.Random(23).choice(files)
    root = tmp_path / 'optc'
    target = root / selected.relative_to(original)
    target.parent.mkdir(parents=True)
    target.symlink_to(selected)
    database = tmp_path / 'commands.duckdb'
    driver = (
        'import sys; from pathlib import Path; '
        f'sys.path.insert(0, {str(DATASETS)!r}); '
        'from _ingest import run; from _ingest_optc import records; '
        f'run(Path({str(root)!r}), records)'
    )
    command = [sys.executable, '-c', driver, '--db', str(database),
               '--sample-files', '1', '--seed', '23', '--max-records', '100000']
    completed = subprocess.run(command, capture_output=True, text=True, check=True)
    stats = json.loads(completed.stdout.splitlines()[-1])
    assert stats['stored'] > 0
    with duckdb.connect(str(database), read_only=True) as connection:
        before = connection.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall()
        assert connection.execute("SELECT count(*) FROM COMMANDS WHERE pgm='' OR session_id='' OR NOT starts_with(session_id, 'optc:') OR os <> 'windows'").fetchall()[0][0] == 0
        expected_label = 'benign' if partition == 'benign' else 'unknown'
        assert connection.execute('SELECT DISTINCT label FROM COMMANDS').fetchall() == [(expected_label,)]
        assert connection.execute('SELECT count(DISTINCT record_id) FROM COMMANDS').fetchall()[0][0] == len(before)
        # Derive expected examples from unchanged source records. OPEN images
        # can name a different executable; argv[0] must still identify the target.
        checked_open = checked_create = False
        with gzip.open(selected, 'rt') as stream:
            for number, line in enumerate(stream, 1):
                if number > 100000:
                    break
                event = json.loads(line)
                if event.get('object') != 'PROCESS':
                    continue
                props = event.get('properties') or {}
                text = props.get('command_line') or ''
                if event.get('action') == 'OPEN' and text.startswith('C:\\Windows\\System32\\svchost.exe ') and 'MsMpEng.exe' in props.get('image_path', ''):
                    rows = connection.execute('SELECT pgm,args FROM COMMANDS WHERE record_id=?', [event['id'] + ':0']).fetchall()
                    assert rows == [('C:\\Windows\\System32\\svchost.exe', text.split()[1:])]
                    checked_open = True
                if event.get('action') == 'CREATE' and text == 'sc  config OneSyncSvc start=disabled':
                    rows = connection.execute('SELECT pgm,args FROM COMMANDS WHERE record_id=?', [event['id'] + ':0']).fetchall()
                    assert rows == [('sc.exe', ['config', 'OneSyncSvc', 'start=disabled'])]
                    checked_create = True
                if checked_open and checked_create:
                    break
        if partition == 'short':
            assert checked_open and checked_create
    subprocess.run(command, capture_output=True, text=True, check=True)
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall() == before
