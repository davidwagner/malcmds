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
    subprocess.run(command, capture_output=True, text=True, check=True)
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall() == before


def test_authentic_short_partition_process_commands(tmp_path):
    """Fixed source excerpts preserve both assertions as downloaded inventories grow.

    These unchanged events come from short/17-18Sep19/AIA-26-50/
    AIA-26-50.ecar-last.json.gz. A random short-partition file need not contain
    either example; adding downloaded files must not change this regression.
    """
    root = tmp_path / 'optc'
    source = root / 'ecar' / 'short' / 'events.json.gz'
    source.parent.mkdir(parents=True)
    events = [json.loads(line) for line in (DATASETS / 'optc_short_fixture.jsonl').read_text().splitlines()]
    with gzip.open(source, 'wt') as stream:
        stream.write(''.join(json.dumps(event) + '\n' for event in events))
    database = tmp_path / 'commands.duckdb'
    driver = ('import sys; from pathlib import Path; '
              f'sys.path.insert(0, {str(DATASETS)!r}); '
              'from _ingest import run; from _ingest_optc import records; '
              f'run(Path({str(root)!r}), records)')
    subprocess.run([sys.executable, '-c', driver, '--db', str(database)],
                   capture_output=True, text=True, check=True)
    with duckdb.connect(str(database), read_only=True) as connection:
        opening, creation = events
        assert opening['action'] == 'OPEN' and 'MsMpEng.exe' in opening['properties']['image_path']
        assert connection.execute('SELECT pgm,args FROM COMMANDS WHERE record_id=?',
                                  [opening['id'] + ':0']).fetchall() == [
            ('C:\\Windows\\System32\\svchost.exe', opening['properties']['command_line'].split()[1:]),
        ], 'An OPEN accessor image must not replace the target executable'
        assert creation['action'] == 'CREATE'
        assert connection.execute('SELECT pgm,args FROM COMMANDS WHERE record_id=?',
                                  [creation['id'] + ':0']).fetchall() == [
            ('sc.exe', ['config', 'OneSyncSvc', 'start=disabled']),
        ], 'Real sc.exe arguments must survive repeated command-line whitespace'
        assert connection.execute('SELECT count(*) FROM COMMANDS').fetchone() == (2,)


def test_repeated_commands_preserve_images_labels_sessions_and_limits(tmp_path):
    """Repeated text must preserve event-specific metadata and parsing semantics."""
    root = tmp_path / 'optc'
    source = root / 'ecar' / 'evaluation' / 'host' / 'events.json.gz'
    source.parent.mkdir(parents=True)
    cases = [
        ('OPEN', r'C:\Windows\cmd.exe /c whoami', r'C:\Windows\other.exe', r'C:\Windows\cmd.exe', ['/c', 'whoami']),
        ('CREATE', 'sc config service', 'sc.exe', 'sc.exe', ['config', 'service']),
        ('CREATE', r'C:\Windows\cmd.exe /q', r'\Device\Other\cmd.exe', r'\Device\Other\cmd.exe', ['/q']),
        ('CREATE', r'C:\Windows\cmd.exe /q', r'\Device\cmd.exe', r'\Device\cmd.exe', ['/q']),
        ('CREATE', 'cmd /c whoami', '', 'cmd', ['/c', 'whoami']),
        ('CREATE', 'cmd /c whoami', 'cmd.exe', 'cmd.exe', ['/c', 'whoami']),
        ('OPEN', 'cmd /c whoami', 'cmd.exe', 'cmd', ['/c', 'whoami']),
        ('CREATE', 'cmd /c whoami', 'other.exe', 'cmd', ['/c', 'whoami']),
        ('CREATE', r'C:\Program Files\App\app.exe /q', r'\Device\HarddiskVolume1\Program Files\App\app.exe', r'\Device\HarddiskVolume1\Program Files\App\app.exe', ['/q']),
        ('CREATE', r'"C:\Windows\cmd.exe" /c "hello world"', r'C:\Windows\cmd.exe', r'C:\Windows\cmd.exe', ['/c', 'hello world']),
        ('TERMINATE', 'cmd\x00/c\x00whoami\x00', 'cmd.exe', 'cmd.exe', ['/c', 'whoami']),
        ('CREATE', 'cmd /c ' + 'x' * 5000, 'cmd.exe', 'cmd.exe', ['/c', 'x' * 5000]),
        ('OPEN', '-', 'cmd.exe', None, []),
        ('CREATE', '  ', 'cmd.exe', None, []),
        ('CREATE', None, '', None, []),
    ]
    expected = []
    with gzip.open(source, 'wt') as stream:
        for repeat in range(2):
            for index, (action, text, image, pgm, args) in enumerate(cases):
                record = f'event-{repeat}-{index}'
                event = {
                    'object': 'PROCESS', 'action': action, 'id': record,
                    'hostname': 'sysclient0201.example',
                    'timestamp': f'2019-09-23T{12 if repeat == 0 else 16}:00:00-04:00',
                    'properties': {'command_line': text, 'image_path': image,
                                   'logon_id': f'login-{repeat}-{index}'},
                }
                stream.write(json.dumps(event) + '\n')
                if pgm:
                    label = 'malicious-group' if repeat == 0 else 'unknown'
                    group = ('optc:empire-day1:sysclient0201:2019-09-23T11:23:29/'
                             '2019-09-23T15:30:00:America_New_York') if repeat == 0 else None
                    expected.append((record + ':0', pgm, args, label, group,
                                     f'optc:sysclient0201.example:login:login-{repeat}-{index}'))
        stream.write('\n')
        stream.write(json.dumps({'object': 'FILE', 'properties': {'command_line': 'ignore'}}) + '\n')
    driver = ('import sys; from pathlib import Path; '
              f'sys.path.insert(0, {str(DATASETS)!r}); '
              'from _ingest import run; from _ingest_optc import records; '
              f'run(Path({str(root)!r}), records)')
    database = tmp_path / 'commands.duckdb'
    command = [sys.executable, '-c', driver, '--db', str(database), '--batch-size', '3']
    for _ in range(2):
        subprocess.run(command, capture_output=True, text=True, check=True)
        with duckdb.connect(str(database), read_only=True) as con:
            assert con.execute('SELECT record_id,pgm,args,label,group_id,session_id '
                               'FROM COMMANDS ORDER BY record_id').fetchall() == sorted(expected)
    limited = tmp_path / 'limited.duckdb'
    subprocess.run([*command, '--db', str(limited), '--max-records', '1'],
                   capture_output=True, text=True, check=True)
    with duckdb.connect(str(limited), read_only=True) as con:
        assert con.execute('SELECT record_id FROM COMMANDS').fetchall() == [('event-0-0:0',)]
