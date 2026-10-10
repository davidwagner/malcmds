"""End-to-end ingestion of bounded samples of the original TC Avro files.

The original corpus is required. Network failures and disk exhaustion cannot be
reached reproducibly with these records and are not simulated with test doubles.
"""

import json
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

DATASETS = Path(__file__).resolve().parent
NAMES = sorted(p.name for p in DATASETS.glob('tc-*') if p.is_dir())


@pytest.mark.parametrize('name', NAMES)
def test_native_avro_ingestion_and_idempotence(name, tmp_path):
    """Exercise the dataset executable, native parsing, normalization and writes."""
    source = DATASETS / name
    if not list((source / 'data').glob('*.gz')):
        pytest.skip('Original TC corpus is not installed')
    database = tmp_path / 'commands.duckdb'
    argv = [sys.executable, str(source / 'ingest'), '--db', str(database),
            '--sample-files', '1', '--seed', '3', '--max-records', '200000']
    first = subprocess.run(argv, capture_output=True, text=True, check=True)
    stats = json.loads(first.stdout.splitlines()[-1])
    assert stats['processed'] > 0
    with duckdb.connect(str(database), read_only=True) as connection:
        before = connection.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall()
        assert len(before) == stats['stored']
        assert connection.execute("SELECT count(*) FROM COMMANDS WHERE pgm='' OR session_id=''").fetchall()[0][0] == 0
        assert connection.execute('SELECT count(DISTINCT record_id) FROM COMMANDS').fetchall()[0][0] == len(before)
        assert connection.execute("SELECT count(*) FROM COMMANDS WHERE (label='malicious-group') <> (group_id IS NOT NULL)").fetchall()[0][0] == 0
        assert connection.execute("SELECT count(*) FROM COMMANDS WHERE starts_with(pgm, 'sshd:') OR pgm='N/A'").fetchall()[0][0] == 0
        expected_os = 'windows' if name.endswith(('fivedirections', 'marple')) else 'linux'
        assert connection.execute('SELECT DISTINCT os FROM COMMANDS').fetchall() == [(expected_os,)]
        if name == 'tc-e3-trace':
            assert connection.execute("SELECT pgm, args FROM COMMANDS WHERE contains(record_id, '5325f54a-77b4-2309-3aa8-2df747293484')").fetchall() == [('groups', [])], 'TRACE Subject argv[0] must survive without arguments'
            assert connection.execute("SELECT count(*) FROM COMMANDS WHERE pgm='-bash' AND len(args)=0 AND contains(record_id, ':Subject:')").fetchone()[0] > 0
            # This native flattened cmdLine contains literal hex characters;
            # it has no raw-audit encoding marker authorizing another decode.
            script = '/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new'
            assert connection.execute("SELECT pgm,args FROM COMMANDS WHERE contains(record_id, '0ac3ac95-c0c4-1685-b6e6-c2bb7a467ae8')").fetchall() == [('sh', ['-c', script.encode('ascii').hex().upper()])]
        if name == 'tc-e5-theia':
            assert connection.execute("SELECT count(*) FROM COMMANDS WHERE pgm='sh' AND args[1]='-c' AND len(args)=2 AND contains(args[2], 'run-parts')").fetchall()[0][0] > 0
        if name == 'tc-e3-cadets':
            assert connection.execute("SELECT count(*) FROM COMMANDS WHERE label='malicious-group' AND starts_with(group_id, 'tc-e3-cadets:')").fetchall()[0][0] > 0
    subprocess.run(argv, capture_output=True, text=True, check=True)
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall() == before


def test_damaged_fivedirections_block_keeps_later_valid_records(tmp_path):
    """The released E3 file has a malformed first block; later blocks are valid."""
    source = DATASETS / 'tc-e3-fivedirections'
    if not (source / 'data' / 'ta1-fivedirections-e3-official.bin.tar.gz').exists():
        pytest.skip('Original damaged release is not installed')
    database = tmp_path / 'recovered.duckdb'
    result = subprocess.run(
        [sys.executable, str(source / 'ingest'), '--db', str(database),
         '--sample-files', '1', '--seed', '17', '--max-records', '300000'],
        capture_output=True, text=True, check=True,
    )
    assert 'malformed Avro block 0' in result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT count(*) FROM COMMANDS').fetchall()[0][0] > 0
