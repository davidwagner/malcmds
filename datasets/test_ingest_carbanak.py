"""Read an authentic CARBANAK subject subset through real pg_restore and DuckDB."""

import os
import shutil
from pathlib import Path

import duckdb
import pytest
from test_ingest_batches import invoke

FIXTURES = Path(__file__).parent / 'fixtures' / 'issue57'


def test_carbanak_real_custom_dump_uuid_labels_and_argument_handling(tmp_path):
    """Changing the PostgreSQL COPY layout must surface as an importer failure."""
    executable = os.environ.get('PG_RESTORE', 'pg_restore')
    if not shutil.which(executable):
        pytest.skip('CARBANAK integration requires PostgreSQL 17+ pg_restore (or PG_RESTORE)')
    root = tmp_path / 'carbanakv2'
    root.mkdir()
    shutil.copyfile(FIXTURES / 'carbanak-subjects.dump', root / 'carbanakv2_edr.dump')
    shutil.copyfile(FIXTURES / 'carbanak-ground-truth.csv', root / 'ground_truth.csv')
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_carbanak import records\n')
    assert result.returncode == 0, 'pg_restore must emit the released subject COPY schema: ' + result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (13,)
        assert con.execute("SELECT count(*) FROM COMMANDS WHERE label='malicious'").fetchone() == (6,), 'Repeated annotation UUIDs must label subjects without duplicating processes'
        assert con.execute("SELECT args FROM COMMANDS WHERE pgm_base='svchost.exe'").fetchone() == (['-k', 'DcomLaunch', '-p'],)
        assert con.execute("SELECT args FROM COMMANDS WHERE record_id='d4ecc9a0-1da0-80e6-94d4-4ed0278beaf6'").fetchone() == ([r'C:\Users\efficientgoldfinch\AppData\Roaming\\TransBaseOdbcDriver\\TransBaseOdbcDriver.js'],)
        assert con.execute("SELECT args FROM COMMANDS WHERE record_id='f9419b5b-5155-81cd-b666-07f0d2b1f6cb'").fetchone() == (['/silentConfig'],), 'Argument-only cmd fields must retain their first option'
        assert con.execute("SELECT args[1:2] FROM COMMANDS WHERE record_id='28fe59e9-23fb-80c0-8138-37daecb8261d'").fetchone() == ([r'Files\Microsoft', r'OneDrive\Update\OneDriveSetup.exe'],), 'The known unquoted image prefix must not become argument fragments'
        assert con.execute('SELECT count(*) FROM COMMANDS WHERE shell_input IS NOT NULL OR len(other_tokens)>0 OR group_id IS NOT NULL').fetchone() == (0,)
        assert con.execute("SELECT count(*) FROM COMMANDS WHERE session_id != dataset || ':record:' || record_id").fetchone() == (0,)
    rerun = invoke(root, database, 'from _ingest_carbanak import records\n')
    assert rerun.returncode == 0, rerun.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (13,)


def test_carbanak_schema_change_and_bounded_import(tmp_path):
    """A renamed source table cannot silently mark an empty import complete."""
    executable = os.environ.get('PG_RESTORE', 'pg_restore')
    if not shutil.which(executable):
        pytest.skip('CARBANAK integration requires PostgreSQL 17+ pg_restore (or PG_RESTORE)')
    dump = tmp_path / 'carbanakv2_edr.dump'
    shutil.copyfile(FIXTURES / 'carbanak-subjects.dump', dump)
    shutil.copyfile(FIXTURES / 'carbanak-ground-truth.csv', tmp_path / 'ground_truth.csv')
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_carbanak import records\n', '--max-records', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (1,)
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
    # Same-length archive metadata names produce a valid PostgreSQL custom dump
    # whose real table selector finds nothing. No executable is substituted.
    dump.write_bytes(dump.read_bytes().replace(b'subject_node_table', b'renamed_node_table'))
    result = invoke(tmp_path, database, 'from _ingest_carbanak import records\n')
    assert result.returncode != 0 and 'no subject_node_table COPY data' in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)


@pytest.mark.parametrize('variant,message', [
    ('columns', 'subject schema changed'),
    ('row', 'Malformed CARBANAK subject COPY row'),
    ('truncated', 'pg_restore failed'),
])
def test_carbanak_changed_or_truncated_source_cannot_complete(tmp_path, variant, message):
    """Actual pg_restore must surface incompatible or incomplete source archives."""
    executable = os.environ.get('PG_RESTORE', 'pg_restore')
    if not shutil.which(executable):
        pytest.skip('CARBANAK integration requires PostgreSQL 17+ pg_restore (or PG_RESTORE)')
    data = (FIXTURES / 'carbanak-subjects.dump').read_bytes()
    identity = b'af5570f5-a181-8b7a-b78c-af4bc70a660f'
    if variant == 'columns':
        data = data.replace(b', path,', b', xxxx,')
    elif variant == 'row':
        data = data.replace(identity + b'\t', identity + b' ')
    else:
        data = data[:data.index(identity)]
    (tmp_path / 'carbanakv2_edr.dump').write_bytes(data)
    shutil.copyfile(FIXTURES / 'carbanak-ground-truth.csv', tmp_path / 'ground_truth.csv')
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_carbanak import records\n')
    assert result.returncode != 0 and message in result.stderr, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)


def test_carbanak_duplicate_uuid_preserves_one_process(tmp_path):
    """A repeated subject UUID remains one observation even with repeated labels."""
    executable = os.environ.get('PG_RESTORE', 'pg_restore')
    if not shutil.which(executable):
        pytest.skip('CARBANAK integration requires PostgreSQL 17+ pg_restore (or PG_RESTORE)')
    data = (FIXTURES / 'carbanak-subjects.dump').read_bytes().replace(
        b'e16e5de6-d41d-8d88-b3f8-6309681f1811', b'af5570f5-a181-8b7a-b78c-af4bc70a660f')
    (tmp_path / 'carbanakv2_edr.dump').write_bytes(data)
    shutil.copyfile(FIXTURES / 'carbanak-ground-truth.csv', tmp_path / 'ground_truth.csv')
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_carbanak import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (12,)


@pytest.mark.parametrize('before,after,identity,arguments', [
    (b'-Embedding', br'\055edding', 'af5570f5-a181-8b7a-b78c-af4bc70a660f', ['-edding']),
    (b'-Embedding', br'\x2Dedding', 'af5570f5-a181-8b7a-b78c-af4bc70a660f', ['-edding']),
    (b'\\N\t2634260\n', b'None\t34260\n', '240e621c-5d81-8b11-9e1b-205ec5001b28', []),
])
def test_carbanak_copy_escape_representations(tmp_path, before, after, identity, arguments):
    """Real pg_restore passes COPY octal/hex escapes through for the reader."""
    executable = os.environ.get('PG_RESTORE', 'pg_restore')
    if not shutil.which(executable):
        pytest.skip('CARBANAK integration requires PostgreSQL 17+ pg_restore (or PG_RESTORE)')
    # The uncompressed archive contains COPY text. Equal-length replacements
    # retain PostgreSQL's valid archive offsets while varying legal COPY values.
    data = (FIXTURES / 'carbanak-subjects.dump').read_bytes().replace(before, after, 1)
    (tmp_path / 'carbanakv2_edr.dump').write_bytes(data)
    shutil.copyfile(FIXTURES / 'carbanak-ground-truth.csv', tmp_path / 'ground_truth.csv')
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_carbanak import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT args FROM COMMANDS WHERE record_id=?', [identity]).fetchone() == (arguments,)
