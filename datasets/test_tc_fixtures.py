"""Native TC excerpts exercise the Avro reader and DuckDB writer without downloads."""

import shutil
import subprocess
import sys
from pathlib import Path

import duckdb

HERE = Path(__file__).parent


def test_trace_executable_only_subjects(tmp_path):
    """Two original TRACE Subjects retain argv[0] across dependency upgrades."""
    root = tmp_path / 'datasets' / 'tc-e3-trace'
    (root / 'data').mkdir(parents=True)
    # Unmodified Subjects from ta1-trace-e3-official-1.bin.tar.gz, first
    # 200,000 records. Keep the release's original CDM18 Avro schema too.
    shutil.copyfile(HERE / 'fixtures/trace-no-args.bin.gz', root / 'data/sample.bin.gz')
    executable = root / 'ingest'
    executable.write_text((HERE / 'tc-e3-trace/ingest').read_text().replace(
        'sys.path.insert(0, str(Path(__file__).resolve().parents[1]))',
        f'sys.path.insert(0, {str(HERE.resolve())!r})'))
    database = tmp_path / 'commands.duckdb'
    argv = [sys.executable, str(executable), '--db', str(database)]
    subprocess.run(argv, capture_output=True, text=True, check=True)
    with duckdb.connect(str(database)) as con:
        before = con.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall()
        assert con.execute('SELECT pgm,args FROM COMMANDS ORDER BY pgm').fetchall() == [('-bash', []), ('groups', [])], 'Native CDM18 Subjects must retain executable-only argv'
        assert con.execute("SELECT count(*) FROM COMMANDS WHERE contains(record_id, '5325f54a-77b4-2309-3aa8-2df747293484')").fetchone()[0] == 1
        assert con.execute('SELECT count(*) FROM COMMANDS WHERE shell_input IS NOT NULL OR len(other_tokens)>0').fetchone()[0] == 0
    subprocess.run(argv, capture_output=True, text=True, check=True)
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall() == before


def test_trace_literal_numeric_words_and_nul_vector(tmp_path):
    """Flattened TRACE text has no encoding marker; numeric words stay literal."""
    import copy
    import gzip
    import fastavro
    from test_ingest_performance import ingest

    root = tmp_path / 'tc-e3-trace'
    (root / 'data').mkdir(parents=True)
    with gzip.open(HERE / 'fixtures/trace-no-args.bin.gz', 'rb') as stream:
        reader = fastavro.reader(stream, return_record_name=True)
        native = list(reader)
        schema = reader.writer_schema
    # Independently constructed command variants retain native Subject layout.
    texts = ['gdb --ex set backtrace limit 2000', 'printf "%s" "2020" 612062',
             'printf\0%s\0a b\0']
    records = []
    for index, text in enumerate(texts):
        row = copy.deepcopy(native[0])
        row['datum'][1]['cmdLine'] = text
        row['datum'][1]['startTimestampNanos'] += index
        records.append(row)
    with (root / 'data/literals.bin').open('wb') as stream:
        fastavro.writer(stream, schema, records)
    database = tmp_path / 'commands.duckdb'
    result = ingest(root, database, 'from _ingest_tc import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute('SELECT pgm,args FROM COMMANDS ORDER BY rowid').fetchall()
        assert rows == [('gdb', ['--ex', 'set', 'backtrace', 'limit', '2000']),
                        ('printf', ['%s', '2020', '612062']), ('printf', ['%s', 'a b'])], 'TRACE text must never infer hex encoding from token spelling'
        assert all('\0' not in arg for _, args in rows for arg in args)


def test_raw_audit_hex_argument_still_decodes(tmp_path):
    """Raw audit's explicit unquoted field encoding remains independent of TRACE."""
    import tarfile
    from test_ingest_lade_otrf import add_member, zipped
    from test_ingest_performance import ingest

    root = tmp_path / 'otrf-security-datasets'
    root.mkdir()
    # Authentic audit event with an independently constructed encoded argument.
    lines = (HERE / 'otrf_audit_fixture.log').read_text().splitlines()[:6]
    lines[1] = lines[1].replace('a1="-a"', 'a1=612062')
    with tarfile.open(root / 'security-datasets.tar.gz', 'w:gz') as archive:
        add_member(archive, 'OTRF/datasets/atomic/linux/host/audit.zip', zipped('audit.log', '\n'.join(lines)))
    database = tmp_path / 'audit.duckdb'
    result = ingest(root, database, 'from _ingest_otrf import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT pgm,args FROM COMMANDS').fetchall() == [('/usr/sbin/arp', ['a b'])]
