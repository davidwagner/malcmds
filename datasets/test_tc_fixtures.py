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
        row['datum'][1]['uuid'] = (100 + index).to_bytes(16, 'big')
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


def test_fivedirections_native_images(tmp_path):
    """Original option-only observations retain the first option and semicolons."""
    from test_ingest_performance import ingest

    root = tmp_path / 'tc-e3-fivedirections'
    (root / 'data').mkdir(parents=True)
    shutil.copyfile(HERE / 'fixtures/fivedirections-images.bin.gz', root / 'data/sample.bin.gz')
    database = tmp_path / 'images.duckdb'
    result = ingest(root, database, 'from _ingest_tc import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        before = con.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall()
        rows = con.execute('SELECT pgm,args FROM COMMANDS').fetchall()
        assert ('TabTip32.exe', ['/loadhooks', '/Parent:0000000000001e98']) in rows, 'FiveDirections CommandLine can contain only arguments; ImageFileName supplies the executable'
        assert ('TabTip.exe', ['/QuitInfo:00000000000001C4;00000000000001B4;']) in rows
        assert (r'C:\WINDOWS\system32\DllHost.exe', ['/Processid:{7966B4D8-4FDC-4126-A10B-39A3209AD251}']) in rows
        assert (r'C:\Program Files\Windows Defender\MSASCuiL.exe', []) in rows
        assert con.execute("SELECT count(*) FROM COMMANDS WHERE (label='malicious-group') <> (group_id IS NOT NULL) OR shell_input IS NOT NULL OR len(other_tokens)>0").fetchone()[0] == 0
    result = ingest(root, database, 'from _ingest_tc import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall() == before


def test_fivedirections_process_images_and_prefixes(tmp_path):
    """Actual native ingestion resolves earlier Subjects only within their process."""
    import copy
    import gzip
    import uuid
    import fastavro
    from test_ingest_performance import ingest

    root = tmp_path / 'tc-e3-fivedirections'
    (root / 'data').mkdir(parents=True)
    with gzip.open(HERE / 'fixtures/fivedirections-images.bin.gz', 'rb') as stream:
        reader = fastavro.reader(stream, return_record_name=True)
        native = list(reader)
        schema = reader.writer_schema
    with gzip.open(HERE / 'fixtures/trace-no-args.bin.gz', 'rb') as stream:
        subject = next(fastavro.reader(stream, return_record_name=True))
    # Add CDM's collector-session qualification to this constructed container.
    schema['fields'].append({'name': 'sessionNumber', 'type': 'int', 'default': 0})
    rows = []
    expected = []
    cases = [
        ('rdpclip', 'rdpclip.exe', 'rdpclip.exe', []),
        ('alias -x', 'actual.exe', 'actual.exe', ['-x']),
        (r'C:\Program Files\App\app.exe /q', 'app.exe', r'C:\Program Files\App\app.exe', ['/q']),
        (r'"C:\Program Files\App\app.exe" /q', 'app.exe', r'C:\Program Files\App\app.exe', ['/q']),
        (r'C:\Windows\rdpclip', 'rdpclip.exe', r'C:\Windows\rdpclip.exe', []),
        ('', 'empty.exe', 'empty.exe', []),
        ('noimage.exe /x', None, 'noimage.exe', ['/x']),
        ('/unresolved', None, None, []),
        ('-unresolved', 'N/A', None, []),
        ('short.exe /x', r'C:\actual\short.exe', r'C:\actual\short.exe', ['/x']),
    ]
    for index, (text, image, program, args) in enumerate(cases):
        row = copy.deepcopy(native[0])
        event = row['datum'][1]
        event['uuid'] = uuid.UUID(int=100+index).bytes
        event['predicateObject'] = ('com.bbn.tc.schema.avro.cdm18.UUID', uuid.UUID(int=200+index).bytes)
        event['properties'] = {'CommandLine': text}
        if image is not None:
            event['properties']['ImageFileName'] = image
        rows.append(row)
        if program:
            expected.append((program, args))
    early = copy.deepcopy(subject)
    early['datum'][1]['uuid'] = native[0]['datum'][1]['predicateObject'][1]
    early['datum'][1]['hostId'] = native[0]['datum'][1]['hostId']
    early['datum'][1]['cmdLine'] = '/early'
    early['datum'][1]['startTimestampNanos'] = native[0]['datum'][1]['timestampNanos'] - 1
    image_only = copy.deepcopy(native[0])
    image_only['datum'][1]['properties']['CommandLine'] = ''
    rows += [early, image_only]
    expected += [('dllhost.exe', ['/early'])]
    other_host = copy.deepcopy(early)
    other_host['datum'][1]['hostId'] = uuid.UUID(int=999).bytes
    other_restart = copy.deepcopy(early)
    other_restart['sessionNumber'] = 9
    rows += [other_host, other_restart]
    with (root / 'data/constructed.bin').open('wb') as stream:
        fastavro.writer(stream, schema, rows)
    database = tmp_path / 'images.duckdb'
    result = ingest(root, database, 'from _ingest_tc import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT pgm,args FROM COMMANDS ORDER BY rowid').fetchall() == expected, 'Process UUIDs must remain qualified by host and collector restart; FORK images belong to the child'


def test_tc_creation_snapshots_and_distinct_execs(tmp_path):
    """FORK/Subject/EXIT copies collapse; separate native EXECUTE IDs survive."""
    import copy
    import gzip
    import fastavro
    from test_ingest_performance import ingest

    root = tmp_path / 'tc-e3-fivedirections'
    (root / 'data').mkdir(parents=True)
    with gzip.open(HERE / 'fixtures/fivedirections-images.bin.gz', 'rb') as stream:
        reader = fastavro.reader(stream, return_record_name=True)
        native = list(reader)
        schema = reader.writer_schema
    fork = copy.deepcopy(native[0])
    event = fork['datum'][1]
    process = event['predicateObject']
    with gzip.open(HERE / 'fixtures/trace-no-args.bin.gz', 'rb') as stream:
        subject = next(fastavro.reader(stream, return_record_name=True))
    subject['datum'][1].update(uuid=process[1], hostId=event['hostId'],
                              cmdLine=event['properties']['CommandLine'],
                              startTimestampNanos=event['timestampNanos'] - 1)
    exit_row = copy.deepcopy(fork)
    exit_row['datum'][1].update(type='EVENT_EXIT', subject=process,
                               timestampNanos=event['timestampNanos'] + 100)
    rows = [subject, exit_row, fork]
    for index in range(2):
        execute = copy.deepcopy(fork)
        execute['datum'][1].update(type='EVENT_EXECUTE', subject=process,
                                  uuid=(900 + index).to_bytes(16, 'big'),
                                  timestampNanos=event['timestampNanos'] + 200)
        rows.extend([execute, copy.deepcopy(execute)])
    other_process = copy.deepcopy(fork)
    other_process['datum'][1]['predicateObject'] = ('com.bbn.tc.schema.avro.cdm18.UUID', (800).to_bytes(16, 'big'))
    other_process['datum'][1]['uuid'] = (801).to_bytes(16, 'big')
    rows.append(other_process)
    creation_exec = copy.deepcopy(other_process)
    creation_exec['datum'][1].update(type='EVENT_EXECUTE',
                                    subject=other_process['datum'][1]['predicateObject'],
                                    uuid=(802).to_bytes(16, 'big'))
    rows.append(creation_exec)
    with (root / 'data/snapshots.bin').open('wb') as stream:
        fastavro.writer(stream, schema, rows)
    database = tmp_path / 'commands.duckdb'
    result = ingest(root, database, 'from _ingest_tc import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        result_rows = con.execute('SELECT pgm,args,record_id FROM COMMANDS').fetchall()
        assert len(result_rows) == 4, 'One creation per process plus both distinct EXECUTE IDs; EXIT time is not another launch'
        assert len({row[2] for row in result_rows}) == 4
        assert len({(row[0], tuple(row[1])) for row in result_rows}) == 1, 'Identical argv must not merge distinct process identities'
        assert not any(':Subject:' in row[2] for row in result_rows), 'FORK supplies the preferred actual creation observation'
