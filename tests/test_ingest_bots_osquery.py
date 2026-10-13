"""Historical osquery source envelopes through ingestion and DuckDB."""
import csv
import json
from pathlib import Path
from types import SimpleNamespace

import duckdb
from _ingest import _initialize, _insert, command_table
from _ingest_bots import exported_observations, osquery_commands
from _ingest_bots_iocs import label_ioc_commands
from _ingest_processes import ProcessCommands


def test_native_osquery_audit_encoding(tmp_path):
    """Published dash/sed/cut arguments are decoded before argument splitting."""
    fixtures = json.loads((Path(__file__).parent / 'fixtures/bots/osquery.json').read_text())
    commands = []
    for fixture in fixtures:
        obj = json.loads(fixture['event']['_raw'])
        commands.extend(osquery_commands(obj, fixture['event']['host'], fixture['bucket'], fixture['row']))
    with duckdb.connect(str(tmp_path / 'native.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(commands, 'splunk-bots'))
        rows = con.execute('SELECT pgm,args FROM PROCESS_LAUNCHES').fetchall()
    assert rows and ('/bin/sed', ['s/:/ /g']) in rows
    assert not any('732F3A2F202F67' in args for _, args in rows), 'Historical audit serialization must be decoded exactly once'


def test_osquery_literal_empty_and_decoded_arguments(tmp_path):
    """Quoted hexadecimal stays literal; modern command strings stay unchanged."""
    inputs = [
        ('pack_process-monitoring_proc_events', '"/bin/sh" "-c" 6563686F206869', ['-c', 'echo hi']),
        ('pack_process-monitoring_proc_events', '"/usr/bin/cut" "-d" 20', ['-d', ' ']),
        ('pack_process-monitoring_proc_events', '"/bin/echo" "20" ""', ['20', '']),
        ('pack_process-monitoring_proc_events', '"/bin/echo" 6G', ['6G']),
        ('process_events', '/bin/echo 20', ['20']),
    ]
    commands = []
    for index, (name, cmdline, expected) in enumerate(inputs):
        obj = {'name': name, 'columns': {'path': '/bin/echo', 'cmdline': cmdline}}
        result = list(osquery_commands(obj, 'host', 'fixture', index))
        assert result[0].args == expected
        commands.extend(result)
    with duckdb.connect(str(tmp_path / 'args.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(commands, 'splunk-bots'))
        assert con.execute('SELECT args FROM PROCESS_LAUNCHES ORDER BY record_id').fetchall() == [(expected,) for _, _, expected in inputs]


def ingest_export_rows(directory, rows, bucket='fixture', first_row=1):
    """Run native CSV parsing, process selection and labeling into DuckDB twice."""
    path = directory / 'events.csv'
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader()
        # Preserve the source ordinal without copying unrelated export contents.
        for _ in range(first_row - 1):
            writer.writerow(dict.fromkeys(rows[0], ''))
        writer.writerows(rows)
    previous = None
    for replay in range(2):
        with ProcessCommands() as processes:
            commands = list(exported_observations(
                [(bucket, path)], SimpleNamespace(max_records=None), processes,
            ))
            commands.extend(processes.commands())
        with duckdb.connect(str(directory / f'sessions-{replay}.duckdb')) as con:
            _initialize(con)
            _insert(con, command_table(label_ioc_commands(commands), 'splunk-bots'))
            result = con.execute(
                'SELECT record_id,pgm,args,dataset_label,group_id,os,session_id '
                'FROM PROCESS_LAUNCHES ORDER BY record_id'
            ).fetchall()
        if previous is not None:
            assert result == previous
        previous = result
    return result


def test_native_sed_events_have_separate_sessions(tmp_path):
    """The published PIDs 7289 and 7292 share an account, but retain separate IDs."""
    fixtures = json.loads((Path(__file__).parent / 'fixtures/bots/osquery.json').read_text())
    events = [fixture['event'] for fixture in fixtures
              if json.loads(fixture['event']['_raw'])['columns']['pid'] in {'7289', '7292'}]
    assert len(events) == 2
    rows = ingest_export_rows(tmp_path, events)
    assert rows == [
        (f'botsv3_data_set.tgz:fixture:{row}:1:1:0', '/bin/sed', ['s/:/ /g'],
         'unknown', None, 'linux', f'splunk-bots:record:botsv3_data_set.tgz:fixture:{row}:1')
        for row in (1, 2)
    ]


def test_event_indexes_and_literal_arguments(tmp_path):
    """Skipped events count toward IDs and process arguments remain literal.

    The current process parser emits at most one command per event, so multiple
    yielded commands from one event cannot be exercised without a test double.
    """
    events = [
        {'name': 'process_events', 'columns': {'cmdline': '   '}},
        {'name': 'process_events', 'columns': {
            'cmdline': '/bin/echo hello; /usr/bin/id', 'uid': '0', 'auid': '1000',
        }},
        {'name': 'process_events', 'columns': {
            'cmdline': '/bin/echo goodbye', 'uid': '0', 'auid': '1000',
        }},
    ]
    rows = ingest_export_rows(tmp_path, [{
        '_raw': '\n'.join(json.dumps(event) for event in events) + '\n',
        'host': 'host::hoth', 'source': 'source::osquery',
        'sourcetype': 'sourcetype::osquery:results',
    }])
    prefix = 'botsv3_data_set.tgz:fixture:1'
    assert rows == [
        (f'{prefix}:2:2:0', '/bin/echo', ['hello;', '/usr/bin/id'], 'unknown', None, 'linux',
         f'splunk-bots:record:{prefix}:2'),
        (f'{prefix}:3:3:0', '/bin/echo', ['goodbye'], 'unknown', None, 'linux',
         f'splunk-bots:record:{prefix}:3'),
    ]


def test_native_multi_event_export_sessions(tmp_path):
    """Retain source row 60024, JSON indexes and the preferred process record."""
    fixture = json.loads((Path(__file__).parent / 'fixtures/bots/osquery-multi.json').read_text())
    rows = ingest_export_rows(tmp_path, [fixture['event']], fixture['bucket'], fixture['row'])
    prefix = 'botsv3_data_set.tgz:db_1534766463_1534762020_305:60024'
    script = '/opt/splunkforwarder/etc/apps/Splunk_TA_nix/bin/cpu.sh'
    expected = [
        (2, '/bin/bash', ['-c', script]),
        (4, '/usr/bin/dirname', [script]),
        (5, '/bin/grep', ['-i', 'en_US.utf']),
        (6, '/usr/bin/locale', ['-a']),
        (7, '/bin/gawk', ['NR==1 {printf $1}']),
        (8, '/bin/uname', ['-s']),
        (9, '/bin/sed', ['s/:/ /g']),
        (10, '/bin/sed', ['s/:/ /g']),
        (11, '/bin/sed', ['s/:/ /g']),
    ]
    assert rows == sorted([
        (f'{prefix}:{index}:{index}:0', pgm, args, 'unknown', None, 'linux',
         f'splunk-bots:record:{prefix}:{index}')
        for index, pgm, args in expected
    ])
