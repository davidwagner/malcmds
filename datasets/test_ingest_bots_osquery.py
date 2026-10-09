"""Historical osquery source envelopes through ingestion and DuckDB."""
import json
from pathlib import Path

import duckdb

from _ingest import _initialize, _insert, command_table
from _ingest_bots import osquery_commands


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
        rows = con.execute('SELECT pgm,args FROM COMMANDS').fetchall()
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
        assert con.execute('SELECT args FROM COMMANDS ORDER BY record_id').fetchall() == [(expected,) for _, _, expected in inputs]
