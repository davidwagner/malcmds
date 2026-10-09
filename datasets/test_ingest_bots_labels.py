"""BOTS exploit invocations labeled with their native context before storage."""
import io
import json
from pathlib import Path

import duckdb

from _ingest import _initialize, _insert, command_table
from _ingest_bots import bots_event_commands
from _ingest_windows import text_fields, xml_events


def native_fields():
    """Read the publisher's process events and exporter time/host context."""
    fixtures = json.loads((Path(__file__).parent / 'fixtures/bots/attack.json').read_text())
    for fixture in fixtures:
        row = fixture['event']
        raw = row['_raw']
        events = xml_events(io.StringIO(raw)) if raw.startswith('<') else [(1, text_fields(raw))]
        for number, fields in events:
            fields.setdefault('Computer', row['host'].removeprefix('host::'))
            fields['_bots_time'] = row['_time']
            yield fields, f"{fixture['bucket']}:{fixture['row']}", number


def test_native_exploit_invocations_and_order(tmp_path):
    """Native id and exploit-source invocations become malicious, without groups."""
    fixtures = list(native_fields())
    observed = []
    for index, sequence in enumerate((fixtures, list(reversed(fixtures)))):
        commands = [command for fields, record, number in sequence for command in bots_event_commands(fields, record, number)]
        with duckdb.connect(str(tmp_path / f'labels-{index}.duckdb')) as con:
            _initialize(con)
            _insert(con, command_table(commands, 'splunk-bots'))
            rows = con.execute('SELECT record_id,pgm,args,label,group_id FROM COMMANDS ORDER BY record_id').fetchall()
            observed.append(rows)
    assert observed[0] == observed[1]
    positives = [row for row in observed[0] if row[3] == 'malicious']
    assert positives
    assert any(row[2][-1] == 'id' for row in positives)
    assert any('/tmp/colonel' in ' '.join(row[2]) for row in positives)
    assert all(row[4] is None for row in positives)
    assert sum(row[3] == 'unknown' for row in observed[0]) > 0


def test_wrong_host_time_path_and_file_inspection(tmp_path):
    """The basename or text mention alone never establishes an attack launch."""
    fields, _, _ = next(item for item in native_fields() if item[0].get('EventID') == '1')
    cases = [
        {'Computer': 'other-host'},
        {'_bots_time': '1534760000'},
        {'_bots_time': 'not-a-time'},
        {'Image': r'C:\Users\Public\iexeplorer.exe'},
        {'EventID': '3'},
        {'Image': 'powershell.exe', 'CommandLine': r'powershell.exe Get-Item C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe'},
        {'CommandLine': r'C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe --help'},
    ]
    commands = []
    for number, changes in enumerate(cases):
        variant = dict(fields)
        variant.update(changes)
        commands.extend(bots_event_commands(variant, 'comparison', number))
    with duckdb.connect(str(tmp_path / 'negative.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(commands, 'splunk-bots'))
        assert con.execute("SELECT count(*) FROM COMMANDS WHERE label != 'unknown'").fetchone()[0] == 0
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone()[0] == len(cases)
