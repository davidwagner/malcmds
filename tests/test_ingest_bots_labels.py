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


def test_native_ioc_commands_through_database(tmp_path):
    """Published Windows, osquery and shell commands retain IOC labels in storage."""
    from _ingest_bots import history_commands, osquery_commands
    from _ingest_bots_iocs import label_ioc_commands
    from _ingest_windows import event_commands

    fixtures = json.loads((Path(__file__).parent / 'fixtures/bots/iocs.json').read_text())
    commands = []
    for fixture in fixtures:
        row = fixture['event']
        raw, host = row['_raw'], row['host'].removeprefix('host::')
        record = f"{fixture['bucket']}:{fixture['row']}"
        kind = row['sourcetype'].removeprefix('sourcetype::').lower()
        if kind == 'osquery:results':
            commands.extend(osquery_commands(json.loads(raw), host, record, 1))
        elif kind == 'bash_history':
            commands.extend(history_commands(raw, record, host))
        elif kind.startswith('xmlwineventlog'):
            for number, fields in xml_events(io.StringIO(raw)):
                commands.extend(event_commands(fields, 'splunk-bots', record, number))
        else:
            commands.extend(event_commands(text_fields(raw), 'splunk-bots', record, 1))
    with duckdb.connect(str(tmp_path / 'iocs.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(label_ioc_commands(commands), 'splunk-bots'))
        rows = con.execute('SELECT pgm,args,label,group_id FROM COMMANDS').fetchall()
    malicious = [(pgm, args) for pgm, args, label, _ in rows if label == 'malicious']
    assert len(malicious) == 22, 'Native parser changes must preserve all 22 newly identified IOC commands'
    assert any(pgm.endswith('hdoor.exe') for pgm, _ in malicious)
    assert any('45.77.53.176' in ' '.join(args) for _, args in malicious)
    assert any('frothlywebcode' in ' '.join(args) for _, args in malicious)
    assert all(group is None for _, _, _, group in rows)
    assert any(pgm == '/tmp/colonelnew' and label == 'unknown' for pgm, _, label, _ in rows), 'An unmatched exploit command must not become benign'


def test_ioc_policy_through_shell_parser_and_database(tmp_path):
    """The pinned indicator set is literal, case-insensitive and command-specific."""
    from _ingest import Command
    from _ingest_bots import history_commands
    from _ingest_bots_iocs import label_ioc_commands

    # Keep expectations independent of the implementation's list. This catches
    # accidental removal of an indicator when the policy or parser changes.
    indicators = [
        '45.77.53.176', '104.207.83.63', '139.198.18.205', '35.153.154.221',
        '209.107.196.112', '82.102.18.111', 'botsv3.ministerofmayhem.com',
        'hdoor.exe', 'iexeplorer.exe', 'definitelydontinvestigatethisfile.sh',
        'frothly-brewery-financial-planning-fy2019-draft.xlsm',
        '586ef56f4d8963dd546163ac31c865d7', 'akiajogcdxj5nw5pxupa',
        'frothlywebcode', 'hyunki1984@naver.com', 'yunki1984@naver.com',
    ]
    commands = []
    for index, indicator in enumerate(indicators):
        commands.extend(history_commands(f"echo '{indicator.upper()}'", str(index), 'session'))
    commands.extend(history_commands('echo 45x77x53x176; echo ordinary', 'negative', 'hdoor.exe'))
    commands.extend(history_commands('echo hdoor.exe; echo ordinary', 'siblings', 'session'))
    commands.append(Command('echo', ['ordinary'], 'known', label='malicious'))
    commands.append(Command('echo', ['hdoor.exe'], 'benign', label='benign'))
    with duckdb.connect(str(tmp_path / 'policy.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(label_ioc_commands(commands), 'splunk-bots'))
        labels = dict(con.execute('SELECT record_id,label FROM COMMANDS').fetchall())
    assert all(labels[f'{index}:shell:0'] == 'malicious' for index in range(len(indicators))), 'All 16 pinned indicators must survive shell parsing and storage'
    assert labels['negative:shell:0'] == labels['negative:shell:1'] == 'unknown'
    assert labels['siblings:shell:0'] == 'malicious'
    assert labels['siblings:shell:1'] == 'unknown', 'Another command in the same shell input must not spread its IOC label'
    assert labels['known'] == 'malicious'
    assert labels['benign'] == 'benign'
