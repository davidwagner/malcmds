"""Issue #115 decisions survive real CSV ingestion and DuckDB storage."""

import base64
import csv
import json
from pathlib import Path

import duckdb
from test_ingest_batches import invoke

PREFIX = '_source.data.win.eventdata.'
FIXTURE = Path(__file__).parent / 'fixtures/windows-apt/policy.json'


def ingest_rows(tmp_path, rows):
    """Store exported events with the production reader and writer."""
    (tmp_path / 'source').mkdir()
    with (tmp_path / 'source/combined.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=sorted(set().union(*(row.keys() for row in rows))))
        writer.writeheader()
        writer.writerows(rows)
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_misc import windows_apt as records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as connection:
        records = connection.execute(
            'SELECT record_id, label, pgm, args, group_id, session_id FROM COMMANDS'
        ).fetchall()
    assert len(records) == len(rows), 'Each process event must retain one stored command.'
    return {record[0]: record[1:] for record in records}


def event(name, command, rule='92041', tags=('T1027', 'T1112')):
    """Serialize a synthetic event with the source export's JSON string layer."""
    return {
        '_index': 'policy', '_id': name,
        PREFIX + 'commandLine': json.dumps(command)[1:-1],
        '_source.rule.id': rule, '_source.rule.mitre.id': ', '.join(tags),
        '_source.data.win.system.computer': 'policy-test-host',
        PREFIX + 'logonGuid': '{12345678-1234-1234-1234-123456789012}',
    }


def test_source_command_exceptions_and_preserved_arguments(tmp_path):
    """Traceable source events cover every documented family of exceptions.

    Fixture source_csv_record includes the header. Native _id and _index values
    identify each event. Stored argument snapshots were captured before the
    labeling change, so JSON/HTML decoding or tokenization regressions are visible.
    """
    examples = json.loads(FIXTURE.read_text())
    saved = ingest_rows(tmp_path, [example['row'] for example in examples])
    differences = []
    for example in examples:
        row = example['row']
        record_id = row['_index'] + ':' + row['_id'] + ':0'
        label, pgm, args, group, session = saved[record_id]
        if label != example['label']:
            differences.append(f"{example['name']} (CSV {example['source_csv_record']}): {label} != {example['label']}")
        assert (pgm, args) == (example['expected_pgm'], example['expected_args']), (
            f"{example['name']}: CSV decoding or Windows argument parsing changed; "
            'a label decision must preserve the observed program and arguments'
        )
        assert group is None
        assert session.startswith('windows-apt-2025:')
        guid = row.get(PREFIX + 'logonGuid', '')
        if guid and guid.strip('{}0-'):
            assert session.endswith(':' + guid)
    assert not differences, '\n'.join(differences)


def test_rule_and_tag_defaults_and_explicit_precedence(tmp_path):
    """Exact IDs and explicit unknown decisions follow the issue's tables."""
    cases = []
    # This opaque executable allows defaults to decide without a command exception.
    command = 'unclassified.exe'
    rule_groups = {
        'malicious': ('61620', '92024', '92074', '92029', '92041', '92046', '92056'),
        'benign': ('61640', '92000', '92031', '92033', '92036', '92039', '92055', '92057', '92076'),
        'unknown': ('61618', '61625', '92004', '92005', '92006', '92021', '92027', '92032', '92043', '92052', '92066'),
    }
    for label, rules in rule_groups.items():
        for rule in rules:
            # Contrary tags must not override a mapped rule, including unknown.
            tags = ('T1059.005',) if label == 'malicious' else ('T1112',)
            cases.append((event('rule-' + rule, command, rule, tags), label))
    tag_cases = [
        ((), 'unknown'), (('T1059',), 'unknown'), (('T1059.001',), 'unknown'),
        (('T1059.003',), 'unknown'), (('T1059.005',), 'benign'),
        (('T1027',), 'malicious'), (('T1027.004',), 'unknown'),
        (('T1003.002',), 'malicious'), (('T1105',), 'malicious'),
        (('T1112',), 'malicious'), (('T1218',), 'benign'),
        (('T1546',), 'benign'), (('T1574.001',), 'benign'),
        (('T1059.005', 'T1218'), 'benign'),
        (('T1059.005', 'T9999'), 'unknown'),
        (('T1112', 'T1059.005'), 'malicious'),
        (('T9999',), 'unknown'), (('T1059.0050',), 'unknown'),
    ]
    for index, (tags, label) in enumerate(tag_cases):
        cases.append((event(f'tag-{index}', command, 'unmapped', tags), label))
    cases.extend([
        (event('explicit-unknown', 'net user guest /active:yes', '92039'), 'unknown'),
        (event('explicit-benign', 'whoami', '92041'), 'benign'),
        (event('guest-tag', 'net user guest /active:yes', 'unmapped', ('T1574.001',)), 'unknown'),
    ])
    saved = ingest_rows(tmp_path, [row for row, _ in cases])
    differences = [f"{row['_id']}: {saved['policy:' + row['_id'] + ':0'][0]} != {label}"
                   for row, label in cases if saved['policy:' + row['_id'] + ':0'][0] != label]
    assert not differences, '\n'.join(differences)


def test_compound_commands_and_encoded_payloads_are_data(tmp_path):
    """Visible attacks win; hidden operations prevent a routine-command label."""
    cases = [
        ('routine-then-attack', 'cmd.exe /c whoami & reg save HKLM\\SAM C:\\Temp\\sam.hiv', 'malicious'),
        ('routine-then-hidden', 'cmd.exe /c whoami & powershell.exe -File C:\\Temp\\unavailable.ps1', 'unknown'),
        ('routine-pair', 'cmd.exe /c whoami & hostname', 'benign'),
        ('invalid-base64', 'powershell.exe -EncodedCommand !notbase64!', 'unknown'),
        ('missing-payload', 'powershell.exe -EncodedCommand', 'unknown'),
        ('invalid-utf16', 'powershell.exe -enc /w==', 'unknown'),
    ]
    payloads = [
        ('encoded-greeting', 'Write-Host "Hey, Atomic!"', 'benign'),
        ('encoded-dump', 'Invoke-Mimikatz -DumpCreds', 'malicious'),
        ('encoded-hidden', '& C:\\Temp\\unavailable.ps1', 'unknown'),
        ('encoded-write', f'Set-Content -Path "{tmp_path / "must-not-exist"}" -Value executed', 'unknown'),
    ]
    for name, payload, label in payloads:
        encoded = base64.b64encode(payload.encode('utf-16le')).decode('ascii')
        cases.append((name, 'powershell.exe -EncodedCommand ' + encoded, label))
    rows = [event(name, command) for name, command, _ in cases]
    saved = ingest_rows(tmp_path, rows)
    differences = []
    for name, command, expected in cases:
        label, _, args, _, _ = saved['policy:' + name + ':0']
        if label != expected:
            differences.append(f'{name}: {label} != {expected}')
        if '-EncodedCommand ' in command:
            assert args == ['-EncodedCommand', command.split('-EncodedCommand ', 1)[1]], (
                'Encoded PowerShell must remain encoded in the stored arguments.'
            )
    assert not (tmp_path / 'must-not-exist').exists(), 'Ingestion must never execute a decoded payload.'
    assert not differences, '\n'.join(differences)
