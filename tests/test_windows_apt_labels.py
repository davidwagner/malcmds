"""Published Wazuh annotations survive CSV ingestion and storage."""
import csv
import json
from pathlib import Path

import duckdb
from test_ingest_batches import invoke


def test_native_annotations_and_unannotated_inventory(tmp_path):
    """Rule fallback and missing tags must keep their documented label meanings."""
    examples = json.loads((Path(__file__).parent/'fixtures/windows-apt/labels.json').read_text())
    rows = list(examples.values())
    prefix = '_source.data.win.eventdata.'
    for tags in ['', '[]']:
        rows.append({'_id': 'empty-'+tags, prefix+'commandLine': 'cmd.exe', '_source.rule.mitre.id': tags, '_source.rule.id': '11'})
    rows.append({'_id': 'inventory', '_source.data.process.cmd': '/bin/ls', '_source.data.process.args': '-l', '_source.rule.id': '92031'})
    (tmp_path/'source').mkdir()
    with (tmp_path/'source/combined.csv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=sorted(set().union(*(r.keys() for r in rows))))
        writer.writeheader()
        writer.writerows(rows)
    database = tmp_path/'commands.duckdb'
    source = 'from _ingest_misc import windows_apt as records\n'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        saved = con.execute('SELECT record_id,label,group_id,session_id FROM COMMANDS').fetchall()
    by_id = {row[0]: row[1:] for row in saved}
    for name, row in examples.items():
        rid = row['_index']+':'+row['_id']+':0'
        assert by_id[rid][0] == ('unknown' if name == 'rule-11' else 'malicious')
    assert all(label == 'unknown' for rid, label, _, _ in saved if rid.startswith(':'))
    assert all(group is None and session for _, _, group, session in saved)
    again = invoke(tmp_path, database, source)
    assert again.returncode == 0, again.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone()[0] == len(rows)


def test_observation_infrastructure_and_attack_tools(tmp_path):
    """Native parent GUIDs distinguish collection helpers from attack tools."""
    examples = json.loads((Path(__file__).parent / 'fixtures/windows-apt/infrastructure.json').read_text())
    rows = list({r['_id']: r for r in examples.values()}.values())
    (tmp_path / 'source').mkdir()
    with (tmp_path / 'source/combined.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=sorted(set().union(*(r.keys() for r in rows))))
        writer.writeheader()
        writer.writerows(reversed(rows))  # Children can precede their parents.
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_misc import windows_apt as records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        saved = dict(con.execute('SELECT record_id,label FROM COMMANDS').fetchall())
    for name, row in examples.items():
        expected = 'malicious' if name.startswith('attack-') else 'benign'
        assert saved[row['_index'] + ':' + row['_id'] + ':0'] == expected, (
            f'{name}: CSV decoding, Windows argument parsing, or process provenance '
            'changed; observation infrastructure must stay separate from attack tools'
        )


def test_infrastructure_requires_matching_process_evidence(tmp_path):
    """Changed arguments, missing provenance and executable lookalikes stay suspicious."""
    examples = json.loads((Path(__file__).parent / 'fixtures/windows-apt/infrastructure.json').read_text())
    prefix = '_source.data.win.eventdata.'
    wazuh = next(row for name, row in examples.items() if name.startswith('parent-helper-') and 'net1 accounts' in name)
    helper = next(row for name, row in examples.items() if name.startswith('helper-') and 'net1 accounts' in name)
    vmware = next(row for name, row in examples.items() if name.startswith('vmware-') and 'poweron' in name)
    vmhelper = next(row for name, row in examples.items() if name.startswith('helper-') and '/renew' in name)
    vmparent = next(row for row in examples.values() if row[prefix + 'processGuid'] == vmhelper[prefix + 'parentProcessGuid'])
    defender = next(row for name, row in examples.items() if name.startswith('defender-'))
    cases = [
        ('different-parent-path', wazuh, prefix + 'parentImage', r'C:\Temp\wazuh-agent.exe'),
        ('missing-parent', wazuh, prefix + 'parentImage', ''),
        ('different-command', wazuh, prefix + 'commandLine', 'net user guest /active:yes'),
        ('different-image', wazuh, prefix + 'image', r'C:\Temp\net.exe'),
        ('different-command-program', wazuh, prefix + 'commandLine', 'payload.exe accounts'),
        ('wrong-provider', wazuh, '_source.data.win.system.providerName', 'other'),
        ('wrong-event', wazuh, '_source.data.win.system.eventID', '7'),
        ('missing-guid', helper, prefix + 'parentProcessGuid', ''),
        ('zero-guid', helper, prefix + 'parentProcessGuid', '{00000000-0000-0000-0000-000000000000}'),
        ('wrong-guid', helper, prefix + 'parentProcessGuid', '{11111111-1111-1111-1111-111111111111}'),
        ('wrong-host', helper, '_source.data.win.system.computer', 'other-host'),
        ('missing-host', helper, '_source.data.win.system.computer', ''),
        ('wrong-parent-image', helper, prefix + 'parentImage', r'C:\Temp\net.exe'),
        ('different-helper-args', helper, prefix + 'commandLine', r'C:\Windows\System32\net1 user guest'),
        ('different-helper-image', helper, prefix + 'image', r'C:\Temp\net1.exe'),
        ('different-helper-program', helper, prefix + 'commandLine', 'payload.exe accounts'),
        ('different-vmware-script', vmware, prefix + 'commandLine', r'C:\Windows\system32\cmd.exe /c ""C:\Temp\poweron-vm-default.bat""'),
        ('extra-vmware-command', vmware, prefix + 'commandLine', r'C:\Windows\system32\cmd.exe /c ""C:\Program Files\VMware\VMware Tools\poweron-vm-default.bat"" & whoami'),
        ('wrong-vmware-parent', vmware, prefix + 'parentImage', r'C:\Temp\vmtoolsd.exe'),
        ('different-vmware-helper', vmhelper, prefix + 'commandLine', r'C:\Windows\System32\ipconfig /all'),
        ('wrong-vmware-helper-image', vmhelper, prefix + 'image', r'C:\Temp\ipconfig.exe'),
        ('wrong-vmware-helper-program', vmhelper, prefix + 'commandLine', 'payload.exe /renew'),
        ('defender-lookalike', defender, prefix + 'parentImage', r'C:\Temp\MsMpEng.exe'),
        ('defender-arguments', defender, prefix + 'commandLine', r'C:\Windows\System32\svchost.exe -k unexpected'),
        ('defender-child-lookalike', defender, prefix + 'image', r'C:\Temp\svchost.exe'),
    ]
    command_free = dict(wazuh)
    command_free.update({'_id': 'no-command', prefix + 'commandLine': ''})
    rows = [wazuh, vmparent, command_free]
    for name, original, field, new_value in cases:
        row = dict(original)
        row.update({'_id': name, field: json.dumps(new_value)[1:-1] if field.endswith(('Image', 'image', 'commandLine')) else new_value})
        # Each altered observation is a separate process, not an alias of its source.
        row[prefix + 'processGuid'] = ''
        rows.append(row)
    (tmp_path / 'source').mkdir()
    with (tmp_path / 'source/combined.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=sorted(set().union(*(r.keys() for r in rows))))
        writer.writeheader()
        writer.writerows(rows)
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_misc import windows_apt as records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        saved = dict(con.execute('SELECT record_id,label FROM COMMANDS').fetchall())
    for name, original, _, _ in cases:
        assert saved[original['_index'] + ':' + name + ':0'] == 'malicious', (
            f'{name}: an infrastructure label requires both the expected command and its provenance'
        )


def test_helper_without_parent_in_selected_records_stays_malicious(tmp_path):
    """A record limit cannot borrow a parent from outside the selected input."""
    examples = json.loads((Path(__file__).parent / 'fixtures/windows-apt/infrastructure.json').read_text())
    helper = next(row for name, row in examples.items() if name.startswith('helper-') and 'net1 accounts' in name)
    prefix = '_source.data.win.eventdata.'
    parent = next(row for row in examples.values() if row[prefix + 'processGuid'] == helper[prefix + 'parentProcessGuid'])
    (tmp_path / 'source').mkdir()
    with (tmp_path / 'source/combined.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(helper))
        writer.writeheader()
        writer.writerows([helper, parent])
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_misc import windows_apt as records\n', '--max-records', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT label FROM COMMANDS').fetchall() == [('malicious',)]
