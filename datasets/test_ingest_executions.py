"""Execution selection checked with real source records and DuckDB writes."""
import gzip
import json
from pathlib import Path
from types import SimpleNamespace

import duckdb
from _ingest import Command, _initialize, _insert, command_table
from _ingest_misc import audit_events
from _ingest_optc import file_commands
from _ingest_processes import ProcessCommands
from _ingest_windows import Budget, carbon_black_commands

FIXTURES = Path(__file__).parent / 'fixtures/executions'


def store(commands, tmp_path):
    """Run the actual Arrow and DuckDB insertion path."""
    with duckdb.connect(str(tmp_path / 'commands.duckdb')) as db:
        _initialize(db)
        _insert(db, command_table(commands, 'test'))
        return db.execute('SELECT pgm,args,record_id FROM COMMANDS ORDER BY record_id').fetchall()


def test_native_audit_repeated_alerts(tmp_path):
    """Two copies of one publisher event are one execution, across EOE records."""
    raw = (FIXTURES / 'audit.log').read_text()
    events = list(audit_events(raw.splitlines()))
    assert len(events) == 2, 'Three published observations identify only two audit event IDs'
    commands = [Command(argv[0], argv[1:], event) for event, _, argv, _, _ in events]
    assert len(store(commands, tmp_path)) == 2


def test_audit_exec_selection_and_failed_target(tmp_path):
    """Architecture-specific calls, USER_CMD, failed attempts and non-exec titles."""
    lines = [
        'type=SYSCALL msg=audit(1:1): arch=c000003e syscall=9 exe="/usr/bin/ls"',
        'type=PROCTITLE msg=audit(1:1): proctitle=7375646f006c7300',
        'type=PROCTITLE msg=audit(1:2): proctitle=7375646f006c7300',
        'type=SYSCALL msg=audit(1:3): arch=c000003e syscall=322 success=no exe="/bin/bash"',
        'type=PATH msg=audit(1:3): name="/missing/program" nametype=NORMAL',
        'type=EXECVE msg=audit(1:3): argc=2 a0="program" a1="arg"',
        'type=SYSCALL msg=audit(1:4): arch=40000003 syscall=11 success=yes',
        'type=EXECVE msg=audit(1:4): argc=1 a0="echo"',
        'type=USER_CMD msg=audit(1:5): cmd=696400 exe="/usr/bin/sudo"',
        'type=SYSCALL msg=audit(1:6): arch=c00000b7 syscall=281 success=no',
        'type=EXECVE msg=audit(1:6): argc=1 a0="echo"',
    ]
    events = list(audit_events(lines))
    assert [e[0] for e in events] == ['1:3', '1:4', '1:5', '1:6']
    assert events[0][1]['exe'] == '"/missing/program"'
    commands = [Command(argv[0], argv[1:], event) for event, _, argv, _, _ in events]
    assert len(store(commands, tmp_path)) == 4


def test_carbon_black_actor_child_and_repeated_sensors(tmp_path):
    """Native parent and child GUIDs remain separate; repeated sensors collapse."""
    fixtures = [json.loads(line) for line in (FIXTURES / 'carbon-black.jsonl').read_text().splitlines()]
    budget = Budget(SimpleNamespace(max_records=None))
    identities = set()
    with ProcessCommands() as processes:
        for sensor in ('edr', 'ngav'):
            for number, fields in enumerate(fixtures):
                source = f'atlasv2.tar.gz/atlasv2/data/attack/h1/cbc-{sensor}/{sensor}-h1-s4.jsonl'
                for identity, command, creation in carbon_black_commands(fields, source, number, budget, 'unknown', None):
                    identities.add(identity)
                    processes.add(identity, command, creation)
        commands = list(processes.commands())
    assert len(commands) == len(identities)
    assert len(commands) < len(fixtures) * 4
    assert any(c.pgm.lower().endswith('firefox.exe') for c in commands)
    assert len(store(commands, tmp_path)) == len(commands)


def test_native_optc_process_observations(tmp_path):
    """Repeated native PROCESS observations produce one representative per UUID."""
    from _optc_labels import load_labels
    events = json.loads((FIXTURES / 'optc.json').read_text())
    path = tmp_path / 'ecar/evaluation/part.json.gz'
    path.parent.mkdir(parents=True)
    with gzip.open(path, 'wt') as stream:
        for event in events + events:
            stream.write(json.dumps(event) + '\n')
    commands = list(file_commands(tmp_path, path, None, load_labels(tmp_path)))
    expected = {(e['hostname'].lower(), e['objectID']) for e in events}
    assert len(commands) == len(expected)
    assert len(store(commands, tmp_path)) == len(expected)


def test_creation_without_guid_and_later_attack_annotation(tmp_path):
    """Explicit launches survive missing IDs and selected argv retains attack evidence."""
    budget = Budget(SimpleNamespace(max_records=None))
    fields = {'type': 'endpoint.event.procstart', 'target_cmdline': 'cmd.exe /c whoami', 'childproc_name': 'cmd.exe'}
    candidates = list(carbon_black_commands(fields, 'attack/h1/cbc-edr/edr-h1-s4.jsonl', 1, budget, 'unknown', None))
    assert len(candidates) == 1 and candidates[0][2]
    with ProcessCommands() as processes:
        processes.add('same', Command('cmd.exe', ['/c', 'whoami'], 'creation'), True)
        processes.add('same', Command('cmd.exe', [], 'later', 'malicious'))
        commands = list(processes.commands())
    assert commands[0].args == ['/c', 'whoami']
    assert commands[0].label == 'malicious' and commands[0].group_id is None
    assert len(store(commands, tmp_path)) == 1


def test_optc_boot_identity_without_label_files(tmp_path):
    """A reboot separates a reused UUID even when no publisher labels are installed."""
    from _ingest_optc import records
    native = json.loads((FIXTURES / 'optc.json').read_text())[0]
    native.update(id='before', objectID='reused-guid', action='CREATE', hostname='host.example', timestamp='2019-09-23T10:00:00Z')
    native.pop('timestamp_ms', None)
    later = dict(native, id='after', timestamp='2019-09-23T12:00:00Z')
    reboot = {'object': 'HOST', 'action': 'START', 'hostname': 'HOST', 'timestamp': '2019-09-23T11:00:00Z'}
    directory = tmp_path / 'ecar/evaluation'
    directory.mkdir(parents=True)
    # The boot marker is in a different file from both process observations.
    for name, events in [('a', [later, native]), ('b', [reboot])]:
        with gzip.open(directory / f'{name}.json.gz', 'wt') as stream:
            for event in events:
                stream.write(json.dumps(event) + '\n')
    commands = list(records(tmp_path, SimpleNamespace(max_records=None, limit=None, sample_files=None)))
    assert {c.record_id for c in commands} == {'before:0', 'after:0'}
    assert len(store(commands, tmp_path)) == 2
