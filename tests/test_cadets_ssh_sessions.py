"""Exercise CADETS grouping through native Avro files and the ingestion CLI.

Network/disk failures require environmental faults and are not simulated.
The native fixture preserves CDM20 records at zero-based positions 89555,
89566, 89567, 89914, 89915, 89993, 149193, 149204, 149205, 149234,
149295, and 149514 in ta1-cadets-1-e5-official-2.bin.1.gz.
"""

import copy
import gzip
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import duckdb
import fastavro
import pytest
from test_ingest_tc_parallel import event, ingest, make_root, observation, write_avro


def accept(subject, program='sshd', **scope):
    """Describe an accepting process using CADETS' native exec property."""
    return observation('Event', f'accept-{subject}', type='EVENT_ACCEPT',
                       subject=subject, properties={'exec': program}, **scope)


def fork(parent, child, **scope):
    """Describe a parent-child relationship without any command text."""
    return observation('Event', f'fork-{parent}-{child}', type='EVENT_FORK',
                       subject=parent, predicateObject=child, **scope)


@pytest.mark.parametrize('workers', [1, 2])
def test_late_relationships_and_scopes(tmp_path, workers):
    """Children and descendants share groups after reading all selected files."""
    root = make_root(tmp_path, 'cadets')
    commands = []
    relations = []
    scopes = [{}, {'host': 'other'}, {'session': 1}]
    for scope in scopes:
        commands += [event(p, f'echo {p}', subject=p, **scope)
                     for p in ['A', 'S', 'B', 'C', 'D', 'E', 'N', 'F']]
        relations += [
            accept('S', **scope),
            observation('Subject', 'A', parentSubject='S', **scope),
            fork('S', 'A', **scope),  # Agreement is not a conflict.
            fork('S', 'B', **scope), fork('A', 'C', **scope),
            fork('B', 'D', **scope), fork('C', 'E', **scope),
            fork('C', 'N', **scope), accept('N', '/usr/sbin/sshd', **scope),
            fork('N', 'F', **scope),
        ]
    write_avro(root / 'data/a.bin', commands)
    write_avro(root / 'data/b.bin', relations)
    rows, _ = ingest(root, workers)
    expected = {'S': 'process:S', 'A': 'ssh-tree:A', 'B': 'ssh-tree:B',
                'C': 'ssh-tree:A', 'D': 'ssh-tree:B', 'E': 'ssh-tree:A',
                'N': 'process:N', 'F': 'ssh-tree:F'}
    assert len(rows) == len(commands)
    assert {(row[2][0], row[7]) for row in rows} == {
        (process, f'{root.name}:{scope.get("host", "host")}:{scope.get("session", 0)}:{suffix}')
        for scope in scopes for process, suffix in expected.items()
    }
    assert len({row[7] for row in rows}) == 15
    # Even a one-command preview must use later relationship records.
    (root / f'commands-{workers}.duckdb').unlink()
    limited, _ = ingest(root, workers, '--limit', '1')
    assert limited == [row for row in rows if row[2] == ['A'] and row[7] == f'{root.name}:host:0:ssh-tree:A']


@pytest.mark.parametrize('reverse', [False, True])
def test_incomplete_conflicting_and_cyclic_parents(tmp_path, reverse):
    """Unresolvable processes each keep their own ID, including descendants."""
    root = make_root(tmp_path, 'cadets')
    relations = [
        accept('S'), fork('S', 'good'),
        observation('Subject', 'good', parentSubject=''),
        fork('absent', 'missing'),
        observation('Subject', 'conflict', parentSubject='S'),
        fork('other', 'conflict'), fork('conflict', 'below-conflict'),
        observation('Subject', 'two-subjects', parentSubject='S'),
        observation('Subject', 'two-subjects', parentSubject='other'),
        fork('cycle2', 'cycle1'), fork('cycle1', 'cycle2'),
        fork('self', 'self'), fork('cycle1', 'below-cycle'),
        accept('http', 'httpd'), fork('http', 'http-child'),
        accept('unknown', ''), fork('unknown', 'unknown-child'),
        fork('no-accept', 'no-accept-child'),
        observation('Subject', 'no-accept', cmdLine='sshd'),
        fork('S', '', host='unused'), fork('', 'empty-parent'),
        accept(''),
        fork('S', 'wrong-host', host='other'),
        fork('S', 'wrong-run', session=1),
    ]
    processes = ['good', 'missing', 'conflict', 'below-conflict', 'two-subjects',
                 'cycle1', 'cycle2', 'self', 'below-cycle', 'http-child',
                 'unknown-child', 'no-accept-child', 'empty-parent',
                 'wrong-host', 'wrong-run', 'orphan']
    commands = [event(p, f'echo {p}', subject=p) for p in processes]
    write_avro(root / 'data/a.bin', commands + (relations[::-1] if reverse else relations))
    rows, _ = ingest(root, 1)
    assert len(rows) == len(processes) + 1
    for row in rows:
        process = row[2][0] if row[2] else 'no-accept'
        suffix = 'ssh-tree:good' if process == 'good' else f'process:{process}'
        assert row[7] == f'{root.name}:host:0:{suffix}'


def test_native_issue_example(tmp_path):
    """Use the original A/B executions and original S/A/B/C/D relationships."""
    root = make_root(tmp_path, 'cadets')
    with gzip.open(Path(__file__).parent / 'fixtures/cadets-ssh-tree.bin.gz', 'rb') as stream:
        reader = fastavro.reader(stream, return_record_name=True)
        native = list(reader)
        schema = reader.writer_schema
    processes = {
        'S': 'd3c8c194-70ca-11e9-b129-6c2b597e484c',
        'A': '7f7d8455-70ed-11e9-b129-6c2b597e484c',
        'B': 'dfbb0ab9-70ed-11e9-b129-6c2b597e484c',
        'C': '7f959a5b-70ed-11e9-b129-6c2b597e484c',
        'D': 'dfe1fe62-70ed-11e9-b129-6c2b597e484c',
    }
    # The excerpt has executions for A and B. Add explicit test commands for
    # S, C, D to observe their groups without changing the source relationships.
    commands = [row for row in native if row['datum'][1].get('type') == 'EVENT_EXECUTE']
    for index, name in enumerate(['S', 'C', 'D'], 1):
        row = copy.deepcopy(commands[0])
        row['datum'][1].update(uuid=uuid.UUID(int=index).bytes,
                               subject=('com.bbn.tc.schema.avro.cdm20.UUID', uuid.UUID(processes[name]).bytes))
        commands.append(row)
    for filename, records in [('a.bin', commands), ('b.bin', native)]:
        with (root / 'data' / filename).open('wb') as stream:
            fastavro.writer(stream, schema, records)
    rows, _ = ingest(root, 2)
    prefix = f'{root.name}:cb02303b-654e-11e9-a80c-6c2b597e484c:0:'
    assert len(rows) == 5
    sessions = {row[4].split(':')[2]: row[7] for row in rows}
    assert sessions['8ccbbe2a-d431-42a3-b8f1-da1d9fbb8a51'] == prefix + 'ssh-tree:' + processes['A']
    assert sessions['bf31c35f-f989-466b-a33c-42d11f16d490'] == prefix + 'ssh-tree:' + processes['B']
    for index, name in enumerate(['S', 'A', 'B'], 1):
        suffix = ('process:' if name == 'S' else 'ssh-tree:') + processes[name]
        assert sessions[str(uuid.UUID(int=index))] == prefix + suffix
    assert all(row[0:3] == ('/usr/sbin/sshd', 'sshd', ['-R']) for row in rows)


def test_native_commands_and_labels_unchanged(tmp_path):
    """Every column except session_id matches output captured before this fix."""
    root = make_root(tmp_path, 'cadets')
    fixtures = Path(__file__).parent / 'fixtures'
    shutil.copyfile(fixtures / 'cadets-ssh-tree.bin.gz', root / 'data/sample.bin.gz')
    rows, _ = ingest(root, 1)
    expected = json.loads((fixtures / 'cadets-ssh-tree-commands.json').read_text())
    assert [list(row[:7]) + list(row[8:]) for row in rows] == expected
    assert len({row[7] for row in rows}) == 2
    again, _ = ingest(root, 2)
    assert again == rows


def test_relationship_events_preserve_commands_without_event_ids(tmp_path):
    """Extra FORK/ACCEPT records leave command counts and fallback IDs intact."""
    root = make_root(tmp_path, 'cadets')
    commands = [event('', 'echo one', subject='A'),
                event('', 'echo two', subject='A'),
                event('no-process', 'echo orphan', subject='')]
    path = root / 'data/a.bin'
    write_avro(path, commands)
    before, _ = ingest(root, 1)
    # Even command-bearing FORK/ACCEPT records were excluded by the old
    # command filter. Their retention for ancestry must add no commands.
    relation = fork('S', 'A')
    relation['datum'][1]['properties'] = {'cmdLine': 'echo fork'}
    server = accept('S')
    server['datum'][1]['properties']['cmdLine'] = 'echo accept'
    write_avro(path, [server, commands[0], relation, *commands[1:]])
    after, _ = ingest(root, 2)
    assert len(after) == 3
    assert [row[:7] + row[8:] for row in before] == [row[:7] + row[8:] for row in after]
    assert {row[7] for row in after} == {f'{root.name}:host:0:ssh-tree:A',
                                        f'{root.name}:host:0:process:no-process'}


@pytest.mark.parametrize('workers', [1, 2])
def test_failed_scan_replays_commands_and_cleans_up(tmp_path, workers):
    """A later malformed container reports failure after committing valid rows."""
    root = make_root(tmp_path, 'cadets')
    write_avro(root / 'data/a.bin', [accept('S'), fork('S', 'A'),
                                    event('first', 'echo first', subject='A'),
                                    event('second', 'echo second', subject='A')])
    (root / 'data/b.bin').write_bytes(b'invalid Avro container')
    database = root / 'commands.duckdb'
    result = subprocess.run(
        [sys.executable, str(root / 'ingest'), '--db', str(database),
         '--tc-workers', str(workers), '--batch-size', '2'],
        capture_output=True, text=True, check=False, timeout=60,
    )
    assert result.returncode != 0
    assert 'Traceback' in result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT args,session_id FROM PROCESS_LAUNCHES ORDER BY args').fetchall() == [
            (['first'], f'{root.name}:host:0:ssh-tree:A'),
            (['second'], f'{root.name}:host:0:ssh-tree:A'),
        ]
        assert connection.execute('SELECT ingested FROM INGESTED').fetchall() == [(False,)]
    assert not list((root.parents[1] / 'tmp').glob('tc-ingest-*'))
