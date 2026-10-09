"""Real ingestion of published OpTC excerpts plus explicit PID-reuse cases.

The immutable fixtures are excerpts of AT03380/optc-labels at
64c9f9b2e1a15bf3c2789d89d93dc0724cb0d4fa (tasks/tasks.zip and
labels/malicious.zip) and the original-data Inria Sysclient0201 event export at
644f41fb0a955e471f34bed016fb2bfd9c74dc04. RPCSS startup comes from the original
20-23Sep19/AIA-201-225 eCAR stream. Synthetic lifetime cases are identified below.
"""

import copy
import gzip
import json
import zipfile
from pathlib import Path

import duckdb
import pytest
from test_ingest_optc_parallel import ingest, rows, write_stream

FIXTURES = Path(__file__).parent / 'fixtures' / 'optc'
COLUMNS = ['pgm', 'pgm_base', 'args', 'dataset', 'record_id', 'label', 'group_id', 'session_id', 'os']


def fixture(name):
    """Read an unchanged excerpt of the published release."""
    return json.loads((FIXTURES / name).read_text())


def install_labels(root, tasks, exported=(), inria=(), intervals=()):
    """Install release-format artifacts without network access or test doubles."""
    directory = root / 'labels' / 'reviewed'
    directory.mkdir(parents=True)
    with zipfile.ZipFile(directory / 'tasks.zip', 'w') as archive:
        archive.writestr('tasks.json', json.dumps(tasks))
    with zipfile.ZipFile(directory / 'malicious.zip', 'w') as archive:
        archive.writestr('malicious.json', ''.join(json.dumps(event) + '\n' for event in exported))
    directory = root / 'labels' / 'inria' / 'original'
    directory.mkdir(parents=True)
    with gzip.open(directory / 'ground_truth_sc1_evts_sysclient0201.json.gz', 'wt') as stream:
        stream.write(''.join(json.dumps(event) + '\n' for event in inria))
    (directory / 'ground_truth_sc1_new.csv').write_text(''.join(','.join(row) + '\n' for row in intervals))


def labels(database):
    """Read final labels while enforcing the existing persistent schema."""
    with duckdb.connect(str(database), read_only=True) as connection:
        assert [row[0] for row in connection.execute('DESCRIBE COMMANDS').fetchall()] == COLUMNS, (
            'OpTC labels must use existing COMMANDS columns; no evidence columns are needed')
        assert connection.execute('SHOW TABLES').fetchall() == [('COMMANDS',), ('INGESTED',)]
        return {record.removesuffix(':0'): (label, group) for record, label, group in
                connection.execute('SELECT record_id,label,group_id FROM COMMANDS').fetchall()}


def test_released_reviewed_and_inria_examples(tmp_path):
    """Real PowerShell, RPCSS, invalid and benign cases survive both worker modes."""
    tasks = fixture('reviewed-tasks.json')
    events = fixture('reviewed-events.json')
    exports = fixture('reviewed-export.json')
    startup = fixture('rpcss-startup.json')
    inria = fixture('inria-event.json')
    root = tmp_path / 'optc'
    # Deliberately conflicting broad intervals exercise reviewed precedence.
    intervals = [(event['hostname'], str(event['pid']), event['timestamp'], 'Infinity')
                 for event in (startup, events[-1])]
    install_labels(root, tasks, exports, [inria], intervals)
    write_stream(root / 'ecar' / 'evaluation' / 'a.json.gz', [json.dumps(e) for e in events])
    write_stream(root / 'ecar' / 'evaluation' / 'b.json.gz', [json.dumps(startup), json.dumps(inria)])
    results = []
    for workers in ('1', '2'):
        database = tmp_path / f'{workers}.duckdb'
        result = ingest(root, database, '--workers', workers)
        assert result.returncode == 0, result.stderr
        result_labels = labels(database)
        assert result_labels['43fb9623-3cd1-45ec-ab22-dbe46e75240e'] == ('malicious', None)
        assert result_labels[startup['id']] == ('benign', None), 'Event-only RPCSS evidence must leave its ordinary startup benign'
        assert '9bcea60a-d719-499e-aac1-710860b10ca1' not in result_labels, 'FLOW events do not create command executions'
        assert result_labels['99b4d49c-1c6b-4a6c-84d2-ce4e161cd21b'] == ('benign', None)
        assert result_labels[exports[0]['id']][0] != 'malicious', 'An invalid correlation must not regain its label through malicious.zip'
        assert result_labels[inria['id']] == ('malicious', None)
        results.append(rows(database))
    assert results[0] == results[1]


def synthetic_event(record, time, process, pid=5452, host='SysClient0201.systemia.com', action='CREATE'):
    """Copy a real execution to make explicit lifetime and identity edge cases."""
    event = copy.deepcopy(fixture('reviewed-events.json')[1])
    event.update(id=record, timestamp=time, objectID=process, actorID='ordinary-parent',
                 pid=pid, hostname=host, action=action, object='PROCESS')
    event['properties'] = {'command_line': 'cmd.exe /c whoami', 'image_path': 'cmd.exe'}
    return event


@pytest.mark.parametrize('workers', ['1', '2'])
def test_pid_reuse_reboot_and_process_roles(tmp_path, workers):
    """An open-ended interval cannot label a later PID incarnation or accessor."""
    root = tmp_path / 'optc'
    intervals = [('sysCLIENT0201', '5452', '2019-09-23T11:23:55-04:00', 'Infinity'),
                 ('SysClient0201', '42', '2019-09-23T11:23:55-04:00', 'Infinity')]
    install_labels(root, [], intervals=intervals)
    start = synthetic_event('first', '2019-09-23T11:23:55.857-04:00', 'first-process')
    reused = synthetic_event('reused', '2019-09-23T11:23:55.950-04:00', 'second-process')
    open_event = synthetic_event('open', '2019-09-23T11:23:55.900-04:00', 'unrelated-target', action='OPEN')
    open_event['actorID'] = start['objectID']
    before_reboot = synthetic_event('before', '2019-09-23T11:23:55.900-04:00', 'other-process', pid=42)
    reboot = {'object': 'HOST', 'action': 'START', 'hostname': 'sysclient0201', 'timestamp': '2019-09-23T11:24:00-04:00'}
    after_reboot = synthetic_event('after', '2019-09-23T11:24:01-04:00', 'other-process', pid=42, action='TERMINATE')
    after_reboot['actorID'] = after_reboot['objectID']
    other_host = synthetic_event('other-host', start['timestamp'], 'first-process', host='SysClient0202')
    # Reuse occurs in an earlier file to test independence from source ordering.
    write_stream(root / 'ecar' / 'evaluation' / 'a.json.gz', [json.dumps(reused), json.dumps(reboot)])
    write_stream(root / 'ecar' / 'evaluation' / 'b.json.gz',
                 [json.dumps(e) for e in (start, open_event, before_reboot, after_reboot, other_host)])
    database = tmp_path / 'commands.duckdb'
    result = ingest(root, database, '--workers', workers)
    assert result.returncode == 0, result.stderr
    result_labels = labels(database)
    assert result_labels['first'] == ('malicious', None)
    assert result_labels['before'] == ('malicious', None)
    assert result_labels['other-host'] == ('unknown', None)
    for record in ('reused', 'open', 'after'):
        assert result_labels[record][0] == 'malicious-group', f'{record} inherited a different execution\'s PID label'


def test_invalid_export_does_not_cancel_independent_positive(tmp_path):
    """A rejected association does not veto an independently reviewed execution."""
    root = tmp_path / 'optc'
    tasks = fixture('reviewed-tasks.json')
    exported = fixture('reviewed-export.json')
    independent = copy.deepcopy(tasks[-1])
    independent['labels'] = ['malicious', 'ground', 'process']
    tasks.append(independent)
    install_labels(root, tasks, exported)
    write_stream(root / 'ecar' / 'evaluation' / 'a.json.gz', [json.dumps(exported[0])])
    database = tmp_path / 'commands.duckdb'
    result = ingest(root, database)
    assert result.returncode == 0, result.stderr
    assert labels(database)[exported[0]['id']] == ('malicious', None)


def test_export_requires_reviewed_decisions(tmp_path):
    """A partial download must fail rather than silently restoring invalid labels."""
    root = tmp_path / 'optc'
    install_labels(root, [], fixture('reviewed-export.json'))
    (root / 'labels' / 'reviewed' / 'tasks.zip').unlink()
    write_stream(root / 'ecar' / 'evaluation' / 'a.json.gz', [json.dumps(fixture('inria-event.json'))])
    result = ingest(root, tmp_path / 'commands.duckdb')
    assert result.returncode != 0
    assert 'requires reviewed tasks.zip' in result.stderr


def test_export_process_propagation_and_unresolved_tasks(tmp_path):
    """Respect source granularity and leave incomplete reviewed tasks unresolved."""
    root = tmp_path / 'optc'
    tasks = fixture('reviewed-tasks.json')
    exported = fixture('valid-export.json')
    flow = fixture('reviewed-events.json')[2]
    invalid_event = copy.deepcopy(tasks[-1])
    invalid_event.update(labels=['invalid', 'event'], event_id='invalid-event-only')
    unlabeled = copy.deepcopy(tasks[0])
    unlabeled.update(labels=None, event_id='unlabeled-event', object_id='unlabeled-process')
    exact_only = copy.deepcopy(tasks[0])
    exact_only.update(labels=['malicious', 'correlated'], event_id='exact-only', object_id='exact-process', raw=[])
    event_only_launch = copy.deepcopy(exact_only)
    event_only_launch.update(labels=['malicious', 'event'], event_id='event-only-launch', object_id='event-only-process')
    tasks += [invalid_event, unlabeled, exact_only, event_only_launch]
    # Duplicate benign reviews must remain benign regardless of list order.
    tasks += [copy.deepcopy(tasks[2])]
    install_labels(root, tasks, [exported, flow], [flow],
                   [('sysclient0201', '88', '2019-09-23T11:00:00-04:00', '2019-09-23T13:00:00-04:00')])
    # Empty lines in both released archive encodings must not alter matching.
    directory = root / 'labels' / 'reviewed'
    with zipfile.ZipFile(directory / 'malicious.zip', 'w') as archive:
        archive.writestr('malicious.json', '\n' + json.dumps(exported) + '\n' + json.dumps(flow) + '\n\n')
    with gzip.open(root / 'labels/inria/original/ground_truth_sc1_evts_sysclient0201.json.gz', 'at') as stream:
        stream.write('\n')
    process = synthetic_event('process-match', '2019-09-23T12:00:00-04:00', tasks[0]['object_id'])
    process['hostname'] = 'sYsClIeNt0201'
    unknown = synthetic_event('unlabeled-event', process['timestamp'], 'unlabeled-process')
    exact = synthetic_event('exact-only', process['timestamp'], 'exact-process')
    event_launch = synthetic_event('event-only-launch', process['timestamp'], 'event-only-process')
    child = synthetic_event('ordinary-child', process['timestamp'], 'ordinary-child-process')
    child['actorID'] = tasks[0]['object_id']
    missing_time = synthetic_event('missing-time', None, 'missing-time-process', pid=88)
    after_start = synthetic_event('later-lifetime', '2019-09-23T12:00:00-04:00', 'reused-pid', pid=88)
    write_stream(root / 'ecar' / 'evaluation' / 'a.json.gz',
                 [json.dumps(e) for e in (exported, process, unknown, exact, event_launch, child, missing_time, after_start)])
    database = tmp_path / 'commands.duckdb'
    result = ingest(root, database)
    assert result.returncode == 0, result.stderr
    actual = labels(database)
    for record in (exported['id'], 'process-match', 'exact-only', 'event-only-launch'):
        assert actual[record] == ('malicious', None)
    assert actual['ordinary-child'][0] == 'malicious-group', 'CREATE must label the child, not its parent'
    assert actual['unlabeled-event'][0] == 'malicious-group'
    assert actual['later-lifetime'][0] == 'malicious-group'
    assert actual['missing-time'] == ('unknown', None)
    limited = tmp_path / 'limited.duckdb'
    result = ingest(root, limited, '--max-records', '1')
    assert result.returncode == 0, result.stderr
    assert labels(limited) == {exported['id']: ('malicious', None)}
