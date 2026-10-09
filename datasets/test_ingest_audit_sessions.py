"""Boot and process-lifetime session reconstruction through stored commands."""
from pathlib import Path

import duckdb

from _ingest import Command, _initialize, _insert, command_table
from _ingest_misc import audit_events


def stored_sessions(lines, tmp_path, state=None):
    """Store actual audit-reader output and return its event/session mapping."""
    events = list(audit_events(lines, state=state, scope='collection'))
    commands = [Command(argv[0], argv[1:], eid, session_id=fields['_session']) for eid, fields, argv, _, _ in events]
    with duckdb.connect(str(tmp_path / 'sessions.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(commands, 'test'))
        return dict(con.execute('SELECT record_id,session_id FROM COMMANDS').fetchall())


def test_process_lifetimes_parent_inheritance_boot_and_rotation(tmp_path):
    """Different PID-1 children and recycled PIDs cannot share inferred sessions."""
    state = {}
    first = [
        'node=h type=EXECVE msg=audit(1:1): pid=10 ppid=1 argc=1 a0="one"',
        'node=h type=EXECVE msg=audit(1:2): pid=11 ppid=1 argc=1 a0="two"',
        'node=h type=EXECVE msg=audit(1:3): pid=20 ses=7 argc=1 a0="login"',
        'node=h type=SYSCALL msg=audit(1:4): pid=20 syscall=fork exit=21',
        'node=h type=EXECVE msg=audit(1:5): pid=21 ppid=20 argc=1 a0="child"',
        'node=h type=DAEMON_START msg=audit(1:6): pid=999',
        'node=h type=EXECVE msg=audit(1:7): pid=20 ses=7 argc=1 a0="same-login"',
        'node=h type=SYSCALL msg=audit(1:8): pid=10 arch=c000003e syscall=60',
        'node=h type=EXECVE msg=audit(1:9): pid=10 ppid=1 argc=1 a0="reused"',
        'node=h type=EXECVE msg=audit(1:10): argc=1 a0="no-pid"',
        'node=h type=EXECVE msg=audit(1:11): argc=1 a0="no-pid"',
    ]
    sessions = stored_sessions(first, tmp_path, state)
    assert sessions['1:1'] != sessions['1:2'] != sessions['1:9']
    assert sessions['1:1'] != sessions['1:9']
    assert sessions['1:3'] == sessions['1:5'] == sessions['1:7']
    assert sessions['1:10'] != sessions['1:11']
    second = [
        'node=h type=EXECVE msg=audit(86401:1): pid=20 ses=7 argc=1 a0="next-day"',
        'node=other type=EXECVE msg=audit(86401:2): pid=20 ses=7 argc=1 a0="other-host"',
        'node=h type=SYSTEM_BOOT msg=audit(86401:3):',
        'node=h type=EXECVE msg=audit(86401:4): pid=20 ses=7 argc=1 a0="new-boot"',
    ]
    sessions = stored_sessions(second, tmp_path, state)
    assert sessions['1:3'] == sessions['86401:1']
    assert len({sessions['86401:1'], sessions['86401:2'], sessions['86401:4']}) == 3


def test_native_aviator_boot_marker(tmp_path):
    """The published Sandworm boot separates reused session seven."""
    original = (Path(__file__).parent / 'fixtures/executions/audit-boot.log').read_text()
    assert list(audit_events(original.splitlines())) == [], 'LOGIN/write observations are not executions'
    raw = (Path(__file__).parent / 'fixtures/executions/audit-boot-execs.log').read_text()
    sessions = stored_sessions(raw.splitlines(), tmp_path)
    before = sessions['1718909190.235:621875']
    after = sessions['1718913978.200:130322']
    assert before != after
    assert ':session:7' in before and ':session:7' in after


def test_boot_only_rotated_member_updates_shared_parser_state(tmp_path):
    """A native boot record in its own rotation still separates session seven."""
    import io
    from types import SimpleNamespace
    from _ingest_windows import Budget, parse_log

    lines = (Path(__file__).parent / 'fixtures/executions/audit-boot-execs.log').read_text().splitlines(keepends=True)
    boot = next(index for index, line in enumerate(lines) if line.startswith('type=SYSTEM_BOOT '))
    pieces = [lines[:boot], [lines[boot]], lines[boot + 1:]]
    budget = Budget(SimpleNamespace(max_records=None))
    commands = []
    for index, piece in enumerate(pieces):
        commands.extend(parse_log(io.BytesIO(''.join(piece).encode()), f'source/run/audit.log.{2-index}', 'splunkad', budget))
    with duckdb.connect(str(tmp_path / 'rotations.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(commands, 'splunkad'))
        count, sessions = con.execute('SELECT count(*),count(DISTINCT session_id) FROM COMMANDS').fetchone()
    assert count == 2, 'A lifecycle-only file must never become a command row'
    assert sessions == 2, 'Audit format detection must recognize a boot-only rotation'
