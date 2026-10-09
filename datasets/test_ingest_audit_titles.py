"""Interpreted audit command titles through the shared reader and DuckDB."""
import re
from pathlib import Path

import duckdb

from _ingest import Command, _initialize, _insert, command_table
from _ingest_misc import audit_events


def test_native_interpreted_titles_with_execution_companions(tmp_path):
    """Native title text is recoverable only when an execution companion exists."""
    titles = (Path(__file__).parent / 'fixtures/executions/interpreted-titles.log').read_text().splitlines()
    assert list(audit_events(titles)) == [], 'Standalone process titles are not execution evidence'
    lines = []
    for title in titles:
        event = re.search(r'msg=audit\(([^)]+)\)', title)[1]
        lines.extend([f'type=SYSCALL msg=audit({event}): arch=x86_64 syscall=execve success=yes', title])
    events = list(audit_events(lines))
    commands = [Command(argv[0], argv[1:], event) for event, _, argv, _, _ in events]
    with duckdb.connect(str(tmp_path / 'titles.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(commands, 'splunkad'))
        rows = con.execute('SELECT pgm,args FROM COMMANDS').fetchall()
    assert ('sudo', ['systemctl', 'status', 'auditd.service']) in rows


def test_raw_titles_and_execve_precedence(tmp_path):
    """Raw hex remains decoded while a complete EXECVE vector wins over a title."""
    lines = [
        'type=SYSCALL msg=audit(1:1): arch=c000003e syscall=59',
        'type=PROCTITLE msg=audit(1:1): proctitle=6464006f663d7800',
        'type=SYSCALL msg=audit(02/20/2025 10:00:00.000:2): syscall=execve',
        'type=PROCTITLE msg=audit(02/20/2025 10:00:00.000:2): proctitle=dd',
        'type=SYSCALL msg=audit(02/20/2025 10:00:01.000:3): syscall=execve',
        'type=PROCTITLE msg=audit(02/20/2025 10:00:01.000:3): proctitle=dd of=random_data.bin if=/dev/zero',
        'type=EXECVE msg=audit(2:3): argc=2 a0="echo" a1=612062',
        'type=PROCTITLE msg=audit(2:3): proctitle=7375646f00',
    ]
    events = list(audit_events(lines))
    commands = [Command(argv[0], argv[1:], event) for event, _, argv, _, _ in events]
    with duckdb.connect(str(tmp_path / 'raw.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(commands, 'splunkad'))
        assert con.execute('SELECT pgm,args FROM COMMANDS ORDER BY record_id').fetchall() == [('dd', []), ('dd', ['of=random_data.bin', 'if=/dev/zero']), ('dd', ['of=x']), ('echo', ['a b'])]
