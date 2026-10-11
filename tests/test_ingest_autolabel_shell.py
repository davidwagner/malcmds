"""Protect flat Sysdig shell reconstruction through nested archives and DuckDB.

Published fixtures were extracted for issue #90 from CVE-2018-17246.tar and
sandworm.tar, each in dataset-17.tar.gz. _source and _run record their provenance.
All commands are inert data; ingestion never executes the recorded payloads.
"""

import io
import json
import tarfile
from pathlib import Path

import duckdb
from test_ingest_batches import invoke

FIXTURES = Path(__file__).parent / 'fixtures' / 'issue90'
READER = 'from _ingest_autolabel import records\n'


def _archive(root, scenario, events):
    payload = '\n'.join(json.dumps(event) for event in events).encode()
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode='w:gz') as archive:
        member = tarfile.TarInfo('sysdig/events.log')
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    with tarfile.open(root / f'{scenario}.tar', 'w') as archive:
        member = tarfile.TarInfo(f'{scenario}/dataset-17.tar.gz')
        member.size = len(inner.getvalue())
        archive.addfile(member, io.BytesIO(inner.getvalue()))


def test_published_shell_commands_keep_payload_and_labels(tmp_path):
    """Source quotes/operators and child argv survive parser dependency updates."""
    root = tmp_path / 'autolabel'
    root.mkdir()
    expected = []
    arguments = {
        338079: ['-c', "/bin/bash -c 'sleep 5' || exit 1"],
        338132: ['-c', 'sleep 5'],
        338392: ['5'],
        9985980: ['-c', 'uname -a'],
        9987518: ['-a'],
        10784973: ['-c', "echo '/var/www/html/centreon_module_linux_app64 &' >> /var/www/html/include/tools/check.sh"],
    }
    for scenario, filename in [('CVE-2018-17246', 'cve-shell.json'), ('sandworm', 'sandworm-shell.json')]:
        events = json.loads((FIXTURES / filename).read_text())
        _archive(root, scenario, events + events)
        for event in events:
            if event['evt.type'] != 'execve':
                continue
            identity = f"{scenario}.tar/{scenario}/dataset-17.tar.gz:{event['container.id']}:{event['evt.num']}"
            expected.append((identity, event['proc.exepath'], arguments[event['evt.num']],
                             'malicious' if event['malicious'] else 'benign', None, []))
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        actual = con.execute('SELECT record_id,pgm,args,label,shell_input,other_tokens FROM COMMANDS ORDER BY record_id').fetchall()
        assert actual == sorted(expected), 'Flat Sysdig shell payloads must remain one argument with original quotes and labels'
        assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(True,)]


def test_flat_heuristic_and_unsupported_forms(tmp_path):
    """Explicit separators win; unsupported flat forms remain approximate.

    sh -c echo hello could mean argv=['sh', '-c', 'echo hello'] or
    ['sh', '-c', 'echo', 'hello']; this heuristic deliberately chooses the former.
    It cannot prove which argv was originally executed.
    """
    cases = [
        ('sh -c echo hello', '/bin/sh', ['-c', 'echo hello']),
        ('/bin/dash\t-c\tprintf  "a b"\\n\nnext  ', '/bin/dash', ['-c', 'printf  "a b"\\n\nnext  ']),
        ('bash -c "literal quotes"', '/bin/bash', ['-c', '"literal quotes"']),
        ('bash -c echo \'unterminated', '/bin/bash', ['-c', "echo 'unterminated"]),
        ('sh -c A#t#k#F#1#echo hello', '/bin/bash', ['-c', 'echo hello']),
        ('python -c print(1)', '/bin/python', ['-c', 'print(1)']),
        ('python -c echo hello', '/bin/bash', ['-c', 'echo', 'hello']),
        ('sh -c echo hello', '/bin/python', ['-c', 'echo', 'hello']),
        ('sh -lc echo hello', '/bin/sh', ['-lc', 'echo', 'hello']),
        ('sh -e -c echo hello', '/bin/sh', ['-e', '-c', 'echo', 'hello']),
        ('sh -- -c echo hello', '/bin/sh', ['--', '-c', 'echo', 'hello']),
        ('sh -c', '/bin/sh', ['-c']),
        ('sh -c   ', '/bin/sh', ['-c']),
        ('"sh" -c echo hello', '/bin/sh', ['-c', 'echo', 'hello']),
        ('sh\0-c\0echo hello\0real-zero\0', '/bin/sh', ['-c', 'echo hello', 'real-zero']),
        ('sh -c echo\0hello\0', '/bin/sh', ['hello']),
        ('', '/bin/sh', []),
        ('sh -c echo hello', None, ['-c', 'echo', 'hello']),
    ]
    events = []
    expected = []
    for index, (text, pgm, args) in enumerate(cases):
        events.append({'evt.type': 'execve', 'evt.num': index, 'evt.rawres': 0,
                       'proc.cmdline': text, 'proc.exepath': pgm, 'malicious': False})
        expected.append((f'cases.tar/cases/dataset-17.tar.gz:host:{index}', pgm or 'sh', args))
    # Failed attempts have a separate source representation, including real argv.
    for arguments, args in [(['/bin/sh', '-c', 'echo hello', 'real-zero'], ['-c', 'echo hello', 'real-zero']),
                            ('-c "echo hello" real-zero', ['-c', 'echo hello', 'real-zero']),
                            (None, ['-c', 'echo', 'hello'])]:
        index = len(events)
        events.append({'evt.type': 'execve', 'evt.num': index, 'evt.rawres': -2,
                       'proc.cmdline': 'sh -c echo hello', 'proc.exepath': '/bin/sh',
                       'evt.arg.filename': '/bin/sh' if arguments else None,
                       'evt.arg.argv': arguments, 'malicious': False})
        expected.append((f'cases.tar/cases/dataset-17.tar.gz:host:{index}', '/bin/sh', args))
    root = tmp_path / 'autolabel'
    root.mkdir()
    _archive(root, 'cases', events)
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT record_id,pgm,args FROM COMMANDS ORDER BY record_id').fetchall() == sorted(expected)
