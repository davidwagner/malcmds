"""Exercise LADE syntax and source selection through its real parser and writer.

PowerShell worker crashes and closed-pipe failures require external process
fault injection. These tests do not replace that process or simulate its output.
They verify partial input with the actual PowerShell AST parser instead.
"""

import io
import json
import os
import shutil
import tarfile
from pathlib import Path

import duckdb
import pytest
from test_ingest_performance import ingest

HERE = Path(__file__).parent


@pytest.fixture(scope='module', autouse=True)
def _real_powershell():
    executable = os.environ.get('LADE_PWSH') or shutil.which('pwsh')
    assert executable and Path(executable).is_file(), 'Set LADE_PWSH to the fetched PowerShell 7.6.6 executable for the real parser tests'


def _member(archive, name, text):
    payload = text.encode()
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))


def _ground(code, platform, truth='BENIGN'):
    information = f'- GROUND-TRUTH: {truth}\n'
    if platform is not None:
        information += f'- PLATFORM: {platform}\n'
    return (f'[ Code-snippet ]:\n{code}\n\n[ Resolved Code ]:\n'
            'Write-Output "duplicate resolved representation"\n\n'
            '[ GROUND-TRUTH & ALL INFORMATION ]:\n' + information
            + '---------------------------------------------------\n')


def _release(root, sequences, annotations=()):
    with tarfile.open(root / 'lade.tar.gz', 'w:gz') as archive:
        for name, text in sequences:
            _member(archive, 'LADE/' + name, text)
    with tarfile.open(root / 'aviator-ground-truth-and-tools.tar.gz', 'w:gz') as archive:
        for name, text in annotations:
            _member(archive, 'aviator/ground_truth/' + name, text)


def test_lade_cmd_quotes_caret_comments_and_redirections(tmp_path):
    """cmd punctuation remains literal when escaped and redirects leave argv."""
    code = ('echo "quoted & value" ^& ^| ^< ^> ^^ && rem ignored\n'
            ':: ignored too\n"" ignored\n'
            'type < input.txt > out.txt 2>&1 || whoami | findstr user')
    _release(tmp_path, [('Caldera-derived/APT_labeled_sequences/GroundTruth/cmd.txt',
                         _ground(code, 'platform.windows.cmd.command'))])
    database = tmp_path / 'commands.duckdb'
    result = ingest(tmp_path, database, 'from _ingest_lade import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT pgm,args FROM COMMANDS ORDER BY rowid').fetchall() == [
            ('echo', ['quoted & value', '&', '|', '<', '>', '^']),
            ('type', []), ('whoami', []), ('findstr', ['user']),
        ], 'cmd quoting and caret escaping must not create extra commands or arguments'
        omitted = con.execute("SELECT other_tokens FROM COMMANDS WHERE pgm='type'").fetchone()[0]
        assert all(token in omitted for token in ['<', 'input.txt', '>', 'out.txt', '2>&1'])
        assert con.execute('SELECT DISTINCT shell_input,label,os FROM COMMANDS').fetchall() == [(code, 'benign', 'windows')]


def test_lade_linux_direct_process_and_partial_powershell(tmp_path):
    """Declared syntax controls parsing while process records omit shell text."""
    snippets = [
        ("printf '%s\\n' hello | cat > out.txt", 'platform.linux.sh.command'),
        ('/usr/bin/id -u', 'platform.linux.proc.command'),
        ('"C:\\Program Files\\viewer.exe" --literal "a|b"', 'platform.windows.proc.command'),
        ('Get-Process -Name "notepad"', None),
        ("if ($true) { Get-Item -LiteralPath 'C:\\Missing';", 'platform.windows.psh.command'),
        ("$x='text'; Write-Output $x", 'platform.windows.cmd.command'),
    ]
    text = ''.join(_ground(code, platform) for code, platform in snippets)
    _release(tmp_path, [('Caldera-derived/APT_labeled_sequences/GroundTruth/mixed.txt', text)])
    database = tmp_path / 'commands.duckdb'
    result = ingest(tmp_path, database, 'from _ingest_lade import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute('SELECT pgm,args,os,shell_input,other_tokens FROM COMMANDS ORDER BY rowid').fetchall()
        assert [row[0] for row in rows] == ['printf', 'cat', '/usr/bin/id', r'C:\Program Files\viewer.exe', 'Get-Process', 'Get-Item', 'Write-Output']
        assert rows[0][1] == [r'%s\n', 'hello']
        assert rows[0][2] == rows[1][2] == rows[2][2] == 'linux'
        assert rows[2][1:] == (['-u'], 'linux', None, [])
        assert rows[3][1:] == (['--literal', 'a|b'], 'windows', None, [])
        assert rows[4][1] == ['-Name', 'notepad']
        assert rows[5][1] == ['-LiteralPath', r'C:\Missing'], 'A valid command inside a partial script must survive AST parsing'
        assert rows[6][1] == ['$x'], 'Static parsing must not evaluate variables'
        assert all(row[3] == snippets[index][0] for index, row in [(3, rows[4]), (4, rows[5]), (5, rows[6])])


def test_lade_sequence_scenario_annotations_and_benign_processes(tmp_path):
    """Exact scenario matches improve attack labels without labeling benign copies."""
    plan = ('# scenario start\n# attack step\nInvoke-Persistence -PersistStep 2\n'
            'echo "controller message"\nwhoami\n\n# scenario end\n')
    sequences = [
        ('AVIATOR/APT_labeled_sequences/Processed_APT29__scenario2.txt',
         'Invoke-Persistence -PersistStep 2\nInvoke-Persistence -PersistStep 1\n"C:\\Program Files\\Mozilla Firefox\\firefox.exe"\n'),
        ('Caldera-derived/Benign_labeled_sequences/day.txt',
         '"ordinary data string"\nGet-Date\nnotepad.exe\n'),
        ('Caldera-derived/APT_labeled_sequences/Processed/duplicate.txt',
         'Write-Output "excluded alternate representation"'),
    ]
    _release(tmp_path, sequences, [('apt29/scenario2.sh', plan), ('apt29/README.txt', 'Invoke-Persistence -PersistStep 1')])
    database = tmp_path / 'commands.duckdb'
    result = ingest(tmp_path, database, 'from _ingest_lade import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute('SELECT pgm,args,label,group_id,shell_input,other_tokens FROM COMMANDS ORDER BY rowid').fetchall()
        assert [row[0] for row in rows] == ['Invoke-Persistence', 'Invoke-Persistence', r'C:\Program Files\Mozilla Firefox\firefox.exe', 'Get-Date', 'notepad.exe']
        assert rows[0][2:4] == ('malicious', None)
        assert rows[1][2] == 'malicious-group' and rows[1][3].endswith('Processed_APT29__scenario2.txt')
        assert all(row[2] == 'benign' for row in rows[2:])
        assert all(row[4:] == (None, []) for row in rows), 'Expanded scripts and process telemetry are not submitted shell input'


def test_lade_bounded_and_sampled_reads_remain_incomplete(tmp_path):
    """Inspection limits do not mark omitted sequences as already imported."""
    text = _ground('whoami /user', 'platform.windows.cmd.command') + _ground('hostname', 'platform.windows.cmd.command')
    _release(tmp_path, [(f'Caldera-derived/APT_labeled_sequences/GroundTruth/{name}.txt', text) for name in ['one', 'two']])
    database = tmp_path / 'commands.duckdb'
    result = ingest(tmp_path, database, 'from _ingest_lade import records\n', '--sample-files', '1', '--max-records', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (1,)
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
    result = ingest(tmp_path, database, 'from _ingest_lade import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (4,)
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (True,)


def test_lade_standalone_static_parser_and_trailing_cmd_separator(tmp_path):
    """The public snippet adapter starts its actual parser when none is supplied."""
    marker = tmp_path / 'must-not-exist'
    snippets = [
        [f'Set-Content -LiteralPath "{marker}" -Value "never run"', 'unknown'],
        ['echo done &\n', 'platform.windows.cmd.command'],
    ]
    (tmp_path / 'snippets.json').write_text(json.dumps(snippets))
    reader = '''
import json
from _ingest_lade import snippet_commands

def records(root, options):
    """Persist static adapter results without executing any snippet."""
    for index, (text, platform) in enumerate(json.loads((root / 'snippets.json').read_text())):
        for program, args, other in snippet_commands(text, platform):
            yield Command(program, args, str(index), shell_input=text, other_tokens=other, os='windows')
'''
    database = tmp_path / 'commands.duckdb'
    result = ingest(tmp_path, database, reader)
    assert result.returncode == 0, result.stderr
    assert not marker.exists(), 'Static PowerShell parsing executed source text'
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT pgm,args FROM COMMANDS ORDER BY rowid').fetchall() == [
            ('Set-Content', ['-LiteralPath', str(marker), '-Value', 'never run']), ('echo', ['done']),
        ]


def test_lade_unknown_platform_infers_unix_from_executable(tmp_path):
    """Missing platform metadata should not turn an absolute Unix command into Windows."""
    code = '/usr/bin/id -u'
    text = _ground(code, None) + _ground('/usr/bin/id -g', 'unknown.proc.command')
    _release(tmp_path, [('Caldera-derived/APT_labeled_sequences/GroundTruth/unknown.txt', text)])
    database = tmp_path / 'commands.duckdb'
    result = ingest(tmp_path, database, 'from _ingest_lade import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT pgm,args,os,shell_input FROM COMMANDS ORDER BY rowid').fetchall() == [
            ('/usr/bin/id', ['-u'], 'linux', code), ('/usr/bin/id', ['-g'], 'linux', None),
        ]


def test_lade_fetched_runtime_installs_and_reuses_without_path_tool(tmp_path):
    """The fetched portable runtime must work on a system without pwsh on PATH."""
    runtime = HERE / 'lade' / 'powershell-7.6.6-linux-x64.tar.gz'
    assert runtime.exists(), 'Run datasets/lade/fetch to test its pinned portable runtime'
    root = tmp_path / 'isolated' / 'lade'
    root.mkdir(parents=True)
    (root / runtime.name).symlink_to(runtime)
    _release(root, [('Caldera-derived/Benign_labeled_sequences/check.txt', 'Get-Date\n')])
    # Configure a real child environment without a preinstalled parser. This
    # exercises the actual publisher runtime archive rather than substituting a tool.
    reader = '''
import os
os.environ.pop('LADE_PWSH', None)
os.environ['PATH'] = ''
from _ingest_lade import records
'''
    for name in ['installed', 'reused']:
        database = tmp_path / f'{name}.duckdb'
        result = ingest(root, database, reader)
        assert result.returncode == 0, result.stderr
        with duckdb.connect(str(database)) as con:
            assert con.execute('SELECT pgm,label FROM COMMANDS').fetchall() == [('Get-Date', 'benign')]
