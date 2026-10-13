"""Store published Microsoft compound examples through the LADE ingestion path."""

import duckdb
from test_ingest_lade_formats import _ground, _release
from test_ingest_performance import ingest


def test_documented_cmd_compounds(tmp_path):
    """Control syntax groups inputs while each body invocation gets its own row."""
    # WindowsServerDocs/administration/windows-commands/{for,if}.md at
    # 312d2998c621f384c4e404fe63c7c1c4cbaf61a0.
    examples = [
        ('for %f in (*.doc *.txt) do type %f', [('type', ['%f'])]),
        ('for /f "usebackq delims==" %i in (`set`) do @echo %i',
         [('set', []), ('echo', ['%i'])]),
        ('for /d %D in ("C:\\Users\\*") do @echo %~nxD', [('echo', ['%~nxD'])]),
        ('for /l %N in (1,2,9) do @echo %N', [('echo', ['%N'])]),
        ('if not exist product.dat echo Cannot find data file',
         [('echo', ['Cannot', 'find', 'data', 'file'])]),
        ('IF EXIST Product.dat (\ndel Product.dat\n) ELSE (\necho The Product.dat file is missing.\n)',
         [('del', ['Product.dat']), ('echo', ['The', 'Product.dat', 'file', 'is', 'missing.'])]),
        ('if %errorlevel% LEQ 1 goto okay', [('goto', ['okay'])]),
        ((':begin\n@echo off\nformat a: /s\nif not errorlevel 1 goto end\n'
         'echo An error occurred during formatting.\n:end\necho End of batch program.'),
         [('echo', ['off']), ('format', ['a:', '/s']), ('goto', ['end']),
          ('echo', ['An', 'error', 'occurred', 'during', 'formatting.']),
          ('echo', ['End', 'of', 'batch', 'program.'])]),
    ]
    text = ''.join(_ground(code, 'platform.windows.cmd.command') for code, _ in examples)
    _release(tmp_path, [('Caldera-derived/APT_labeled_sequences/GroundTruth/cmd.txt', text)])
    database = tmp_path / 'commands.duckdb'
    result = ingest(tmp_path, database, 'from _ingest_lade import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT shell_input FROM SHELL_INPUTS ORDER BY rowid').fetchall() == [
            (code,) for code, _ in examples]
        assert con.execute('SELECT pgm,args FROM PROCESS_LAUNCHES ORDER BY rowid').fetchall() == [
            invocation for _, invocations in examples for invocation in invocations]
        assert con.execute("SELECT DISTINCT dataset_label,group_id,os FROM PROCESS_LAUNCHES").fetchall() == [
            ('benign', None, 'windows')]


def test_cmd_nested_and_continued_submissions(tmp_path):
    """Nested bodies and escaped physical lines retain their complete input."""
    code = (
        '((echo nested)) & if /i "yes"=="YES" (echo equal)\n'
        'if defined PATH echo ready\n'
        'if "a"== "a" echo equal-left\n'
        'if "a" =="a" echo equal-right\n'
        "for /f %i in ('echo foo(bar)') do echo %i\n"
        'for /f %i in (\'echo one ^| findstr one\') do (echo %i & type result.txt)\n'
        'echo continued ^\r\nnext > output.txt 2>&1\n'
        'echo joined^\nword\n'
        'for /f "usebackq" %i in ("records.txt") do echo %i\n'
        'echo %ProgramFiles(x86)%\n'
        'typeperf \\Processor(_Total)\\% Processor Time\n'
        'icacls "myDirectory" /setintegritylevel (CI)(OI)H\n'
        '>empty.txt\n'
        'if'
    )
    _release(tmp_path, [('Caldera-derived/APT_labeled_sequences/GroundTruth/cmd.txt',
                         _ground(code, 'platform.windows.cmd.command'))])
    database = tmp_path / 'commands.duckdb'
    result = ingest(tmp_path, database, 'from _ingest_lade import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT pgm,args FROM PROCESS_LAUNCHES ORDER BY rowid').fetchall() == [
            ('echo', ['nested']), ('echo', ['equal']), ('echo', ['ready']),
            ('echo', ['equal-left']), ('echo', ['equal-right']), ('echo', ['foo(bar)']), ('echo', ['%i']),
            ('echo', ['one']), ('findstr', ['one']), ('echo', ['%i']), ('type', ['result.txt']),
            ('echo', ['continued', 'next']), ('echo', ['joinedword']), ('echo', ['%i']),
            ('echo', ['%ProgramFiles(x86)%']),
            ('typeperf', [r'\Processor(_Total)\%', 'Processor', 'Time']),
            ('icacls', ['myDirectory', '/setintegritylevel', '(CI)(OI)H']),
        ]
        assert con.execute('SELECT shell_input FROM SHELL_INPUTS').fetchone() == (code,)


def test_incomplete_cmd_control_input_is_retained(tmp_path):
    """A partial control header is stored without inventing a program invocation."""
    code = 'for /f %i in ('
    _release(tmp_path, [('Caldera-derived/APT_labeled_sequences/GroundTruth/cmd.txt',
                         _ground(code, 'platform.windows.cmd.command'))])
    database = tmp_path / 'commands.duckdb'
    result = ingest(tmp_path, database, 'from _ingest_lade import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT shell_input,pgms FROM SHELL_INPUTS').fetchall() == [(code, [])]
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (0,)
