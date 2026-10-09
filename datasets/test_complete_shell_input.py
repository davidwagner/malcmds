"""Complete input is parsed statically through native archive readers and DuckDB."""

import gzip
import json
import zipfile
from pathlib import Path

import duckdb
from test_ingest_batches import invoke

FIXTURES = Path(__file__).parent / "fixtures"


def test_native_iot_heredoc_and_later_commands(tmp_path):
    """Publisher uudecode fragments produce no body or delimiter program rows."""
    row = json.loads((FIXTURES / "iot-heredoc.json").read_text())
    with zipfile.ZipFile(tmp_path / "Microsoft.IoT-Dump-pwd-infected.zip", "w") as archive:
        archive.writestr("Microsoft.IoT-Dump1.json", json.dumps([row]))
    database = tmp_path / "commands.duckdb"
    result = invoke(tmp_path, database, "from _ingest_misc import microsoft_iot as records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT pgm,args,shell_input,other_tokens,record_id FROM COMMANDS").fetchall()
    assert not any(pgm in {"~", "end", "begin"} for pgm, *_ in rows), "Here-document contents are input data, never executions"
    decoded = [r for r in rows if r[0] == "uudecode"]
    assert decoded and all("\n" in r[2] and "<<" in r[2] for r in decoded)
    assert all(r[2] is not None for r in rows)
    assert any(r[0].endswith("busybox") for r in rows)


def test_native_cyberlab_python_is_not_bash(tmp_path):
    """A rejected recorded construct does not discard later independent input."""
    source = json.loads((FIXTURES / "cyberlab-python.json").read_text())
    events = next(iter(source.values()))
    events.insert(0, {"eventid": "cowrie.command.input", "input": "echo before"})
    events.append({"eventid": "cowrie.command.input", "input": "echo after"})
    (tmp_path / "events.json.gz").write_bytes(gzip.compress(json.dumps([source]).encode()))
    database = tmp_path / "commands.duckdb"
    result = invoke(tmp_path, database, "from _ingest_misc import cyberlab as records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT pgm,args FROM COMMANDS ORDER BY rowid").fetchall() == [("echo", ["before"]), ("echo", ["after"])]


def test_fragments_substitutions_exec_and_multiple_documents(tmp_path):
    """Bash checks never execute substitutions; unresolved names create no row."""
    sentinel = tmp_path / "must-not-exist"
    parts = ["echo before", "print_('hello')", "$(exec 1>&-)", "exec /bin/id",
             "'$(name)'", r"\$\(name\)", 'echo "multi', 'line"',
             "cat <<A <<-'B'", "first body", "A", "\tsecond body", "\tB",
             f"echo $(touch {sentinel})", 'exec "$target"', "echo after",
             'echo $((1 << 2))', '(( value <<= 1 )); echo final',
             'echo foo\\', 'bar', 'echo $(echo', 'inner)',
             "cat <<NEVER", "unclosed body"]
    source = f'''
from _ingest import shell_command_fragments
def records(root, options):
    for occurrence, (index, text, program, args, other) in enumerate(shell_command_fragments({parts!r})):
        yield Command(program, args, f"{{index}}:{{occurrence}}", shell_input=text, other_tokens=other)
'''
    database = tmp_path / "commands.duckdb"
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    assert not sentinel.exists(), "Syntax validation must never evaluate the recorded shell input"
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT pgm,args,shell_input,other_tokens FROM COMMANDS ORDER BY rowid").fetchall()
    assert [r[0] for r in rows] == ["echo", "/bin/id", "$(name)", "$(name)", "echo", "cat", "echo", "touch", "echo", "echo", "echo", "echo", "echo", "echo", "inner"]
    assert rows[-4][1] == ["foobar"]
    assert rows[-1][1] == []
    assert rows[4][1] == ["multi\nline"]
    assert rows[5][1] == []
    assert rows[5][3] == ["<<", "A", "<<-", "'B'", "first body\n", "A", "\tsecond body\n", "\tB"]
