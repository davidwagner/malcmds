"""Native BOTS process-table regression through Arrow and DuckDB storage."""
from pathlib import Path

import duckdb

from _ingest import _initialize, _insert, command_table
from _ingest_bots import ps_commands


def test_native_ps_preserves_only_recoverable_arguments(tmp_path):
    """The publisher's AWK observation must never become invented arguments."""
    raw = (Path(__file__).parent / "fixtures/bots/ps-9928.txt").read_text()
    assert "RSZ_KB" in raw and "awk" in raw, "Publisher fixture lost the reported AWK case"
    commands = list(ps_commands(raw, "bucket303:9928", "bots:host:ps"))
    with duckdb.connect(str(tmp_path / "commands.duckdb")) as con:
        _initialize(con)
        _insert(con, command_table(commands, "splunk-bots"))
        rows = con.execute("SELECT pgm,args,shell_input,other_tokens FROM COMMANDS").fetchall()
    assert rows
    assert not any(pgm == "awk" for pgm, *_ in rows)
    assert all(len(args) <= 1 and shell is None and tokens == [] for _, args, shell, tokens in rows)
    assert any(args == [] for _, args, *_ in rows)


def test_ps_ambiguous_and_plain_arguments(tmp_path):
    """Document the collector information loss and preserve distinct process IDs."""
    header = "USER PID PSR pctCPU CPUTIME pctMEM RSZ_KB VSZ_KB TTY S ELAPSED COMMAND ARGS"
    arguments = ["a_b", "'quoted'", '"quoted"', "plain", "<noArgs>", "plain"]
    raw = header + "\n" + "\n".join(
        f"root {pid} 0 0 00:00 0 10 10 ? S 00:01 echo {arg}"
        for pid, arg in enumerate(arguments, 100)
    )
    commands = list(ps_commands(raw, "table", "bots:host:ps"))
    with duckdb.connect(str(tmp_path / "commands.duckdb")) as con:
        _initialize(con)
        _insert(con, command_table(commands, "splunk-bots"))
        rows = con.execute("SELECT args,session_id FROM COMMANDS ORDER BY record_id").fetchall()
    assert [args for args, _ in rows] == [["plain"], [], ["plain"]]
    assert len({session for _, session in rows}) == 3
