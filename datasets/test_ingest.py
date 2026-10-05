"""End-to-end normalization/database tests with real subprocesses and native DuckDB."""

import json
import subprocess
import sys
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parent


def test_command_ingestion(tmp_path):
    """Exercise shell parsing, native argv, Windows quoting, enums and deduplication."""
    driver = tmp_path / "ingest.py"
    driver.write_text(
        """
import sys
from pathlib import Path
sys.path.insert(0, ROOT_PATH)
from _ingest import Command, normalize, run

def records(root, options):
    examples = [
        ('cd ..; X=y ls "docs a" > /dev/null', 'linux', True, None),
        ('echo $(id) | cat 2>&1', 'linux', True, None),
        ('cat <<EOF\\nhello world\\nEOF', 'linux', True, None),
        ('printf "%s" "" a\\\\ b $\\\'x\\\\ny\\\'', 'linux', True, None),
        ('/usr/bin/printf\\0%s\\0a b\\0', 'linux', False, None),
        ('"C:\\\\Program Files\\\\app.exe" "a b" "" C:\\\\Temp\\\\x', 'windows', False, None),
        ('C:\\\\Program Files\\\\app.exe --flag "x y"', 'windows', False, 'C:\\\\Program Files\\\\app.exe'),
        ('sh -c "echo x > y"', 'linux', False, '/bin/sh'),
        ('', 'linux', True, None),
        ('-', 'linux', False, None),
    ]
    for i, (text, os, shell, pgm) in enumerate(examples):
        for j, (program, args) in enumerate(normalize(text, os=os, shell=shell, pgm=pgm)):
            yield Command(program, args, f'{i}:{j}', session_id='example:session', os=os)
    yield Command('id', [], 'group', 'malicious-group', 'example:attack', 'example:session')
run(Path(__file__).parent, records)
""".replace("ROOT_PATH", repr(str(ROOT)))
    )
    db = tmp_path / "commands.duckdb"
    cmd = [sys.executable, str(driver), "--db", str(db)]
    first = subprocess.run(cmd, check=True, text=True, capture_output=True)
    second = subprocess.run(cmd, check=True, text=True, capture_output=True)
    assert (
        json.loads(first.stdout)["stored"] == json.loads(second.stdout)["stored"] == 12
    )
    con = duckdb.connect(str(db), read_only=True)
    rows = con.execute("SELECT pgm,args FROM COMMANDS ORDER BY record_id").fetchall()
    assert ("ls", ["docs a"]) in rows
    assert ("cat", []) in rows
    assert ("printf", ["%s", "", "a b", "x\ny"]) in rows
    assert ("/usr/bin/printf", ["%s", "a b"]) in rows
    assert ("C:\\Program Files\\app.exe", ["a b", "", "C:\\Temp\\x"]) in rows
    assert ("C:\\Program Files\\app.exe", ["--flag", "x y"]) in rows
    assert ("/bin/sh", ["-c", "echo x > y"]) in rows
    assert (
        con.execute(
            "SELECT count(*) FROM COMMANDS WHERE group_id IS NOT NULL"
        ).fetchall()[0][0]
        == 1
    )
    assert con.execute(
        "SELECT typeof(args),typeof(label),typeof(os) FROM COMMANDS LIMIT 1"
    ).fetchone() == (
        "VARCHAR[]",
        "ENUM('malicious', 'benign', 'unknown', 'malicious-group')",
        "ENUM('windows', 'linux')",
    )
    con.close()


def test_rollback(tmp_path):
    """A parser failure after a flushed batch leaves no partial dataset behind."""
    driver = tmp_path / "ingest.py"
    driver.write_text(
        """
import sys
from pathlib import Path
sys.path.insert(0, ROOT_PATH)
from _ingest import Command, run

def records(root, options):
    for i in range(10001):
        yield Command('echo', [str(i)], str(i))
    raise ValueError('source corruption')
run(Path(__file__).parent, records)
""".replace("ROOT_PATH", repr(str(ROOT)))
    )
    db = tmp_path / "commands.duckdb"
    result = subprocess.run(
        [sys.executable, str(driver), "--db", str(db)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0 and "source corruption" in result.stderr
    con = duckdb.connect(str(db), read_only=True)
    assert con.execute("SELECT count(*) FROM COMMANDS").fetchall()[0][0] == 0
    con.close()
    result = subprocess.run(
        [sys.executable, str(driver), "--db", str(db), "--limit", "3"],
        check=True,
        text=True,
        capture_output=True,
    )
    assert json.loads(result.stdout)["stored"] == 3


def test_empty_argv_and_continuations(tmp_path):
    """Preserve empty native arguments and join shell line continuations."""
    driver = tmp_path / "normalize.py"
    inputs = ["printf\0%s\0\0", "echo a\\\nb", "echo 'a\\\nb'"]
    driver.write_text(
        f"import sys,json\nsys.path.insert(0, {str(ROOT)!r})\n"
        "from _ingest import normalize\n"
        f"inputs = {inputs!r}\n"
        "print(json.dumps([normalize(text, shell=i > 0) for i,text in enumerate(inputs)]))\n"
    )
    result = subprocess.run(
        [sys.executable, str(driver)], check=True, text=True, capture_output=True
    )
    values = json.loads(result.stdout)
    assert values[0] == [["printf", ["%s", ""]]]
    assert values[1] == [["echo", ["ab"]]]
    assert values[2] == [["echo", ["a\\\nb"]]]


def test_ingest_all_order_and_failure_reporting(tmp_path):
    """The real orchestrator runs OpTC last and reports failures across datasets."""
    db = tmp_path / "all.duckdb"
    command = [
        str(ROOT / "ingestall"),
        "optc",
        "kypo",
        "--db",
        str(db),
        "--limit",
        "3",
        "--sample-files",
        "1",
        "--seed",
        "3",
    ]
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    assert result.stdout.index("Ingesting kypo") < result.stdout.index("Ingesting optc")
    with duckdb.connect(str(db), read_only=True) as con:
        assert con.execute(
            "SELECT dataset,count(*) FROM COMMANDS GROUP BY dataset ORDER BY dataset"
        ).fetchall() == [("kypo", 3), ("optc", 3)]
    failed = subprocess.run(
        [
            str(ROOT / "ingestall"),
            "kypo",
            "microsoft-iot",
            "--limit",
            "0",
            "--db",
            str(tmp_path / "failed.duckdb"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert failed.returncode == 1
    assert "Failed datasets: kypo, microsoft-iot" in failed.stderr
    assert not (tmp_path / "failed.duckdb").exists()
    invalid = subprocess.run(
        [str(ROOT / "ingestall"), "nonexistent-dataset"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert invalid.returncode == 2 and "Unknown datasets" in invalid.stderr
