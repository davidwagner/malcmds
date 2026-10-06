"""End-to-end regressions for large batches and command-poor XML streams."""

import json
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parent


def ingest(root, database, reader, *options):
    """Run the real writer and a source reader in a separate interpreter."""
    driver = root / "driver.py"
    driver.write_text(
        f"import sys\nfrom pathlib import Path\nsys.path.insert(0, {str(ROOT)!r})\n"
        "from _ingest import Command, run\n"
        "from _ingest_windows import Budget, parse_log\n"
        + reader
        + "\nrun(Path(__file__).parent, records)\n"
    )
    return subprocess.run(
        [sys.executable, str(driver), "--db", str(database), *options],
        capture_output=True,
        text=True,
        check=False,
    )


XML_READER = """
def records(root, options):
    with (root / 'events.xml').open('rb') as stream:
        yield from parse_log(stream, 'events.xml', root.name, Budget(options))
"""


def test_command_poor_xml_reports_progress_and_preserves_ids(tmp_path):
    """Large gaps between commands remain visible and retain source numbering."""
    root = tmp_path / "xml"
    root.mkdir()
    irrelevant = "<Event><System><EventID>4663</EventID></System></Event>"
    command = "<Event><EventData><Data Name='CommandLine'>cmd /c whoami</Data></EventData></Event>"
    (root / "events.xml").write_text(irrelevant * 100000 + command)
    database = tmp_path / "commands.duckdb"
    result = ingest(root, database, XML_READER)
    assert result.returncode == 0, result.stderr
    assert "100,000 XML events scanned in events.xml" in result.stderr
    assert "committing 1 commands" in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT pgm,args,record_id FROM COMMANDS").fetchall() == [
            ("cmd", ["/c", "whoami"], "events.xml:100001:100001:0")
        ]
    limited = ingest(
        root, tmp_path / "limited.duckdb", XML_READER, "--max-records", "100000"
    )
    assert limited.returncode == 0, limited.stderr
    assert json.loads(limited.stdout)["stored"] == 0


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_xml_filter_retains_supported_fields_and_malformed_exports(tmp_path, encoding):
    """Filtering preserves every supported alias, XML escapes, and repair paths."""
    root = tmp_path / "xml"
    root.mkdir()
    names = [
        "CommandLine",
        "ProcessCommandLine",
        "process_cmdline",
        "command_line",
        "cmdline",
        "process.command_line",
        "HostApplication",
        "&#67;ommandLine",
    ]
    events = [
        f"<Event><EventData><Data Name='{name}'>cmd /c echo {i}</Data></EventData></Event>"
        for i, name in enumerate(names)
    ]
    # A complete event spans multiple reads, followed by malformed publisher XML.
    events.extend(
        [
            "<Event><EventData><Data Name='Other'>" + "x" * 140000 + "</Data>"
            "<Data Name='CommandLine'>cmd /c large</Data></EventData></Event>",
            "<Event><EventData><Data Name='CommandLine'>cmd /c echo a&b</Data></EventData></Event>",
        ]
    )
    # Start-tag splits and a non-event prefix exercise framing without wrappers.
    (root / "events.xml").write_text(" " * 65534 + "".join(events), encoding=encoding)
    # parse_log detects the format in its first 4096 bytes, so use an Events wrapper
    # containing an initial command-free event before the large inter-event gap.
    text = (
        "<Events><Event><EventData/></Event>"
        + (root / "events.xml").read_text(encoding=encoding)
        + "</Events>"
    )
    (root / "events.xml").write_text(text, encoding=encoding)
    result = ingest(root, tmp_path / "commands.duckdb", XML_READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(tmp_path / "commands.duckdb")) as con:
        rows = con.execute("SELECT args FROM COMMANDS ORDER BY record_id").fetchall()
        assert len(rows) == 10
        assert sorted(row[0][-1] for row in rows) == sorted(
            [str(i) for i in range(8)] + ["large", "a&b"]
        )


def test_truncated_xml_rolls_back_and_empty_xml_finishes(tmp_path):
    """Filtering still rejects incomplete events and accepts empty wrappers."""
    root = tmp_path / "xml"
    root.mkdir()
    database = tmp_path / "commands.duckdb"
    (root / "events.xml").write_text("<Events><Event><EventData/></Event><Event>")
    result = ingest(root, database, XML_READER)
    assert result.returncode != 0
    assert "Truncated XML Event" in result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT count(*) FROM COMMANDS").fetchone() == (0,)
    (root / "events.xml").write_text("<Events></Events>")
    result = ingest(root, database, XML_READER)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["stored"] == 0


def test_large_batches_preserve_existing_rows_and_internal_duplicates(tmp_path):
    """Every input is inserted; completed datasets skip even with new limits."""
    root = tmp_path / "batch"
    root.mkdir()
    database = tmp_path / "commands.duckdb"
    reader = """
def records(root, options):
    yield Command('first', [], '0')
    for i in range(100005):
        yield Command('later', [str(i)], str(i))
    yield Command('duplicate', [], '1')
"""
    first = ingest(root, database, reader)
    assert first.returncode == 0, first.stderr
    assert json.loads(first.stdout)["stored"] == 100007
    second = ingest(root, database, reader, "--limit", "3")
    assert second.returncode == 0, second.stderr
    assert json.loads(second.stdout)["skipped"] is True
    with duckdb.connect(str(database)) as con:
        assert con.execute(
            "SELECT pgm FROM COMMANDS WHERE record_id='0' ORDER BY pgm"
        ).fetchall() == [("first",), ("later",)]
        assert con.execute(
            "SELECT pgm FROM COMMANDS WHERE record_id='1' ORDER BY pgm"
        ).fetchall() == [("duplicate",), ("later",)]
        assert con.execute(
            "SELECT count(*)-count(DISTINCT record_id) FROM COMMANDS"
        ).fetchone() == (2,)


@pytest.mark.parametrize("with_command", [False, True])
def test_short_xml_event_is_counted_once_at_read_boundary(tmp_path, with_command):
    """Consumed events shorter than the retained suffix never appear twice."""
    root = tmp_path / "xml"
    root.mkdir()
    empty = "<Event></Event>"
    text = empty
    if with_command:
        text += " " * (65536 - 2 * len(empty)) + empty
        text += "<Event><EventData><Data Name='CommandLine'>whoami</Data></EventData></Event>"
    (root / "events.xml").write_text(text)
    database = tmp_path / "commands.duckdb"
    result = ingest(root, database, XML_READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT record_id FROM COMMANDS").fetchall() == (
            [("events.xml:3:3:0",)] if with_command else []
        )
