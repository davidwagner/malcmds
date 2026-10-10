"""Archive-to-DuckDB regressions for fast filtering and large XML events."""

import json
import zipfile

import duckdb
import pytest
from test_ingest_performance import XML_READER, ingest


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_json_candidates_keep_aliases_envelopes_and_source_numbers(tmp_path, encoding):
    """All supported command fields survive filtering, including escaped keys."""
    root = tmp_path / "comiset"
    root.mkdir()
    events: list[dict[str, object]] = [{"message": "irrelevant", "padding": "x" * 5000}]
    aliases = ["CommandLine", "ProcessCommandLine", "process_cmdline", "command_line",
               "cmdline", "process.command_line", "HostApplication"]
    for name in aliases:
        events.append({"_source": {name: "cmd /c " + name}})
    for envelope in ["EventData", "event_data", "columns", "event", "data", "Event"]:
        events.append({envelope: {"CommandLine": "cmd /c " + envelope}})
    events.extend([
        {"process": {"command_line": "cmd /c nested", "executable": "cmd"}},
        {"process_cmdline": "cmd /c parent", "target_cmdline": "cmd /c child"},
        {"_raw": '<Event><EventData><Data Name="CommandLine">cmd /c raw</Data></EventData></Event>'},
    ])
    lines = [json.dumps(e) for e in events]
    lines += ['{"\\u0043ommandLine": "cmd /c escaped"}', '{"irrelevant": NaN}',
              '{"huge": ' + '9' * 100 + '}', '   ', '{"unused": [1, 2]}']
    with zipfile.ZipFile(root / "input.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("events.json", ("\n".join(lines) + "\n").encode(encoding))
    # Exercise the generic event parser directly: COMISET now requires native
    # process identities and annotations, which these alias-only records lack.
    reader = """
import zipfile
def records(root, options):
    budget = Budget(options)
    with zipfile.ZipFile(root / 'input.zip') as archive:
        with archive.open('events.json') as stream:
            yield from parse_log(stream, 'input.zip/events.json', root.name, budget)
"""
    db = tmp_path / "commands.duckdb"
    result = ingest(root, db, reader)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        rows = con.execute("SELECT args,record_id FROM COMMANDS ORDER BY rowid").fetchall()
        assert [r[0][-1] for r in rows] == aliases + [
            "EventData", "event_data", "columns", "event", "data", "Event", "nested",
            "parent", "child", "raw", "escaped",
        ]
        assert rows[0][1] == "input.zip/events.json:2:2:0"
        assert rows[-1][1] == "input.zip/events.json:18:18:0"
    result = ingest(root, tmp_path / "limited.duckdb", reader, "--max-records", "1")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["stored"] == 0


@pytest.mark.parametrize("bad", ['{"unrelated": ', '{"CommandLine": ', '{"unused": [1,]}'])
def test_json_filter_still_rejects_malformed_records(tmp_path, bad):
    """Native validation must not silently skip corrupt command-free JSON."""
    root = tmp_path / "json"
    root.mkdir()
    (root / "events.xml").write_text('{"irrelevant": true}\n' + bad + '\n')
    result = ingest(root, tmp_path / "commands.duckdb", XML_READER)
    assert result.returncode != 0
    assert "events.xml:2: expected a complete JSON event" in result.stderr


@pytest.mark.parametrize("size", [65530, 65536, 131068, 4 * 1024 * 1024])
def test_xml_large_event_and_split_delimiters(tmp_path, size):
    """Framing must preserve large fields, following events, and source indices."""
    root = tmp_path / "xml"
    root.mkdir()
    prefix = "<Event><EventData><Data Name='CommandLine'>cmd /c "
    text = prefix + "x" * size + "</Data></EventData></Event>"
    # Split the next start tag too, with an ignored Events wrapper in the prefix.
    text += " " * ((65534 - len(text)) % 65536)
    text += "<Event></Event><Event><EventData><Data Name='CommandLine'>whoami</Data></EventData></Event>"
    (root / "events.xml").write_text(text)
    db = tmp_path / "commands.duckdb"
    result = ingest(root, db, XML_READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        rows = con.execute("SELECT pgm,args,record_id FROM COMMANDS ORDER BY rowid").fetchall()
        assert rows == [("cmd", ["/c", "x" * size], "events.xml:1:1:0"),
                        ("whoami", [], "events.xml:3:3:0")]
