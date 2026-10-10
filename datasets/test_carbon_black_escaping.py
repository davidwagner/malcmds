"""Keep JSON-decoded endpoint command strings intact through DuckDB ingestion."""

import json
from pathlib import Path

import duckdb
from test_ingest_performance import XML_READER, ingest


def test_carbon_black_pipe_and_unc_arguments(tmp_path):
    """Native ATLAS line 3988 and a UNC variant retain every path separator."""
    root = tmp_path / "atlasv2"
    root.mkdir()
    native = json.loads((Path(__file__).parent / "fixtures/atlas-pipe.jsonl").read_text())
    variant = dict(native, process_cmdline=r'cmd.exe /c \\server\share\file',
                   process_path="cmd.exe", target_cmdline="")
    (root / "events.xml").write_text(json.dumps(native) + "\n" + json.dumps(variant))
    database = tmp_path / "commands.duckdb"
    result = ingest(root, database, XML_READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT pgm,args FROM COMMANDS ORDER BY rowid").fetchall()
        assert rows[0][0] == r"c:\program files\mozilla firefox\firefox.exe"
        assert r"\\.\pipe\gecko-crash-server-pipe.3900" in rows[0][1], (
            "JSON already decodes Carbon Black backslashes; a second decode corrupts pipes"
        )
        assert r"C:\Program Files\Mozilla Firefox\omni.ja" in rows[0][1]
        assert rows[-1] == ("cmd.exe", ["/c", r"\\server\share\file"])
    result = ingest(root, database, XML_READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT pgm,args FROM COMMANDS ORDER BY rowid").fetchall() == rows
