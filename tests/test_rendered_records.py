"""Distinguish published search text from rendered process events at ingestion."""

import gzip
import json
from pathlib import Path

import duckdb
import pytest
from test_ingest_performance import XML_READER, ingest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("wrapped", [False, True])
def test_complete_search_export_is_not_execution(tmp_path, wrapped):
    """A renamed or JSON-wrapped search export must create zero command rows."""
    root = tmp_path / "splunkad"
    root.mkdir()
    text = gzip.decompress((FIXTURES / "splunk-search.log.gz").read_bytes()).decode()
    (root / "events.xml").write_text(json.dumps({"_raw": text}) if wrapped else text)
    database = tmp_path / "commands.duckdb"
    result = ingest(root, database, XML_READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT count(*) FROM COMMANDS").fetchone()[0] == 0, (
            "Splunk search predicates describe queries, not process executions"
        )


def test_rendered_process_requires_header_provider_and_event(tmp_path):
    """Native Security 4688 survives; unrelated assignments and events do not."""
    root = tmp_path / "splunkad"
    root.mkdir()
    native = (FIXTURES / "rendered-process.txt").read_text()
    text = "CommandLine=cmd.exe\n" + native
    text += native.replace("EventCode=4688", "EventCode=4624")
    text += native.replace("SourceName=Microsoft Windows security auditing.", "SourceName=other")
    (root / "events.xml").write_text(text)
    database = tmp_path / "commands.duckdb"
    result = ingest(root, database, XML_READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT pgm,args,record_id FROM COMMANDS").fetchall()
        assert rows == [(r"C:\Program Files\SplunkUniversalForwarder\bin\splunk-MonitorNoHandle.exe",
                         [], "events.xml:1329691:1:0")]
