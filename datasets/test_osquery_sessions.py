"""Preserve native osquery host/session scope through the ingestion CLI."""

import json
from pathlib import Path

import duckdb
from test_ingest_performance import XML_READER, ingest


def test_native_osquery_hosts_dates_and_sessions(tmp_path):
    """Seven publisher records give four host/date/session groups, in either order."""
    source = (Path(__file__).parent / "fixtures/osquery-keychains.jsonl").read_text()
    previous = None
    for index, lines in enumerate([source.splitlines(), list(reversed(source.splitlines()))]):
        root = tmp_path / str(index) / "splunkad"
        root.mkdir(parents=True)
        (root / "events.xml").write_text("\n".join(lines))
        database = tmp_path / f"commands{index}.duckdb"
        result = ingest(root, database, XML_READER)
        assert result.returncode == 0, result.stderr
        with duckdb.connect(str(database)) as con:
            rows = con.execute("SELECT pgm,args,session_id,os FROM COMMANDS ORDER BY session_id,pgm,args").fetchall()
        assert len(rows) == 7
        assert len({r[2] for r in rows}) == 4, "osquery sessions need host and capture-day scope"
        assert all(r[3] == "linux" for r in rows)
        if index:
            assert rows == previous
        previous = rows


def test_boot_and_missing_session_fallbacks(tmp_path):
    """Boot identities and actual process lifetimes scope reused numeric IDs."""
    base = json.loads((Path(__file__).parent / "fixtures/osquery-keychains.jsonl").read_text().splitlines()[0])
    records = []
    for boot in ["first", "second"]:
        row = dict(base, boot_id=boot)
        records.append(row)
    for host in ["host-a", "host-b"]:
        row = dict(base, hostIdentifier=host, columns=dict(base["columns"]))
        row["columns"].pop("session_id")
        records.append(row)
    for index in range(2):
        records.append({"name": "custom-query", "hostIdentifier": "host-a",
                        "columns": {"cmdline": f"/bin/echo {index}", "path": "/bin/echo"}})
    root = tmp_path / "splunkad"
    root.mkdir()
    (root / "events.xml").write_text("\n".join(json.dumps(r) for r in records))
    database = tmp_path / "commands.duckdb"
    result = ingest(root, database, XML_READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        sessions = [r[0] for r in con.execute("SELECT session_id FROM COMMANDS").fetchall()]
    assert len(set(sessions)) == 6
    assert all("unknown" not in session for session in sessions)
