"""Native BOTS persistence observations through CSV parsing and DuckDB storage."""

import csv
import json
from pathlib import Path
from types import SimpleNamespace

import duckdb
import pytest
from _ingest import _initialize, _insert, command_table
from _ingest_bots import exported_observations
from _ingest_processes import ProcessCommands


def native_events():
    """Load unmodified export rows, retaining their original bucket and ordinal."""
    return json.loads((Path(__file__).parent / "fixtures/bots/persistence.json").read_text())


def ingest_events(directory, events):
    """Read exported native CSV events and store the selected commands in DuckDB."""
    path = directory / "events.csv"
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=events[0].keys())
        writer.writeheader()
        writer.writerows(events)
    with ProcessCommands() as processes:
        commands = list(exported_observations(
            [("fixture", path)], SimpleNamespace(max_records=None), processes,
        ))
        commands.extend(processes.commands())
    with duckdb.connect(str(directory / "commands.duckdb")) as connection:
        _initialize(connection)
        _insert(connection, command_table(commands, "splunk-bots"))
        return connection.execute(
            "SELECT pgm,args,label,group_id,session_id FROM COMMANDS ORDER BY record_id"
        ).fetchall()


def test_native_persistence_and_parent_only_control(tmp_path):
    """Windows quoting and process selection must preserve six known observations."""
    rows = ingest_events(tmp_path, [item["event"] for item in native_events()])
    positives = [row for row in rows if row[2] == "malicious"]
    assert len(positives) == 6, "Native Security, Sysmon and WinHostMon persistence labels changed"
    assert all(row[3] is None for row in rows)
    assert sum(row[0].lower().endswith("schtasks.exe") for row in positives) == 2
    powershell = [row for row in positives if row[0].lower().endswith("powershell.exe")]
    assert len(powershell) == 4
    assert all(row[1][:4] == ["-NonI", "-W", "hidden", "-c"] for row in powershell), (
        "Windows argument parsing changed the recorded PowerShell invocation"
    )
    assert len({row[4] for row in powershell if ":process:5448:" in row[4]}) == 2, (
        "WinHostMon records with distinct recorded start times must stay distinct"
    )
    assert len(rows) == 7
    assert [row[2] for row in rows if row[0].lower().endswith("whoami.exe")] == ["unknown"]


@pytest.mark.parametrize("index", [0, 1, 2, 3, 5, 6])
@pytest.mark.parametrize("time", ["", "invalid", "nan", "inf", "-inf", "1534723199", "1534809600"])
def test_unusable_or_unrelated_time(tmp_path, index, time):
    """A missing, non-finite or unrelated export timestamp cannot establish identity."""
    row = native_events()[index]["event"]
    row["_time"] = time
    assert ingest_events(tmp_path, [row])[0][2] == "unknown"


@pytest.mark.parametrize("index", [0, 1, 2, 3, 5, 6])
@pytest.mark.parametrize("change", ["host", "payload", "path"])
def test_wrong_host_payload_or_path(tmp_path, index, change):
    """Lookalike commands and conflicting native/export hosts remain unknown."""
    row = native_events()[index]["event"]
    if change == "host":
        row["host"] = "host::BGIST-L"
    elif change == "payload":
        row["_raw"] = row["_raw"].replace("Network debug", "Network other")
    else:
        row["_raw"] = row["_raw"].replace("System32", "Temp").replace("system32", "Temp")
    assert ingest_events(tmp_path, [row])[0][2] == "unknown"


@pytest.mark.parametrize("index", [0, 1, 2, 3])
@pytest.mark.parametrize("offset,expected", [(-0.001, "unknown"), (0, "malicious"), (0.999, "malicious"), (1, "unknown")])
def test_process_event_time_precision(tmp_path, index, offset, expected):
    """The confirmed export second is included; adjacent seconds are excluded."""
    row = native_events()[index]["event"]
    row["_time"] = str(float(row["_time"]) + offset)
    assert ingest_events(tmp_path, [row])[0][2] == expected


@pytest.mark.parametrize("index,old,new", [
    (0, "WinEventLog:Security", "WinEventLog:Other"),
    (1, "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "XmlWinEventLog:Other"),
    (0, "EventCode=4688", "EventCode=1"),
    (1, "<EventID>1</EventID>", "<EventID>3</EventID>"),
    (1, "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>", "<Channel>Other</Channel>"),
    (1, "Name='Microsoft-Windows-Sysmon'", "Name='Other'"),
    (0, "/TN Updater", "/TN Other"),
    (0, "/Create", "/Delete"),
    (2, "-NonI -W hidden", "-NonI -W normal"),
    (5, "ProcessId=5448", "ProcessId=5449"),
    (5, "20180820101100.007904+000", "20180820101101.007904+000"),
    (5, 'Host="FYODOR-L"', 'Host="OTHER"'),
])
def test_other_event_task_or_process_identity(tmp_path, index, old, new):
    """Provider, task arguments and native process identity limit the label rule."""
    row = native_events()[index]["event"]
    assert old in row["_raw"] or old in row["sourcetype"]
    row["_raw"] = row["_raw"].replace(old, new)
    row["sourcetype"] = row["sourcetype"].replace(old, new)
    assert ingest_events(tmp_path, [row])[0][2] == "unknown"


def test_non_process_snapshot_is_omitted(tmp_path):
    """A WinHostMon inventory record cannot become a process execution."""
    row = native_events()[5]["event"]
    row["_raw"] = row["_raw"].replace("Type=Process", "Type=Service")
    assert ingest_events(tmp_path, [row]) == []
