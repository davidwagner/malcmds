"""Exercise actual AVIATOR archives, worker processes, Arrow spools and DuckDB."""

import io
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import duckdb
import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
ARCHIVE = "10.35097-8s5b0u5yqgfs2y0d.tar"


def event(number, command=None):
    """Construct an XML event with source metadata and an optional command."""
    field = f'<Data Name="CommandLine">{command}</Data>' if command else ""
    return (f'<Event><System><Computer>host</Computer><EventRecordID>{number}'
            f'</EventRecordID></System><EventData>{field}'
            '<Data Name="LogonId">0x12</Data></EventData></Event>')


def archive_root(tmp_path, members):
    """Build a genuine nested tar/ZIP archive from named export contents."""
    root = tmp_path / "datasets" / "aviator"
    root.mkdir(parents=True)
    with tarfile.open(root / ARCHIVE, "w") as archive:
        for name, exports in members:
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                for filename, text in exports:
                    zipped.writestr(filename, text)
            info = tarfile.TarInfo(name)
            info.size = len(payload.getvalue())
            archive.addfile(info, io.BytesIO(payload.getvalue()))
    return root


def ingest(root, database, workers, *extra, check=True):
    """Run the production driver in a separate interpreter with real workers."""
    driver = ("import sys; from pathlib import Path; "
              f"sys.path.insert(0, {str(SCRIPTS)!r}); "
              "from _ingest import run; from _ingest_aviator import records; "
              f"run(Path({str(root)!r}), records)")
    return subprocess.run(
        [sys.executable, "-c", driver, "--db", str(database), "--workers", str(workers),
         "--batch-size", "2", *extra], capture_output=True, text=True, check=check,
    )


def rows(database):
    """Read persisted commands in insertion order to catch reordered exports."""
    with duckdb.connect(str(database), read_only=True) as connection:
        return connection.execute("SELECT pgm,pgm_base,args,dataset,record_id,label,group_id,session_id,os,shell_input,other_tokens FROM COMMANDS ORDER BY rowid").fetchall()


def assert_clean(root):
    """Verify that temporary worker output and spill directories were removed."""
    scratch = root.parent.parent / "tmp" / "ingest"
    assert not list(scratch.glob("aviator-*"))
    assert not list(scratch.rglob("*.arrow"))


def test_serial_parallel_rows_labels_order_and_sampling(tmp_path):
    """Parallel ingestion preserves source order, labels, IDs and ZIP sampling."""
    root = archive_root(tmp_path, [
        ("data/ex_first.zip", [
            ("security.xml", event(8, "security.exe /s")),
            ("sysmon_normal_operation.xml", event(1) + event(2, "cmd.exe /c a")
             + event(3, "cmd.exe /c b") + event(4, "cmd.exe /c c")),
            ("empty.xml", event(5)),
            ("raw.evtx", "ignored"),
        ]),
        ("data/ex_second.zip", [("sysmon_attack.xml", event(9, "attack.exe /x"))]),
        ("data/raw.zip", [("ignored.xml", event(10, "ignored.exe"))]),
    ])
    serial, parallel = tmp_path / "serial.db", tmp_path / "parallel.db"
    ingest(root, serial, 1)
    ingest(root, parallel, 3)
    assert rows(parallel) == rows(serial)
    assert [row[0] for row in rows(parallel)] == [
        "cmd.exe", "cmd.exe", "cmd.exe", "security.exe", "attack.exe"
    ]
    assert [row[5:7] for row in rows(parallel)] == [
        ("benign", None), ("benign", None), ("benign", None),
        ("malicious-group", "aviator:first"), ("malicious-group", "aviator:second"),
    ]
    for workers in (1, 3):
        ingest(root, tmp_path / f"sample-{workers}.db", workers,
               "--sample-files", "1", "--seed", "3")
    assert rows(tmp_path / "sample-1.db") == rows(tmp_path / "sample-3.db")
    assert_clean(root)


@pytest.mark.parametrize("bounds,count", [(('--max-records', '1'), 0),
                                         (('--max-records', '2'), 1),
                                         (('--limit', '1'), 1)])
def test_parallel_request_preserves_global_serial_bounds(tmp_path, bounds, count):
    """A bound counts the same source events or output commands for any workers."""
    root = archive_root(tmp_path, [("ex_sample.zip", [
        ("sysmon_first.xml", event(1) + event(2, "cmd.exe /c a")),
        ("sysmon_second.xml", event(3, "cmd.exe /c b")),
    ])])
    for workers in (1, 3):
        ingest(root, tmp_path / f"bound-{workers}.db", workers, *bounds)
    assert rows(tmp_path / "bound-1.db") == rows(tmp_path / "bound-3.db")
    assert len(rows(tmp_path / "bound-3.db")) == count
    assert_clean(root)


@pytest.mark.parametrize("members", [[], [("ex_empty.zip", [("raw.evtx", "ignored")])]])
def test_no_exports_completes_without_worker_outputs(tmp_path, members):
    """Archives without canonical exports ingest an empty successful dataset."""
    root = archive_root(tmp_path, members)
    database = tmp_path / "empty.db"
    ingest(root, database, 3)
    assert rows(database) == []
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute("SELECT * FROM INGESTED").fetchall() == [("aviator", True)]
    assert_clean(root)


def test_worker_failure_cleans_spools_and_keeps_prior_commits(tmp_path):
    """Malformed XML fails visibly after earlier exports commit; retry starts over."""
    root = archive_root(tmp_path, [("ex_attack.zip", [
        ("sysmon_1.xml", event(1, "cmd.exe /a") + event(2, "cmd.exe /b")),
        ("sysmon_2.xml", event(3, "cmd.exe /c") + "<Event>truncated"),
        ("sysmon_3.xml", event(4, "cmd.exe /d")),
    ])])
    database = tmp_path / "failure.db"
    failed = ingest(root, database, 2, check=False)
    assert failed.returncode != 0
    assert "Truncated XML Event" in failed.stderr
    assert [row[2] for row in rows(database)] == [["/a"], ["/b"]]
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute("SELECT * FROM INGESTED").fetchall() == [("aviator", False)]
    assert_clean(root)
    ingest(root, database, 2, "--max-records", "1")
    assert [row[2] for row in rows(database)] == [["/a"]]
    assert_clean(root)


def test_early_close_terminates_workers_and_removes_spools(tmp_path):
    """Closing a consumer while workers remain leaves no processes or files."""
    root = archive_root(tmp_path, [("ex_attack.zip", [
        (f"sysmon_{index}.xml", event(index, "cmd.exe /x") * 10)
        for index in range(5)
    ])])
    driver = ("import sys, multiprocessing; from pathlib import Path; "
              "from types import SimpleNamespace; "
              f"sys.path.insert(0, {str(SCRIPTS)!r}); "
              "from _ingest_aviator import records; "
              "options=SimpleNamespace(workers=2,max_records=None,limit=None,"
              "batch_size=2,sample_files=None,seed=0); "
              f"reader=records(Path({str(root)!r}),options); "
              "assert next(reader).num_rows==2; reader.close(); "
              "assert not multiprocessing.active_children()")
    subprocess.run([sys.executable, "-c", driver], check=True, capture_output=True, text=True)
    assert_clean(root)
