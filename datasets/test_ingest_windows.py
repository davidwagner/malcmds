"""End-to-end checks against local publisher records and native DuckDB files."""

import csv
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import duckdb
import pytest

DATASETS = Path(__file__).resolve().parent
TMP = DATASETS.parent / "tmp"


def invoke(dataset, database, *options, root=None):
    """Run the real CLI runner in an independent Python process."""
    if root is None:
        command = [sys.executable, str(DATASETS / dataset / "ingest")]
    else:
        code = (
            "import sys; from pathlib import Path; "
            f"sys.path.insert(0, {str(DATASETS)!r}); "
            "from _ingest import run; "
            f"from _ingest_windows import {dataset}; "
            f"run(Path({str(root)!r}), {dataset})"
        )
        command = [sys.executable, "-c", code]
    return subprocess.run(
        command + ["--db", str(database), *options],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("dataset", "options"),
    [
        ("atlasv2", ["--limit", "30"]),
        ("aviator", ["--limit", "30", "--sample-files", "1", "--seed", "42"]),
        ("comiset", ["--limit", "30", "--max-records", "100000"]),
        ("splunkad", ["--limit", "30", "--sample-files", "30", "--seed", "42"]),
    ],
)
def test_actual_archive_ingestion_is_idempotent(dataset, options):
    """Actual downloaded records survive normalization and repeated ingestion."""
    if not (DATASETS / dataset).exists():
        pytest.skip("Publisher data is not present")
    TMP.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="windows-e2e-", dir=TMP) as directory:
        db = Path(directory) / "cmds.duckdb"
        invoke(dataset, db, *options)
        with duckdb.connect(str(db)) as connection:
            first = connection.execute(
                "SELECT * FROM COMMANDS ORDER BY record_id"
            ).fetchall()
            assert first
            assert (
                connection.execute(
                    "SELECT count(*) FROM COMMANDS "
                    "WHERE pgm = '' OR session_id = '' OR args IS NULL"
                ).fetchall()[0][0]
                == 0
            )
            assert (
                connection.execute(
                    "SELECT count(*) FROM COMMANDS "
                    "WHERE (label = 'malicious-group') != (group_id IS NOT NULL)"
                ).fetchall()[0][0]
                == 0
            )
            assert (
                connection.execute(
                    "SELECT count(*) - count(DISTINCT record_id) FROM COMMANDS"
                ).fetchall()[0][0]
                == 0
            )
        invoke(dataset, db, *options)
        with duckdb.connect(str(db)) as connection:
            assert (
                connection.execute(
                    "SELECT * FROM COMMANDS ORDER BY record_id"
                ).fetchall()
                == first
            )


def test_malformed_publisher_xml_retains_command_arguments():
    """SnapAttack's unescaped ampersands must preserve cmd redirection arguments."""
    rel = Path("datasets/attack_techniques/T1053/snapattack/snapattack.log")
    original = DATASETS / "splunkad/source" / rel
    if not original.exists():
        pytest.skip("Publisher data is not present")
    with tempfile.TemporaryDirectory(prefix="windows-xml-", dir=TMP) as directory:
        root = Path(directory) / "splunkad"
        target = root / "source" / rel
        target.parent.mkdir(parents=True)
        shutil.copyfile(original, target)
        db = Path(directory) / "commands.duckdb"
        invoke("splunkad", db, "--limit", "1", root=root)
        with duckdb.connect(str(db)) as connection:
            pgm, args = connection.execute("SELECT pgm,args FROM COMMANDS").fetchall()[
                0
            ]
            assert pgm.lower().endswith("\\cmd.exe")
            assert "2>&1" in args
            session = connection.execute("SELECT session_id FROM COMMANDS").fetchall()[
                0
            ][0]
            assert session.endswith(":0x3e7")


def test_carbon_black_exact_reapr_process_join():
    """The publisher process GUID, rather than its numeric PID, supplies labels."""
    archive = DATASETS / "atlasv2/atlasv2.tar.gz"
    if not archive.exists():
        pytest.skip("Publisher data is not present")
    with tempfile.TemporaryDirectory(prefix="windows-reapr-", dir=TMP) as directory:
        root = Path(directory) / "atlasv2"
        labels = root / "reapr" / "atlasv2"
        labels.mkdir(parents=True)
        for source in (DATASETS / "atlasv2/reapr/atlasv2").glob("*.labels"):
            shutil.copyfile(source, labels / source.name)
        attack_guids: set[str] = set()
        for source in labels.glob("*.labels"):
            with source.open() as stream:
                attack_guids.update(
                    row["process_uuid"].strip()
                    for row in csv.DictReader(stream, skipinitialspace=True)
                )
        with (
            tarfile.open(archive) as original,
            tarfile.open(root / archive.name, "w:gz") as small,
        ):
            found_alerts = found_attack = False
            for member in original:
                if member.name.endswith("edr-alerts-h2-m2.jsonl"):
                    small.addfile(member, original.extractfile(member))
                    found_alerts = True
                elif "/cbc-edr/" in member.name and member.isfile():
                    selected = []
                    found_target = False
                    member_stream = original.extractfile(member)
                    assert member_stream is not None
                    for line in member_stream:
                        row = json.loads(line)
                        if (
                            not found_target
                            and row.get("type") == "endpoint.event.procstart"
                            and row.get("target_cmdline")
                        ):
                            selected.append(line)
                            found_target = True
                        elif (
                            not found_attack
                            and row.get("process_guid") in attack_guids
                            and row.get("process_cmdline")
                        ):
                            selected.append(line)
                            found_attack = True
                        if found_target and found_attack:
                            break
                    subset = tarfile.TarInfo(member.name)
                    payload = b"".join(selected)
                    subset.size = len(payload)
                    small.addfile(subset, io.BytesIO(payload))
                if found_alerts and found_attack:
                    break
        db = Path(directory) / "commands.duckdb"
        invoke("atlasv2", db, root=root)
        with duckdb.connect(str(db)) as connection:
            rows = connection.execute("SELECT pgm,args,label FROM COMMANDS").fetchall()
            assert len(rows) == 31
            assert all("\\\\" not in pgm for pgm, _, _ in rows)
            assert any(label == "malicious" for _, _, label in rows)
            assert any("udp port 53" in args for _, args, _ in rows)
            assert any(
                pgm.lower().endswith("searchprotocolhost.exe") for pgm, _, _ in rows
            )


def test_interpreted_audit_preserves_unquoted_argument_spaces():
    """ausearch's decoded output preserves each indexed argument in full."""
    rel = Path(
        "datasets/attack_techniques/T1555.005/linux_auditd_find_credentials/"
        "auditd_execve_find_creds.log"
    )
    original = DATASETS / "splunkad/source" / rel
    if not original.exists():
        pytest.skip("Publisher data is not present")
    with tempfile.TemporaryDirectory(prefix="windows-audit-", dir=TMP) as directory:
        root = Path(directory) / "splunkad"
        target = root / "source" / rel
        target.parent.mkdir(parents=True)
        shutil.copyfile(original, target)
        db = Path(directory) / "commands.duckdb"
        invoke("splunkad", db, "--limit", "1", root=root)
        with duckdb.connect(str(db)) as connection:
            pgm, args, osname = connection.execute(
                "SELECT pgm,args,os FROM COMMANDS"
            ).fetchall()[0]
            assert pgm == "grep"
            assert osname == "linux"
            assert len(args) == 2
            assert args[0] == "-v"
            assert args[1].startswith("File does not exist:")
            assert "config-set-passwords already ran" in args[1]
