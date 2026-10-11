"""End-to-end checks against the downloaded publisher data.

Unavailable archives skip their corresponding checks. External I/O failures are
not simulated: tests exercise actual archive readers and DuckDB transactions.
"""

import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[1] / "datasets"
INPUTS = {
    "ait": "fox_no-pcaps.zip",
    "cyberlab": "cyberlab_2019-08-01.json.gz",
    "kypo": "data.zip",
    "microsoft-iot": "Microsoft.IoT-Dump-pwd-infected.zip",
    "linux-apt-2024": "source/combine.csv",
    "windows-apt-2025": "source/combined.csv",
    "publicarena": "source/SystemAuditLogs/Host A win10/HostA-F-Lateral.zip",
}


@pytest.mark.parametrize("dataset", list(INPUTS))
def test_real_dataset_idempotent(dataset, tmp_path):
    """Random files produce typed commands with stable IDs on repeated runs."""
    if not (ROOT / dataset / INPUTS[dataset]).exists():
        pytest.skip("Publisher data not downloaded")
    database = tmp_path / "commands.duckdb"
    command = [
        sys.executable,
        str(ROOT / dataset / "ingest"),
        "--db",
        str(database),
        "--limit",
        "50",
        "--sample-files",
        "2",
        "--seed",
        "83",
    ]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=180)
    with duckdb.connect(str(database), read_only=True) as connection:
        first = connection.execute(
            "SELECT * FROM COMMANDS ORDER BY record_id"
        ).fetchall()
        assert len(first) == 50
        assert (
            connection.execute(
                "SELECT count(*) FROM COMMANDS WHERE pgm = '' OR session_id = '' "
                "OR record_id = '' OR args IS NULL "
                "OR (label = 'malicious-group' AND group_id IS NULL)"
            ).fetchall()[0][0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT count(DISTINCT record_id) FROM COMMANDS"
            ).fetchall()[0][0]
            == 50
        )
        if dataset == "windows-apt-2025":
            assert all("\\\\" not in row[0] for row in first)
        if dataset in ("cyberlab", "microsoft-iot"):
            assert (
                connection.execute(
                    "SELECT count(*) FROM COMMANDS WHERE label != 'malicious'"
                ).fetchall()[0][0]
                == 0
            )
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=180)
    with duckdb.connect(str(database), read_only=True) as connection:
        assert (
            first
            == connection.execute(
                "SELECT * FROM COMMANDS ORDER BY record_id"
            ).fetchall()
        )


def test_linux_audit_headers_and_excel_escapes(tmp_path):
    """Changing CSV headers and Excel control escapes preserve audit labels."""
    if not (ROOT / "linux-apt-2024" / INPUTS["linux-apt-2024"]).exists():
        pytest.skip("Publisher data not downloaded")
    database = tmp_path / "linux.duckdb"
    subprocess.run(
        [sys.executable, str(ROOT / "linux-apt-2024/ingest"), "--db", str(database)],
        check=True,
        capture_output=True,
        timeout=180,
    )
    with duckdb.connect(str(database), read_only=True) as connection:
        rows = connection.execute(
            "SELECT pgm,args,label FROM COMMANDS WHERE record_id LIKE '%1704304027.612:3126'"
        ).fetchall()
        assert len(rows) == 1  # Two Wazuh alerts describe one kernel execution.
        assert all(
            row
            == (
                "/usr/lib/systemd/systemd-user-runtime-dir",
                ["start", "1000"],
                "benign",
            )
            for row in rows
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM COMMANDS WHERE label = 'benign'"
            ).fetchall()[0][0]
            > 1000
        )


def test_sudo_list_is_privilege_query(tmp_path):
    """sudo's logged COMMAND=list denotes sudo -l, not an executable list."""
    if not (ROOT / "ait/fox_no-pcaps.zip").exists():
        pytest.skip("Publisher data not downloaded")
    database = tmp_path / "ait.duckdb"
    subprocess.run(
        [sys.executable, str(ROOT / "ait/ingest"), "--db", str(database)],
        check=True,
        capture_output=True,
        timeout=180,
    )
    with duckdb.connect(str(database), read_only=True) as connection:
        rows = connection.execute(
            "SELECT pgm,args FROM COMMANDS WHERE "
            "record_id = 'fox_no-pcaps.zip:gather/intranet_server/logs/auth.log:354:0'"
        ).fetchall()
        assert rows == [("sudo", ["-l"])]
