"""End-to-end regression checks using the publisher's BOTS index buckets."""

import random
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import duckdb
import pytest

DATASETS = Path(__file__).resolve().parents[1] / "datasets"
TMP = DATASETS.parent / "tmp"


def invoke(database, *arguments):
    """Execute the actual ingester with an isolated destination database."""
    return subprocess.run(
        [
            sys.executable,
            str(DATASETS / "splunk-bots/ingest"),
            "--db",
            str(database),
            *arguments,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def history_bucket_seed(bucket="db_1534766463_1534762020_305"):
    """Select the publisher bucket containing the known apt history observation."""
    with tarfile.open(DATASETS / "splunk-bots/botsv3_data_set.tgz") as archive:
        buckets = sorted(
            {
                Path(member.name).parents[1].name
                for member in archive
                if member.name.endswith("/rawdata/journal.gz")
            }
        )
    for seed in range(10000):
        if random.Random(seed).sample(buckets, 1)[0] == bucket:
            return str(seed)
    raise AssertionError("Could not select the expected publisher bucket")


def test_bots_native_export_and_idempotence():
    """A real bucket produces native DuckDB rows and stable source identifiers."""
    if not (DATASETS / "splunk-bots/botsv3_data_set.tgz").exists():
        pytest.skip("Publisher dataset is not present")
    TMP.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bots-e2e-", dir=TMP) as directory:
        db = Path(directory) / "commands.duckdb"
        options = [
            "--limit",
            "50",
            "--sample-files",
            "1",
            "--seed",
            history_bucket_seed(),
        ]
        invoke(db, *options)
        with duckdb.connect(str(db)) as connection:
            rows = connection.execute(
                "SELECT * FROM COMMANDS ORDER BY record_id"
            ).fetchall()
            assert len(rows) == 50
            assert (
                connection.execute(
                    "SELECT count(*) FROM COMMANDS WHERE label != 'unknown' OR group_id IS NOT NULL"
                ).fetchall()[0][0]
                == 0
            )
            assert (
                connection.execute(
                    "SELECT count(*) FROM COMMANDS "
                    "WHERE pgm = '' OR session_id = '' OR args IS NULL"
                ).fetchall()[0][0]
                == 0
            )
        invoke(db, *options)
        with duckdb.connect(str(db)) as connection:
            assert (
                connection.execute(
                    "SELECT * FROM COMMANDS ORDER BY record_id"
                ).fetchall()
                == rows
            )


def test_apt_history_contains_only_its_recorded_invocation():
    """The real history-2 event is apt metadata surrounding a Commandline field."""
    if not (DATASETS / "splunk-bots/botsv3_data_set.tgz").exists():
        pytest.skip("Publisher dataset is not present")
    with tempfile.TemporaryDirectory(prefix="bots-history-", dir=TMP) as directory:
        db = Path(directory) / "commands.duckdb"
        # This seeded bucket has the apt history record at CSV row 157,959.
        invoke(
            db,
            "--sample-files",
            "1",
            "--seed",
            history_bucket_seed(),
            "--max-records",
            "158000",
        )
        with duckdb.connect(str(db)) as connection:
            assert (
                connection.execute(
                    "SELECT count(*) FROM COMMANDS "
                    "WHERE pgm = 'apt-get' AND args = ['install','netcat']"
                ).fetchall()[0][0]
                > 0
            )
            assert (
                connection.execute(
                    "SELECT count(*) FROM COMMANDS "
                    "WHERE pgm IN ('Start-Date:', 'End-Date:', 'Commandline:', 'Install:')"
                ).fetchall()[0][0]
                == 0
            )


def test_winhostmon_preserves_quoted_executable_and_last_argument():
    """A quoted executable plus quoted arguments is not a whole-value wrapper."""
    if not (DATASETS / "splunk-bots/botsv3_data_set.tgz").exists():
        pytest.skip("Publisher dataset is not present")
    with tempfile.TemporaryDirectory(prefix="bots-wmi-", dir=TMP) as directory:
        db = Path(directory) / "commands.duckdb"
        bucket = "db_1534762138_1534758300_302"
        invoke(
            db,
            "--sample-files",
            "1",
            "--seed",
            history_bucket_seed(bucket),
            "--max-records",
            "165162",
        )
        with duckdb.connect(str(db)) as connection:
            rows = connection.execute(
                "SELECT pgm_base,args,session_id FROM COMMANDS WHERE record_id = ?",
                [f"botsv3_data_set.tgz:{bucket}:165162:1:1:0"],
            ).fetchall()
            assert len(rows) == 1
            basename, args, session_id = rows[0]
            assert basename == "SearchProtocolHost.exe"
            assert (
                session_id
                == "splunk-bots:MKRAEUS-L:process:3732:start:20180820100730.737247+000"
            )
            assert args[-1] == "1"
            assert args[-2] == "DownLevelDaemon"
            assert "Software\\Microsoft\\Windows Search" in args
            assert (
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)"
                in args
            )
            assert (
                connection.execute(
                    "SELECT count(*) FROM COMMANDS WHERE pgm_base = 'svchost.exe' "
                    "AND list_contains(args, '-k')"
                ).fetchall()[0][0]
                > 0
            )
