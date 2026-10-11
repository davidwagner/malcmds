"""Run relocated commands from outside the repository without network downloads."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("dataset", sorted(p.parent.name for p in (REPO / "datasets").glob("*/ingest")))
def test_dataset_ingest_help(dataset, tmp_path):
    """Every launcher must find its shared imports without relying on cwd."""
    result = subprocess.run(
        [sys.executable, str(REPO / "datasets" / dataset / "ingest"), "--help"],
        check=False, cwd=tmp_path, text=True, capture_output=True,
    )
    assert result.returncode == 0, f"{dataset}/ingest cannot load relocated helpers: {result.stderr}"
    assert "--db" in result.stdout


@pytest.mark.parametrize("command", ["fetchall", "ingestall"])
def test_bulk_unknown_dataset(command, tmp_path):
    """Unknown names must still produce a useful command-line error."""
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts" / command), "missing-dataset"],
        check=False, cwd=tmp_path, text=True, capture_output=True,
    )
    assert result.returncode == 2
    assert "Unknown datasets: missing-dataset" in result.stderr


def test_bulk_fetch_inventory(tmp_path):
    """Bulk fetching must find dataset launchers and adjacent TC manifests."""
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts/fetchall"), "tc-e3-trace", "quasarnix"],
        check=False, cwd=tmp_path, env=os.environ | {"FETCH_LIST": "1"},
        text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert "=== tc-e3-trace ===" in result.stdout
    assert "=== quasarnix ===" in result.stdout
    assert "data/" in result.stdout
    assert "nl2bash.json" in result.stdout


def test_bulk_ingest_default_database(tmp_path):
    """Real ingestion must keep the default database at the repository root."""
    checkout = tmp_path / "checkout"
    shutil.copytree(REPO / "scripts", checkout / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
    dataset = checkout / "datasets/quasarnix"
    dataset.mkdir(parents=True)
    shutil.copy2(REPO / "datasets/quasarnix/ingest", dataset / "ingest")
    for split in ("train", "test"):
        for variant in ("orig", "adv"):
            (dataset / f"X_{split}_malicious_cmd_{variant}.json").write_text("[]")
    (dataset / "nl2bash.json").write_text(json.dumps(["printf hello"]))
    result = subprocess.run(
        [sys.executable, str(checkout / "scripts/ingestall"), "quasarnix"],
        check=False, cwd=tmp_path, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    database = checkout / "cmds.duckdb"
    assert database.is_file(), "Moving scripts must not move the default database"
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute("SELECT pgm,args FROM COMMANDS").fetchall() == [("printf", ["hello"])]
