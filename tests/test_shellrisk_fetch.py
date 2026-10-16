"""Run the public fetch/ingest commands against real pinned source files.

Set SHELLRISK_FETCH_CACHE to a checkout containing fetched ShellRisk and
QuasarNix files, and SHELLRISK_UPSTREAM_ROOT to its cached upstream trajectories,
to run the full regression without downloading several GB again.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

REPO = Path(__file__).resolve().parents[1]


def copy_commands(root):
    """Copy the real entry points and helpers into an isolated dataset layout."""
    shutil.copytree(REPO / 'scripts', root / 'scripts')
    for dataset, commands in [('shellrisk-bench', ['fetch', 'build_sessions', 'ingest']),
                              ('quasarnix', ['fetch'])]:
        target = root / 'datasets' / dataset
        target.mkdir(parents=True)
        for command in commands:
            shutil.copy2(REPO / 'datasets' / dataset / command, target / command)
    return root / 'datasets' / 'shellrisk-bench'


def test_fetch_list_leaves_dataset_unprepared(tmp_path):
    """Listing downloads must work without input files or session construction."""
    root = copy_commands(tmp_path)
    result = subprocess.run([sys.executable, str(root / 'fetch')], cwd=tmp_path,
                            env=dict(os.environ, FETCH_LIST='1'),
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert 'train-00000-of-00001.parquet' in result.stdout
    assert 'X_train_malicious_cmd_orig.json' in result.stdout
    assert not (root / 'sessions.jsonl').exists()
    assert not (tmp_path / 'tmp').exists()


@pytest.mark.skipif(not (os.environ.get('SHELLRISK_FETCH_CACHE') and
                        os.environ.get('SHELLRISK_UPSTREAM_ROOT')),
                    reason='Fetch regression needs the real published and upstream caches.')
def test_fetch_then_ingest_builds_sessions(tmp_path):
    """Fetching a release without a mapping must prepare it for full ingestion."""
    from _ingest_quasarnix import FILES
    from _shellrisk_sessions import PUBLISHED_FILES

    root = copy_commands(tmp_path)
    cache = Path(os.environ['SHELLRISK_FETCH_CACHE']) / 'datasets'
    for name in [*PUBLISHED_FILES, 'SOURCE_README.md']:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(cache / 'shellrisk-bench' / name)
    for name in FILES:
        (root.parent / 'quasarnix' / name).symlink_to(cache / 'quasarnix' / name)
    (tmp_path / 'tmp').mkdir()
    (tmp_path / 'tmp' / 'shellrisk-upstream').symlink_to(
        Path(os.environ['SHELLRISK_UPSTREAM_ROOT']), target_is_directory=True)
    env = dict(os.environ, FETCH_LIST='0')
    result = subprocess.run([sys.executable, str(root / 'fetch')], cwd=tmp_path,
                            env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    db = tmp_path / 'commands.duckdb'
    result = subprocess.run([sys.executable, str(root / 'ingest'), '--db', str(db)],
                            cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT count(*), count(DISTINCT session_id) FROM SHELL_INPUTS'
                           ).fetchone() == (19699, 13137)
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (41663,)
        assert con.execute('SELECT dataset, ingested FROM INGESTED').fetchall() == [
            ('shellrisk-bench', True)]
    assert (root / 'sessions.jsonl').is_file()
    assert (root / 'sessions.manifest.json').is_file()
