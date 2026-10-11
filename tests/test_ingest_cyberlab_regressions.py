"""Real compressed inputs exercise strict parsing and explicit partial recovery."""

import gzip
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[1] / "scripts"


def run_archive(
    tmp_path, payload, *, truncate=False, salvage=False, known_name=False,
    malformed_deflate=False, limit=None,
):
    """Ingest a fixture through the real reader and database writer."""
    name = "cyberlab_2020-01-29.json.gz" if known_name else "sample.json.gz"
    archive = tmp_path / name
    data = gzip.compress(payload)
    if malformed_deflate:
        # BTYPE=3 is reserved and must produce a native zlib decoding error.
        data = data[:10] + b"\x07" + data[-8:]
    archive.write_bytes(data[:-8] if truncate else data)
    driver = tmp_path / "driver.py"
    reader = (
        "yield from cyberlab(root, options)"
        if known_name
        else f"for i, row in enumerate(gzip_json_items(root / {name!r}, allow_truncated={salvage!r})):\n        yield Command('echo', [row['value']], str(i))"
    )
    driver.write_text(
        f"import sys\nfrom pathlib import Path\nsys.path.insert(0, {str(ROOT)!r})\n"
        "from _ingest import Command, run\n"
        "from _ingest_misc import cyberlab, gzip_json_items\n"
        f"def records(root, options):\n    {reader}\n"
        "run(Path(__file__).parent, records)\n"
    )
    database = tmp_path / "commands.duckdb"
    command = [sys.executable, str(driver), "--db", str(database)]
    if limit is not None:
        command.extend(["--limit", str(limit)])
    result = subprocess.run(
        command,
        capture_output=True, text=True, timeout=60, check=False,
    )
    return result, database, archive


@pytest.mark.parametrize(
    "truncate,salvage,incomplete_json",
    [(False, False, False), (True, True, True), (True, True, False)],
)
def test_complete_records_survive(tmp_path, truncate, salvage, incomplete_json):
    """Recovery keeps complete objects including those in the final read."""
    payload = b'[{"value":"first"},{"value":"last"}'
    payload += b',{"value":"unfinished' if incomplete_json else b']'
    result, database, archive = run_archive(
        tmp_path, payload, truncate=truncate, salvage=salvage
    )
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute("SELECT args FROM COMMANDS ORDER BY record_id").fetchall() == [(["first"],), (["last"],)]
    if truncate:
        assert archive.name in result.stderr and "incomplete" in result.stderr.lower()


@pytest.mark.parametrize("payload,truncate,salvage,known_name", [
    (b'[{"value":"complete"},{"value":"unfinished', True, False, False),
    (b'[{"value":"complete"},invalid]', False, True, False),
    (b'[{"value":"complete"}', False, False, False),
    (b'[{"session": [{"eventid": "cowrie.command.input", "input": "echo complete"}]}', True, False, True),
    (b'[{"value":"complete"}', False, True, False),
])
def test_unknown_corruption_fails_with_filename(tmp_path, payload, truncate, salvage, known_name):
    """Neither opt-in recovery nor the known basename excuses other corruption."""
    result, _, archive = run_archive(tmp_path, payload, truncate=truncate, salvage=salvage, known_name=known_name)
    assert result.returncode != 0
    assert archive.name in result.stderr


def test_record_limit_does_not_pull_next_record(tmp_path):
    """A streaming parser must not read the next malformed record after a limit."""
    driver = tmp_path / "limited.py"
    driver.write_text(
        f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n"
        "import io, ijson\nfrom types import SimpleNamespace\n"
        "from _ingest_misc import limited\n"
        "stream = io.BytesIO(b'[1,' + b' ' * 131072 + b'invalid]')\n"
        "assert list(limited(ijson.items(stream, 'item'), SimpleNamespace(max_records=1))) == [1]\n"
        "stream = io.BytesIO(b'invalid')\n"
        "assert list(limited(ijson.items(stream, 'item'), SimpleNamespace(max_records=0))) == []\n"
    )
    result = subprocess.run([sys.executable, str(driver)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_published_truncated_archive(tmp_path):
    """Read the actual damaged publisher archive to EOF without losing objects."""
    archive = ROOT.parent / "datasets" / "cyberlab" / "cyberlab_2020-01-29.json.gz"
    if not archive.exists():
        pytest.skip("Publisher data not downloaded")
    driver = tmp_path / "publisher.py"
    driver.write_text(
        f"import sys\nfrom pathlib import Path\nsys.path.insert(0, {str(ROOT)!r})\n"
        "from _ingest_misc import gzip_json_items, known_truncated_cyberlab\n"
        f"path = Path({str(archive)!r})\n"
        "assert known_truncated_cyberlab(path)\n"
        "count = 0\n"
        "for row in gzip_json_items(path, allow_truncated=True):\n"
        "    count += 1\n    last = next(iter(row))\n"
        "assert count == 89426, count\n"
        "assert last == '340b9d085b1a', last\n"
        # An equal-size file with altered contents must never inherit recovery.
        f"other = Path({str(tmp_path)!r}) / path.name\n"
        "with path.open('rb') as source, other.open('wb') as target:\n"
        "    while chunk := source.read(1024 * 1024):\n"
        "        target.write(chunk)\n"
        "with other.open('r+b') as target:\n"
        "    target.seek(-1, 2)\n    original = target.read(1)\n"
        "    target.seek(-1, 2)\n    target.write(bytes([original[0] ^ 1]))\n"
        "assert not known_truncated_cyberlab(other)\n"
    )
    result = subprocess.run(
        [sys.executable, str(driver)], capture_output=True, text=True, timeout=90, check=False
    )
    assert result.returncode == 0, result.stderr
    assert archive.name in result.stderr and "incomplete" in result.stderr.lower()


def test_malformed_deflate_has_filename(tmp_path):
    """A corrupt deflate block fails with the archive path even in recovery mode."""
    result, _, archive = run_archive(
        tmp_path, b'[]', malformed_deflate=True, salvage=True
    )
    assert result.returncode != 0
    assert f"Cannot read {archive}" in result.stderr
    assert "invalid block type" in result.stderr


def test_empty_array(tmp_path):
    """An empty input completes with an empty real database."""
    result, database, _ = run_archive(tmp_path, b'[]')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute("SELECT count(*) FROM COMMANDS").fetchone() == (0,)


def test_short_command_limit_closes_reader(tmp_path):
    """Stopping after one command closes a suspended reader before damaged EOF."""
    payload = b'[{"value":"first"},' + b' ' * 131072 + b'{"value":"unfinished'
    result, database, _ = run_archive(tmp_path, payload, truncate=True, limit=1)
    assert result.returncode == 0, result.stderr
    assert "WARNING" not in result.stderr and "Traceback" not in result.stderr
    assert "Exception ignored" not in result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute("SELECT args FROM COMMANDS").fetchall() == [(["first"],)]


def test_cyberlab_continues_across_files(tmp_path):
    """The dataset reader finishes each array and continues to the next archive."""
    payload = b'[{"session":[{"eventid":"cowrie.command.input","input":"echo ok"}]}]'
    (tmp_path / 'zz-next.json.gz').write_bytes(gzip.compress(payload))
    result, database, _ = run_archive(tmp_path, payload, known_name=True)
    assert result.returncode == 0, result.stderr
    assert 'WARNING' not in result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT pgm,args FROM COMMANDS ORDER BY record_id').fetchall() == [('echo', ['ok']), ('echo', ['ok'])]
