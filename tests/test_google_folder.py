"""End-to-end regressions for OpTC's Google folder download path.

Run with tmp/google-venv/bin/python -m unittest discover -s tests
-p test_google_folder.py -v. Tests use real files, gdown, and Google responses.
Transient HTML, quotas, connection failures during a transfer, and recovery on a
second request depend on Google; those branches cannot be forced without doubles.
"""

import csv
import gzip
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1] / "scripts"


class GoogleFolderTests(unittest.TestCase):
    """Exercise the production file helper and folder worker in subprocesses."""

    def setUp(self):
        """Keep every test's downloads under the repository scratch directory."""
        scratch = ROOT.parent / "tmp"
        scratch.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)

    def download(self, file_id, output, **environment):
        """Run the real helper without browser credentials or a substitute server."""
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from _google import download_drive_file; "
            "download_drive_file(sys.argv[2], sys.argv[3], None)"
        )
        return subprocess.run(
            [sys.executable, "-c", code, str(ROOT), file_id, str(output)],
            env=dict(os.environ, **environment), capture_output=True, text=True,
            timeout=120, check=False,
        )

    def test_completed_file_skips_google(self):
        """An existing file succeeds even with an invalid ID and no network route."""
        output = self.base / "complete.json.gz"
        content = gzip.compress(b'{"event":"previously downloaded"}\n')
        output.write_bytes(content)
        before = output.stat().st_mtime_ns
        result = self.download(
            "nonexistent-regression-file", output,
            HTTPS_PROXY="http://127.0.0.1:1", NO_PROXY="",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Already downloaded", result.stdout)
        self.assertEqual(output.read_bytes(), content)
        self.assertEqual(output.stat().st_mtime_ns, before)

    def test_missing_file_reports_response_and_preserves_partial(self):
        """A real Google error explains the failure and preserves gdown's partial."""
        output = self.base / "missing.json.gz"
        partial = self.base / "missing.json.gzprevious.part"
        partial.write_bytes(b"existing partial payload")
        result = self.download("nonexistent-regression-file", output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Response saved at", result.stderr)
        self.assertIn("HTTP 404", result.stderr)
        self.assertNotIn("Cannot retrieve the public link", result.stderr)
        self.assertTrue(Path(str(output) + ".part.bad").is_file())
        self.assertEqual(partial.read_bytes(), b"existing partial payload")
        self.assertFalse(output.exists())

    def test_real_file_resumes_gdown_partial(self):
        """A published small PDF resumes using gdown's existing partial naming."""
        with (ROOT / "_tc_manifest.tsv").open() as stream:
            row = next(row for row in csv.DictReader(stream, delimiter="\t")
                       if row["dataset"] == "e3" and row["path"] == "schema/cdm.pdf")
        file_id = parse_qs(urlparse(row["url"]).query)["id"][0]
        source = self.base / "source.pdf"
        result = self.download(file_id, source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.stat().st_size, int(row["size"]))
        output = self.base / "nested" / "resumed.pdf"
        output.parent.mkdir()
        partial = output.with_name(output.name + "previous.part")
        partial.write_bytes(source.read_bytes()[:32])
        result = self.download(file_id, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(partial.exists())
        self.assertEqual(output.read_bytes(), source.read_bytes())

    def test_optc_folder_skips_completed_files(self):
        """The actual OpTC subfolder listing feeds the helper's completed-file path."""
        names = (
            "AIA-501-525.ecar-2019-11-16T23-22-29.234.json.gz",
            "AIA-501-525.ecar-last.json.gz",
        )
        content = gzip.compress(b'{"event":"test completed file"}\n')
        for name in names:
            (self.base / name).write_bytes(content)
        result = subprocess.run(
            [sys.executable, str(ROOT / "_google.py"), "--worker", "folder",
             "1XPdjfZXXAIarVH6kh5YUM8s__Ml_VxNr", str(self.base)],
            env=dict(os.environ, FETCH_GOOGLE_BROWSER="none", FETCH_GOOGLE_COOKIES=""),
            capture_output=True, text=True, timeout=120, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("Already downloaded:"), len(names))
        for name in names:
            self.assertEqual((self.base / name).read_bytes(), content)

    def test_reported_files_return_gzip(self):
        """The reported files resolve to actual gzip bytes through our resolver."""
        for file_id in (
            "1HD3pjUoA5388fVVee5zTGGWRW4sIyeZf",
            "1LapnEjF0W47nCrYlFFefqmn6Vua_IiiG",
            "17R7mWyOzl-RdGZLX5JhIvBjKgarO7CaT",
        ):
            with self.subTest(file_id=file_id):
                output = self.base / (file_id + ".gz")
                result = subprocess.run(
                    [sys.executable, str(ROOT / "_google.py"), "--worker", "curl",
                     "--fail", "--silent", "--show-error", "--location",
                     "--range", "0-31", "--max-filesize", "65536",
                     "--max-time", "90", "--output", str(output),
                     "https://drive.google.com/uc?export=download&id=" + file_id],
                    capture_output=True, text=True, timeout=120, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(output.read_bytes()), 32)
                self.assertEqual(output.read_bytes()[:2], b"\x1f\x8b")


if __name__ == "__main__":
    unittest.main()
