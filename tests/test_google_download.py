"""Live regressions for Google's large-file confirmation using bounded curl ranges.

Run explicitly: python -m unittest discover -s tests -p test_google_download.py -v
Requires the configured Google browser session and network access. Quota, login,
HTTP outages, and malformed Google pages cannot be forced without test doubles;
those paths are checked against saved real responses in test_fetch.py instead.
"""

import csv
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "scripts"


class GoogleDownloadTests(unittest.TestCase):
    """Exercise the real cookie worker and Google confirmation service."""

    def test_large_file_confirmation(self):
        """Previously failing files return gzip bytes after automatic confirmation."""
        names = {
            "ta1-trace-e3-official.bin.tar.gz",
            "ta1-cadets-1-e5-official-2.bin.119.gz",
            "ta1-trace-1-e5-official-1.bin.1.gz",
            "ta1-theia-1-e5-official-1.bin.1.gz",
            "ta1-fivedirections-1-e5-official-1.bin.10.gz",
        }
        with (ROOT / "_tc_manifest.tsv").open() as stream:
            rows = [row for row in csv.DictReader(stream, delimiter="\t")
                    if Path(row["path"]).name in names]
        self.assertEqual(len(rows), len(names))
        scratch = ROOT.parent / "tmp"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            for row in rows:
                with self.subTest(dataset=row["dataset"]):
                    output = Path(directory) / "sample.gz"
                    result = subprocess.run(
                        [sys.executable, str(ROOT / "_google.py"), "curl",
                         "--fail", "--silent", "--show-error", "--location",
                         "--range", "0-31", "--max-filesize", "65536",
                         "--max-time", "90", "--output", str(output), row["url"]],
                        env=dict(os.environ), capture_output=True, text=True,
                        timeout=180, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    data = output.read_bytes()
                    self.assertEqual(len(data), 32)
                    self.assertEqual(data[:2], b"\x1f\x8b", result.stderr)

    def test_inaccessible_file_preserves_partial(self):
        """A real Drive error leaves existing data intact and names the saved report."""
        scratch = ROOT.parent / "tmp"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            part = Path(directory) / "sample.gz.part"
            content = b"existing partial payload"
            part.write_bytes(content)
            url = "https://drive.google.com/uc?export=download&id=nonexistent-regression-file"
            result = subprocess.run(
                [sys.executable, str(ROOT / "_google.py"), "curl",
                 "--fail", "--silent", "--location", "--continue-at", "-",
                 "--max-filesize", "65536", "--max-time", "90",
                 "--output", str(part), url],
                capture_output=True, text=True, timeout=180, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(part.read_bytes(), content)
            self.assertIn("signed-in browser", result.stderr)
            self.assertIn("Response saved at", result.stderr)
            self.assertTrue(part.with_name(part.name + ".bad").is_file())
            self.assertNotIn("Traceback", result.stderr)

    def test_verified_metadata_resume(self):
        """The shared downloader resumes real bytes, verifies hashes, and skips repeats."""
        with (ROOT / "_tc_manifest.tsv").open() as stream:
            row = next(row for row in csv.DictReader(stream, delimiter="\t")
                       if row["dataset"] == "e3" and row["path"] == "schema/cdm.pdf")
        scratch = ROOT.parent / "tmp"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            part = Path(directory) / "sample.pdf.part"
            result = subprocess.run(
                [sys.executable, str(ROOT / "_google.py"), "curl",
                 "--fail", "--silent", "--location", "--range", "0-31",
                 "--max-filesize", "65536", "--max-time", "90",
                 "--output", str(part), row["url"]],
                capture_output=True, text=True, timeout=180, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(part.stat().st_size, 32)
            self.assertTrue(part.read_bytes().startswith(b"%PDF"))
            code = (
                "import sys; sys.path.insert(0, sys.argv[1]); from _fetch import download; "
                "download(sys.argv[2], 'sample.pdf', int(sys.argv[3]), sys.argv[4])"
            )
            args = [sys.executable, "-c", code, str(ROOT), row["url"],
                    row["size"], row["checksum"]]
            first = subprocess.run(args, cwd=directory, capture_output=True,
                                   text=True, timeout=180, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertFalse(part.exists())
            output = Path(directory) / "sample.pdf"
            self.assertEqual(output.stat().st_size, int(row["size"]))
            before = output.stat().st_mtime_ns
            second = subprocess.run(args, cwd=directory, capture_output=True,
                                    text=True, timeout=180, check=False)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("Already downloaded", second.stdout)
            self.assertEqual(output.stat().st_mtime_ns, before)


if __name__ == "__main__":
    unittest.main()
