"""Integration tests using real curl/file transfers and public source APIs.

Run: python -m unittest discover -s datasets -p test_fetch.py -v
Network interruption, disk exhaustion, publisher outages, and large private-host
quota failures are not simulated. No mocks or replacement downloaders are used.
Temporary artifacts stay in the repository's tmp directory.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class DownloadTests(unittest.TestCase):
    """Exercise complete transfers and repeat runs through a separate process."""

    def setUp(self):
        """Allocate independent source and destination directories."""
        scratch = ROOT.parent / "tmp"
        scratch.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.source = self.base / "original.bin"
        self.source.write_bytes(bytes(range(256)) * 100)
        self.output = self.base / "downloads"
        self.output.mkdir()
        self.checksum = "sha256:" + hashlib.sha256(self.source.read_bytes()).hexdigest()

    def run_download(self, **kwargs):
        """Invoke the actual helper and curl in a subprocess."""
        args = {
            "url": self.source.as_uri(),
            "relative_dest": "data.bin",
            "size": self.source.stat().st_size,
            "checksum": self.checksum,
        } | kwargs
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); from _fetch import download; download(**"
            + repr(args)
            + ")"
        )
        return subprocess.run(
            [sys.executable, "-c", code, str(ROOT)],
            cwd=self.output,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_download_and_skip(self):
        """Completed receipts preserve file contents and modification time."""
        self.assertEqual(self.run_download().returncode, 0)
        dest = self.output / "data.bin"
        before = dest.stat().st_mtime_ns
        self.assertEqual(dest.read_bytes(), self.source.read_bytes())
        result = self.run_download()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Already downloaded", result.stdout)
        self.assertEqual(dest.stat().st_mtime_ns, before)
        (self.output / "data.bin.download.json").unlink()
        self.assertEqual(self.run_download().returncode, 0)
        self.assertEqual(dest.stat().st_mtime_ns, before)

    def test_partial_and_completed_partial(self):
        """A partial transfer resumes, including completion before final rename."""
        part = self.output / "data.bin.part"
        part.write_bytes(self.source.read_bytes()[:100])
        result = self.run_download()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.output / "data.bin").read_bytes(), self.source.read_bytes())
        (self.output / "data.bin").replace(part)
        result = self.run_download()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(part.exists())

    def test_truncated_final(self):
        """An externally truncated final file is completed and checked."""
        (self.output / "data.bin").write_bytes(self.source.read_bytes()[:100])
        result = self.run_download()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.output / "data.bin").read_bytes(), self.source.read_bytes())

    def test_wrong_checksum(self):
        """A checksum mismatch cannot leave a completed payload or receipt."""
        result = self.run_download(checksum="sha256:" + "0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Checksum mismatch", result.stderr)
        self.assertFalse((self.output / "data.bin").exists())
        self.assertTrue((self.output / "data.bin.part.bad").exists())
        self.assertEqual(self.run_download().returncode, 0)

    def test_corrupt_completed_partial(self):
        """A corrupt full-length partial is rejected and can be retried."""
        part = self.output / "data.bin.part"
        part.write_bytes(b"x" * self.source.stat().st_size)
        result = self.run_download()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Checksum mismatch", result.stderr)
        self.assertEqual(self.run_download().returncode, 0)

    def test_wrong_size_and_path(self):
        """Unexpected size and paths outside the destination fail explicitly."""
        result = self.run_download(size=self.source.stat().st_size + 1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Size mismatch", result.stderr)
        result = self.run_download(relative_dest="../outside.bin")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "outside.bin").exists())

    def test_html_rejected_and_unknown_size_skip(self):
        """An HTML login/error response is rejected; un-sized real data can repeat."""
        self.source.write_bytes(b"<!doctype html><html>sign in</html>")
        result = self.run_download(size=None, checksum=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTML page", result.stderr)
        self.source.write_bytes(b"actual data\n")
        self.assertEqual(self.run_download(size=None, checksum=None).returncode, 0)
        self.assertIn("Already downloaded", self.run_download(size=None, checksum=None).stdout)

    def test_interrupted_receipt(self):
        """A damaged completion receipt does not force manual intervention."""
        self.assertEqual(self.run_download().returncode, 0)
        receipt = self.output / "data.bin.download.json"
        receipt.write_text("{")
        result = self.run_download()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Already downloaded", result.stdout)

    def test_public_github_lfs(self):
        """GitHub LFS pointers resolve to the actual checked log payload."""
        code = """import sys
sys.path.insert(0, sys.argv[1])
from _fetch import github
def selected(path):
    return path == ('datasets/attack_techniques/T1030/'
                    'linux_auditd_split_b_exec/auditd_execve_split.log')
github('splunk/attack_data', selected, 'a28608b53aa3d8222052e8f3ada59e2d9a4adfff')
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(ROOT)],
            cwd=self.output,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = next(self.output.rglob("auditd_execve_split.log")).read_bytes()
        self.assertEqual(len(data), 229)
        self.assertIn(b"type=EXECVE", data)
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            "6594f2541ea8143fb7f11b1f38496888f7603d2ba91002a40914d1e4a9977e05",
        )

    def test_public_zenodo_fetcher(self):
        """The real KYPO entry point downloads a valid archive and skips it later."""
        target = self.base / "datasets"
        (target / "kypo").mkdir(parents=True)
        shutil.copy2(ROOT / "_fetch.py", target)
        shutil.copy2(ROOT / "kypo" / "fetch", target / "kypo")
        env = dict(os.environ)
        env.pop("FETCH_LIST", None)
        script = target / "kypo" / "fetch"
        first = subprocess.run(
            [str(script)], cwd=self.base, env=env, capture_output=True, text=True
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        import zipfile

        archive = next((target / "kypo").glob("*.zip"))
        self.assertTrue(zipfile.is_zipfile(archive))
        before = archive.stat().st_mtime_ns
        second = subprocess.run(
            [str(script)], cwd=self.base, env=env, capture_output=True, text=True
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("Already downloaded", second.stdout)
        self.assertEqual(archive.stat().st_mtime_ns, before)


if __name__ == "__main__":
    unittest.main()
