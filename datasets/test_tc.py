"""End-to-end TC checks using real entry points and public Drive files.

Run: python -m unittest discover -s datasets -p test_tc.py -v
All scratch downloads stay under tmp/. Outages and exhausted Drive quotas are
external failures, not simulated with replacement servers or mocked transfers.
"""

import csv
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COUNTS = {
    "tc-e3-cadets": 3,
    "tc-e3-fivedirections": 3,
    "tc-e3-theia": 4,
    "tc-e3-trace": 2,
    "tc-e5-cadets": 122,
    "tc-e5-fivedirections": 337,
    "tc-e5-marple": 55,
    "tc-e5-theia": 121,
    "tc-e5-trace": 555,
}


class TCIntegrationTests(unittest.TestCase):
    """Exercise inventory selection, metadata transfers, and bulk dispatch."""

    def setUp(self):
        """Copy the actual implementation into an isolated download directory."""
        scratch = ROOT.parent / "tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.datasets = self.base / "datasets"
        self.datasets.mkdir()
        for name in ("_fetch.py", "_tc.py", "_tc_manifest.tsv", "fetchall"):
            shutil.copy2(ROOT / name, self.datasets / name)
        for name in COUNTS:
            (self.datasets / name).mkdir()
            shutil.copy2(ROOT / name / "fetch", self.datasets / name / "fetch")
        self.env = dict(os.environ)
        self.env.pop("FETCH_LIST", None)

    def run_script(self, script, *args, listing=False):
        """Run an unmodified executable from outside its dataset directory."""
        env = self.env | ({"FETCH_LIST": "1"} if listing else {})
        return subprocess.run(
            [str(self.datasets / script), *args],
            cwd=self.base,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_inventory_and_bulk_selection(self):
        """All nine inventories retain every binary chunk and their support files."""
        for name, count in COUNTS.items():
            with self.subTest(dataset=name):
                result = self.run_script(name + "/fetch", listing=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                rows = [line.split("\t") for line in result.stdout.splitlines()]
                data = [row for row in rows if row[0].startswith("data/")]
                self.assertEqual(len(data), count)
                self.assertEqual(len({row[0] for row in rows}), len(rows))
                self.assertTrue(all(".bin" in row[0] for row in data))
                self.assertTrue(all(".json" not in row[0] for row in data))
                self.assertTrue(any(row[0].startswith("ground_truth/") for row in rows))
                self.assertTrue(any(row[0].endswith(".avdl") for row in rows))
                metadata = self.run_script(
                    name + "/fetch", "--metadata-only", listing=True
                )
                self.assertEqual(metadata.returncode, 0, metadata.stderr)
                self.assertNotIn("data/", metadata.stdout)
        selected = self.run_script(
            "fetchall", "tc-e3-theia", "tc-e5-marple", listing=True
        )
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertEqual(selected.stdout.count("=== tc-"), 2)
        self.assertNotIn("=== tc-e5-cadets", selected.stdout)
        default = self.run_script("fetchall", listing=True)
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertEqual(default.stdout.count("=== tc-"), 9)
        unknown = self.run_script("fetchall", "tc-nonexistent", listing=True)
        self.assertNotEqual(unknown.returncode, 0)
        self.assertNotIn("===", unknown.stdout)
        bad_option = self.run_script("tc-e3-theia/fetch", "--invalid")
        self.assertNotEqual(bad_option.returncode, 0)

    def test_bulk_reports_failures(self):
        """A missing required inventory fails each selected fetcher and is reported."""
        (self.datasets / "_tc_manifest.tsv").unlink()
        result = self.run_script(
            "fetchall", "tc-e3-theia", "tc-e5-marple", listing=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("=== tc-"), 2)
        self.assertIn("Failed datasets: tc-e3-theia, tc-e5-marple", result.stderr)

    def test_public_metadata_and_repeat(self):
        """Real Drive ground truth and schemas download and skip on a second run."""
        with (ROOT / "_tc_manifest.tsv").open() as stream:
            manifest = list(csv.DictReader(stream, delimiter="\t"))
        for name in COUNTS:
            with self.subTest(dataset=name):
                first = self.run_script(name + "/fetch", "--metadata-only")
                self.assertEqual(first.returncode, 0, first.stderr)
                dest = self.datasets / name
                self.assertFalse((dest / "data").exists())
                selected = [
                    row
                    for row in manifest
                    if row["dataset"] in (name, name.split("-")[1])
                    and not row["path"].startswith("data/")
                ]
                before = {}
                for row in selected:
                    path = dest / row["path"]
                    content = path.read_bytes()
                    self.assertEqual(len(content), int(row["size"]))
                    self.assertEqual(
                        "sha256:" + hashlib.sha256(content).hexdigest(), row["checksum"]
                    )
                    before[path] = path.stat().st_mtime_ns
                    if path.suffix == ".pdf":
                        self.assertTrue(content.startswith(b"%PDF"))
                    if path.suffix == ".avdl":
                        self.assertIn(b"record Subject", content)
                        self.assertIn(b"cmdLine", content)
                    if path.name == "bins.md5sum":
                        published = {
                            filename: "md5:" + checksum
                            for checksum, filename in (
                                line.split() for line in content.decode().splitlines()
                            )
                        }
                        pinned = {
                            Path(item["path"]).name: item["checksum"]
                            for item in manifest
                            if item["dataset"] == name
                            and item["path"].startswith("data/")
                        }
                        self.assertEqual(pinned, published)
                second = self.run_script(name + "/fetch", "--metadata-only")
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertEqual(
                    second.stdout.count("Already downloaded:"), len(selected)
                )
                self.assertEqual(before, {p: p.stat().st_mtime_ns for p in before})

    def test_real_binary_resume(self):
        """Resume a real MARPLE gzip and validate its published MD5 twice."""
        with (ROOT / "_tc_manifest.tsv").open() as stream:
            row = next(
                row
                for row in csv.DictReader(stream, delimiter="\t")
                if row["path"] == "data/ta1-marple-1-e5-official-1.bin.16.gz"
            )
        partial = self.base / "sample.bin.gz.part"
        prefix = subprocess.run(
            [
                "curl",
                "--disable",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--max-time",
                "120",
                "--range",
                "0-1048575",
                "--output",
                str(partial),
                row["url"],
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(prefix.returncode, 0, prefix.stderr)
        self.assertEqual(partial.stat().st_size, 1048576)
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); from _fetch import download; "
            "download(sys.argv[2], 'sample.bin.gz', int(sys.argv[3]), sys.argv[4])"
        )
        args = [
            sys.executable,
            "-c",
            code,
            str(ROOT),
            row["url"],
            row["size"],
            row["checksum"],
        ]
        first = subprocess.run(
            args, cwd=self.base, capture_output=True, text=True, check=False
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertFalse(partial.exists())
        path = self.base / "sample.bin.gz"
        before = path.stat().st_mtime_ns
        self.assertEqual(path.read_bytes()[:2], b"\x1f\x8b")
        second = subprocess.run(
            args, cwd=self.base, capture_output=True, text=True, check=False
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("Already downloaded:", second.stdout)
        self.assertEqual(path.stat().st_mtime_ns, before)


if __name__ == "__main__":
    unittest.main()
