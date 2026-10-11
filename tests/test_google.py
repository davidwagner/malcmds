"""Integration tests for the cookie worker using real files and subprocesses.

Browser keyring failures and Google quota responses depend on external state;
these are not simulated. Live browser and Drive checks are run separately.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "scripts"


class GoogleTests(unittest.TestCase):
    """Exercise cookie configuration without printing or transmitting secrets."""

    def setUp(self):
        """Create independent cookie-file fixtures under the repository tmp."""
        scratch = ROOT.parent / "tmp"
        scratch.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.cookies = self.base / "cookies.txt"
        self.cookies.write_text(
            "# Netscape HTTP Cookie File\n"
            ".google.com\tTRUE\t/\tTRUE\t0\tSID\tfixture-secret\n"
            ".example.com\tTRUE\t/\tTRUE\t0\tother\tunrelated-secret\n"
        )
        self.env = dict(os.environ, FETCH_GOOGLE_COOKIES=str(self.cookies))
        self.env.pop("FETCH_GOOGLE_BROWSER", None)

    def run_worker(self, *args):
        """Run the actual dependency bootstrap and worker entry point."""
        return subprocess.run(
            [sys.executable, str(ROOT / "_google.py"), *args],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_cookie_file(self):
        """Explicit exports are read without changing them or exposing values."""
        before = self.cookies.read_bytes()
        result = self.run_worker("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Google session cookies ready", result.stdout)
        self.assertNotIn("fixture-secret", result.stdout + result.stderr)
        self.assertNotIn("unrelated-secret", result.stdout + result.stderr)
        self.assertEqual(self.cookies.read_bytes(), before)

    def test_missing_and_invalid_cookie_file(self):
        """A missing or malformed explicit export never falls back silently."""
        self.cookies.unlink()
        result = self.run_worker("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cookie file", result.stderr)
        self.cookies.write_text("invalid-secret")
        result = self.run_worker("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("invalid-secret", result.stderr)

    def test_no_login_and_expired_login(self):
        """Preferences and expired login cookies are insufficient for sign-in."""
        for line in (
            ".google.com\tTRUE\t/\tTRUE\t0\tNID\tpreference\n",
            ".google.com\tTRUE\t/\tTRUE\t1\tSID\texpired\n",
            ".evilgoogle.com\tTRUE\t/\tTRUE\t0\tSID\tunrelated\n",
        ):
            with self.subTest(line=line):
                self.cookies.write_text("# Netscape HTTP Cookie File\n" + line)
                result = self.run_worker("check")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("No Google sign-in cookies", result.stderr)

    def test_curl_transfer_and_failure(self):
        """The cookie worker preserves real curl payloads and exit status."""
        source = self.base / "source.bin"
        source.write_bytes(b"download fixture")
        output = self.base / "output.bin"
        result = self.run_worker(
            "curl", "--fail", "--silent", "--output", str(output), source.as_uri()
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_bytes(), source.read_bytes())
        result = self.run_worker("curl", "--silent", (self.base / "missing").as_uri())
        self.assertEqual(result.returncode, 37)

    def test_private_filtered_jar_and_cleanup(self):
        """Real jar creation filters domains and cleans up on success and error."""
        code = """import sys
from pathlib import Path
from http.cookiejar import MozillaCookieJar
sys.path.insert(0, sys.argv[1])
from _google import google_cookies
for fail in (False, True):
    path = None
    try:
        with google_cookies() as name:
            path = Path(name)
            assert path.stat().st_mode & 0o777 == 0o600
            assert path.parent.stat().st_mode & 0o777 == 0o700
            jar = MozillaCookieJar(name)
            jar.load(ignore_discard=True)
            assert len(jar) == 1
            assert all(c.domain == '.google.com' for c in jar)
            if fail:
                raise RuntimeError('test cleanup')
    except RuntimeError:
        if not fail:
            raise
    assert path is not None and not path.parent.exists()
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(ROOT)],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_disabled_and_invalid_browser(self):
        """Explicit anonymous mode and invalid configuration are distinguished."""
        self.env.pop("FETCH_GOOGLE_COOKIES")
        self.env["FETCH_GOOGLE_BROWSER"] = "none"
        result = self.run_worker("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("disabled", result.stdout)
        self.env["FETCH_GOOGLE_BROWSER"] = "invalid"
        result = self.run_worker("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported browser", result.stderr)


if __name__ == "__main__":
    unittest.main()
