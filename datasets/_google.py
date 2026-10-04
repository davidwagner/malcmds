"""Google browser sessions for fetchers; no cookies are kept in source or caches.

By default try Firefox, Chrome, Chromium, then other supported browsers.
FETCH_GOOGLE_BROWSER=firefox selects a browser (none opts out).
FETCH_GOOGLE_COOKIES=/absolute/path/cookies.txt uses a Netscape export instead.
Run `python datasets/_google.py check` to check local cookie access.
An unlocked desktop keyring may be needed for Chromium browsers. Sign in to
Google in the chosen browser if automatic extraction cannot find a session.
Cookies help with anonymous throttling; Google may still enforce file quotas.
"""

import contextlib
import fcntl
import io
import os
import subprocess
import sys
import tempfile
import venv
import warnings
from http.cookiejar import MozillaCookieJar
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BROWSERS = ("firefox", "chrome", "chromium", "brave", "edge", "vivaldi", "opera", "safari", "whale")
HELP = (
    "Sign in to Google in your browser and unlock its desktop keyring, then retry. "
    "Set FETCH_GOOGLE_BROWSER=firefox (or chrome/chromium), or set "
    "FETCH_GOOGLE_COOKIES to an absolute path to a Netscape cookie export. "
    "FETCH_GOOGLE_BROWSER=none explicitly allows anonymous downloads."
)


def run_google(arguments):
    """Run a cookie-aware worker in a lazily installed, pinned environment."""
    scratch = ROOT / "tmp"
    scratch.mkdir(exist_ok=True)
    environment = scratch / "google-venv"
    python = environment / "bin/python"
    # Multiple fetch commands may start simultaneously.
    with (scratch / "google-install.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ready = environment / "gdown-6.4.1-secretstorage.ready"
        if not ready.exists():
            if not python.exists():
                venv.create(environment, with_pip=True)
            subprocess.run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "--disable-pip-version-check",
                    "install",
                    "--no-input",
                    "gdown[secretstorage]==6.4.1",
                ],
                check=True,
            )
            ready.touch()
    return subprocess.run(
        [str(python), "-u", str(Path(__file__).resolve()), "--worker", *arguments],
        check=False,
    )


def read_google_cookies(source):
    """Load unexpired Google cookies, including browser-export session cookies."""
    jar = MozillaCookieJar(str(source))
    try:
        # Malformed Netscape files can emit warnings containing cookie values.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            jar.load(ignore_discard=True, ignore_expires=True)
    except (OSError, ValueError):
        raise RuntimeError("Cannot read the Netscape cookie file. " + HELP) from None
    selected = MozillaCookieJar()
    for cookie in jar:
        domain = cookie.domain.lstrip(".")
        if domain != "google.com" and not domain.endswith(".google.com"):
            continue
        if cookie.expires == 0:
            cookie.expires = None
            cookie.discard = True
        if not cookie.is_expired():
            selected.set_cookie(cookie)
    if not any(c.name in {"SID", "__Secure-1PSID", "__Secure-3PSID"} for c in selected):
        raise RuntimeError("No Google sign-in cookies found. " + HELP)
    return selected


@contextlib.contextmanager
def google_cookies():
    """Yield a private temporary Google-only cookie jar, then remove it."""
    source = os.environ.get("FETCH_GOOGLE_COOKIES")
    browser = os.environ.get("FETCH_GOOGLE_BROWSER", "auto")
    if not source and browser == "none":
        yield None
        return
    if not source and browser not in (*BROWSERS, "auto"):
        raise RuntimeError("Unsupported browser. " + HELP)
    scratch = ROOT / "tmp"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="google-cookies-", dir=scratch) as directory:
        # The browser extractor also copies its database; keep that copy private.
        previous = tempfile.tempdir
        tempfile.tempdir = directory
        try:
            path = Path(directory) / "cookies.txt"
            if source:
                jar = read_google_cookies(Path(source).expanduser())
            else:
                from gdown.download import _import_cookies_from_browser

                jar = None
                for candidate in BROWSERS if browser == "auto" else (browser,):
                    path.unlink(missing_ok=True)
                    try:
                        # Report browser names, never library exception text or values.
                        with (
                            contextlib.redirect_stderr(io.StringIO()),
                            contextlib.redirect_stdout(io.StringIO()),
                        ):
                            _import_cookies_from_browser(browser=candidate, cookies_file=str(path))
                        jar = read_google_cookies(path)
                    except Exception:
                        continue
                    print(f"Using Google session from {candidate}", file=sys.stderr)
                    break
                if jar is None:
                    raise RuntimeError("Cannot read Google sign-in cookies from a browser. " + HELP)
            path.touch(mode=0o600, exist_ok=True)
            path.chmod(0o600)
            jar.save(str(path), ignore_discard=True)
            yield str(path)
        finally:
            tempfile.tempdir = previous


def main(arguments):
    """Check cookie access, run curl, or download/list an OpTC Drive folder."""
    if not arguments or arguments[0] not in {"check", "curl", "folder", "list-folder"}:
        raise RuntimeError(
            "Usage: _google.py check | curl ARGS... | folder ID OUTPUT | list-folder ID"
        )
    with google_cookies() as cookies:
        if arguments[0] == "check":
            print("Google session cookies ready" if cookies else "Google cookies disabled")
            return 0
        if arguments[0] == "curl":
            options = ["--cookie", cookies] if cookies else []
            # --disable must remain curl's first argument; retain its exit code.
            return subprocess.run(
                ["curl", "--disable", *options, *arguments[1:]], check=False
            ).returncode
        import gdown

        files = gdown.download_folder(
            id=arguments[1],
            output=arguments[2] if len(arguments) > 2 else "ecar",
            resume=True,
            use_cookies=bool(cookies),
            cookies_file=cookies,
            timeout=60,
            retries=4,
            skip_download=arguments[0] == "list-folder",
        )
        if not files:
            raise RuntimeError("Drive returned no files")
        if arguments[0] == "list-folder":
            print(f"Drive folder accessible: {len(files)} files")
        return 0


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--worker"]:
            sys.exit(main(sys.argv[2:]))
        sys.exit(run_google(sys.argv[1:]).returncode)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        sys.exit(1)
