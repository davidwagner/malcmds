"""Shared download support. Requires Python 3.10+ and curl; never extracts data."""

import hashlib
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import quote


def get_json(url):
    """Read public API metadata with bounded retries and no interactive login."""
    result = subprocess.run(
        [
            "curl",
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--retry",
            "3",
            "--connect-timeout",
            "30",
            "--max-time",
            "180",
            url,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def write_json(path, data):
    """Replace metadata atomically so interrupted writes cannot poison reruns."""
    path.parent.mkdir(parents=True, exist_ok=True)
    part = path.with_name(path.name + ".part")
    part.write_text(json.dumps(data, indent=2) + "\n")
    part.replace(path)


def cached_json(url, name):
    """Cache source metadata locally so repeat runs use the same file inventory."""
    path = Path(".fetch-metadata") / name
    if path.exists():
        return json.loads(path.read_text())
    data = get_json(url)
    write_json(path, data)
    return data


def digest(path, algorithm):
    """Hash a file in bounded memory, including Git's blob header when requested."""
    value = hashlib.new("sha1" if algorithm == "git" else algorithm)
    if algorithm == "git":
        value.update(f"blob {path.stat().st_size}\0".encode())
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def valid(path, size, checksum):
    """Check a completed file against the available publisher metadata."""
    if not path.is_file() or (size is not None and path.stat().st_size != size):
        return False
    if checksum:
        algorithm, expected = checksum.split(":", 1)
        return digest(path, algorithm) == expected
    return size is not None


def html_error(part, destination):
    """Recognize HTML error responses without reading large payloads into memory."""
    if destination.suffix.lower() in {".html", ".htm"} or not part.exists():
        return None
    with part.open("rb") as stream:
        prefix = stream.read(8192).lstrip().lower()
    if not prefix.startswith((b"<!doctype html", b"<html")):
        return None
    if b"quota exceeded" in prefix:
        return (
            f"Google Drive download quota exceeded for {destination}. "
            "Retry later (Google advises allowing up to 24 hours); "
            "the error page was saved as .part.bad."
        )
    return f"Received an HTML page instead of {destination}; saved as .part.bad"


def download(url, relative_dest, size=None, checksum=None):
    """Fetch atomically, resume partial files, and skip verified completed files.

    FETCH_LIST=1 prints the selection without transferring payloads. Receipts
    avoid rehashing unchanged large files. Unknown-size files are accepted only
    after curl reports success; no dataset contents are executed or extracted.
    """
    path = Path(relative_dest)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Download destination must stay in the dataset: {path}")
    if os.environ.get("FETCH_LIST") == "1":
        print(f"{path}\t{size if size is not None else '?'}\t{url}", flush=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    receipt = path.with_name(path.name + ".download.json")
    identity = {"url": url, "size": size, "checksum": checksum}
    if path.exists():
        stat = path.stat()
        fingerprint = {"bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}
        try:
            saved = json.loads(receipt.read_text()) if receipt.exists() else None
        except json.JSONDecodeError:
            saved = None
        if saved == identity | fingerprint:
            print(f"Already downloaded: {path}", flush=True)
            return
        if valid(path, size, checksum):
            write_json(receipt, identity | fingerprint)
            print(f"Already downloaded: {path}", flush=True)
            return
    part = path.with_name(path.name + ".part")
    if path.exists():
        # An incomplete final file may have been supplied by an earlier downloader.
        if size is not None and path.stat().st_size < size and not part.exists():
            path.replace(part)
        else:
            raise RuntimeError(f"Existing file failed verification; move it aside: {path}")
    if html_error(part, path):
        # Older versions left HTTP-success error pages as resumable payloads.
        part.replace(part.with_name(part.name + ".bad"))
    print(f"Downloading: {path}", flush=True)
    if not valid(part, size, checksum):
        command = [
            "curl",
            "--disable",
            "--fail",
            "--location",
            "--show-error",
            "--silent",
            "--globoff",
            "--retry",
            "4",
            "--connect-timeout",
            "30",
            "--speed-limit",
            "1",
            "--speed-time",
            "120",
            "--continue-at",
            "-",
            "--output",
            str(part),
            url,
        ]
        result = subprocess.run(command, check=False)
        if result.returncode == 33:  # Server does not support range requests.
            part.unlink(missing_ok=True)
            result = subprocess.run(command, check=False)
        result.check_returncode()
    error = html_error(part, path)
    if error:
        part.replace(part.with_name(part.name + ".bad"))
        raise RuntimeError(error)
    if size is not None and part.stat().st_size != size:
        raise RuntimeError(f"Size mismatch for {part}: expected {size}, got {part.stat().st_size}")
    if checksum:
        algorithm, expected = checksum.split(":", 1)
        if digest(part, algorithm) != expected:
            # A complete but corrupt partial cannot be repaired by appending bytes.
            part.replace(part.with_name(part.name + ".bad"))
            raise RuntimeError(f"Checksum mismatch for {path}; saved as .part.bad; rerun to retry")
    part.replace(path)
    stat = path.stat()
    write_json(receipt, identity | {"bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns})


def zenodo(record, predicate=None):
    """Download selected files from a fixed Zenodo record with published hashes."""
    data = cached_json(f"https://zenodo.org/api/records/{record}", f"zenodo-{record}.json")
    selected = [f for f in data["files"] if predicate is None or predicate(f["key"])]
    if not selected:
        raise RuntimeError(f"No matching files in Zenodo record {record}")
    for item in selected:
        download(item["links"]["self"], item["key"], item["size"], item["checksum"])


def github(repo, predicate, ref=None):
    """Download selected GitHub blobs, resolving LFS pointers to checked payloads."""
    ref = ref or "HEAD"
    commit = cached_json(
        f"https://api.github.com/repos/{repo}/commits/{quote(ref, safe='')}",
        f"commit-{repo.replace('/', '-')}-{ref.replace('/', '-')}.json",
    )["sha"]
    tree = cached_json(
        f"https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1",
        f"github-{repo.replace('/', '-')}-{ref.replace('/', '-')}.json",
    )
    if tree.get("truncated"):
        raise RuntimeError(f"GitHub truncated the file inventory for {repo}")
    selected = [f for f in tree["tree"] if f["type"] == "blob" and predicate(f["path"])]
    if not selected:
        raise RuntimeError(f"No matching files in {repo}")
    for item in selected:
        name = item["path"]
        raw = f"https://raw.githubusercontent.com/{repo}/{commit}/{quote(name)}"
        # LFS pointers are tiny Git blobs. Only inspect small files, not payloads.
        checksum = "git:" + item["sha"]
        size = item["size"]
        if size <= 1024:
            pointer_path = Path(".fetch-metadata") / ("blob-" + item["sha"])
            if not pointer_path.exists():
                result = subprocess.run(
                    [
                        "curl",
                        "--disable",
                        "--fail",
                        "--silent",
                        "--show-error",
                        "--location",
                        "--retry",
                        "3",
                        "--max-time",
                        "180",
                        raw,
                    ],
                    check=True,
                    capture_output=True,
                )
                pointer_path.write_bytes(result.stdout)
            content = pointer_path.read_text(errors="replace")
            if content.startswith("version https://git-lfs.github.com/spec/v1\n"):
                fields = dict(line.split(" ", 1) for line in content.splitlines())
                raw = f"https://media.githubusercontent.com/media/{repo}/{commit}/{quote(name)}"
                checksum, size = fields["oid"], int(fields["size"])
        download(raw, "source/" + name, size, checksum)


def mendeley(dataset, version, predicate=None):
    """Download a versioned Mendeley file listing with publisher SHA-256 checksums."""
    data = cached_json(
        f"https://data.mendeley.com/public-api/datasets/{dataset}/files?folder_id=root&version={version}",
        f"mendeley-{dataset}-{version}.json",
    )
    selected = [f for f in data if predicate is None or predicate(f["filename"])]
    if not selected:
        raise RuntimeError(f"No matching files in Mendeley dataset {dataset}")
    for item in selected:
        info = item["content_details"]
        download(
            info["download_url"],
            "source/" + item["filename"],
            info["size"],
            "sha256:" + info["sha256_hash"],
        )
