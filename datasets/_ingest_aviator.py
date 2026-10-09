"""Read independent AVIATOR exports concurrently, preserving source order."""

import multiprocessing
import codecs
import re
import tarfile
import tempfile
import zipfile
from collections import deque
from multiprocessing.pool import AsyncResult
from pathlib import Path
from types import SimpleNamespace

import pyarrow as pa
from _ingest import SCHEMA, command_table, select_files
from _ingest_windows import Budget, aviator_priority, parse_log

ARCHIVE = "10.35097-8s5b0u5yqgfs2y0d.tar"


def export_encoding(stream):
    """Select AVIATOR's declared codec or validated UTF-8/Windows export codec."""
    prefix = stream.read(4096)
    stream.seek(0)
    if prefix.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if prefix.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    declaration = re.match(br'''\s*<\?xml\b[^>]*encoding=["']([^"']+)["']''', prefix)
    if declaration:
        encoding = codecs.lookup(declaration[1].decode("ascii")).name
        if encoding not in {"utf-8", "utf-16", "utf-16-le", "utf-16-be", "cp1252", "iso8859-1", "ascii"}:
            raise ValueError(f"Unsupported AVIATOR XML encoding: {encoding}")
        return encoding
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        while chunk := stream.read(1024 * 1024):
            decoder.decode(chunk)
        decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        # Publisher Windows exports contain E4 (ä) and F1 (ñ); preserve the
        # exported text, including mojibake already present in raw EVTX.
        return "cp1252"
    finally:
        stream.seek(0)
    return "utf-8"


def export_names(zipped):
    """Return canonical exports in their established ingestion order."""
    return sorted(
        (name for name in zipped.namelist()
         if name.endswith(".xml") or ("auditd" in name and name.endswith(".log"))),
        key=aviator_priority,
    )


def export_commands(root, member, name, stream, budget):
    """Read one export with its archive-derived source IDs and labels."""
    benign = "normal_operation" in name
    yield from parse_log(
        stream,
        f"{ARCHIVE}/{member.name}/{name}",
        root.name,
        budget,
        "benign" if benign else "malicious-group",
        None if benign else f"aviator:{Path(member.name).stem[3:]}",
        encoding=export_encoding(stream) if name.endswith(".xml") else None,
    )


def records(root, options):
    """Yield AVIATOR commands or ordered Arrow batches from parallel exports.

    Limited runs retain the serial reader's shared raw-record budget and early
    termination. Unbounded runs spool at most one export per worker at a time.
    """
    with tarfile.open(root / ARCHIVE, "r:") as archive:
        members = [member for member in archive
                   if Path(member.name).name.startswith("ex_")
                   and member.name.endswith(".zip")]
        selected = {str(path) for path in select_files(
            [Path(member.name) for member in members], options
        )}
        members = [member for member in members if member.name in selected]
        workers = getattr(options, "workers", 1)
        # Audit boot/process state must survive rotated exports. Independent
        # export workers cannot reconstruct that state across files.
        if workers > 1:
            for member in members:
                binary = archive.extractfile(member)
                assert binary is not None
                with binary, zipfile.ZipFile(binary) as zipped:
                    if any("auditd" in name for name in export_names(zipped)):
                        workers = 1
                        break
        if workers <= 1 or options.max_records is not None or options.limit is not None:
            budget = Budget(options)
            for member in members:
                binary = archive.extractfile(member)
                assert binary is not None
                with binary, zipfile.ZipFile(binary) as zipped:
                    for name in export_names(zipped):
                        with zipped.open(name) as stream:
                            yield from export_commands(root, member, name, stream, budget)
                        if budget.done:
                            return
            return
        tasks: list[tuple[tarfile.TarInfo, str]] = []
        for member in members:
            binary = archive.extractfile(member)
            assert binary is not None
            with binary, zipfile.ZipFile(binary) as zipped:
                tasks.extend((member, name) for name in export_names(zipped))
    if tasks:
        yield from parallel_tables(root, tasks, options.batch_size, min(workers, len(tasks)))


def parallel_tables(root, tasks, batch_size, workers):
    """Parse a bounded number of exports concurrently and yield in source order."""
    scratch = root.parent.parent / "tmp" / "ingest"
    scratch.mkdir(parents=True, exist_ok=True)
    context = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="aviator-", dir=scratch) as temporary, \
            context.Pool(workers) as pool:
        pending: deque[AsyncResult] = deque()
        for index, (member, name) in enumerate(tasks):
            output = Path(temporary) / f"{index}.arrow"
            pending.append(pool.apply_async(
                write_export, (root, member, name, batch_size, output)
            ))
            if len(pending) >= workers:
                yield from read_tables(pending.popleft().get())
        while pending:
            yield from read_tables(pending.popleft().get())
        pool.close()
        pool.join()


def write_export(root, member, name, batch_size, output):
    """Parse an export at its tar offset and spool compressed Arrow batches."""
    ipc_options = pa.ipc.IpcWriteOptions(compression="lz4")
    budget = Budget(SimpleNamespace(max_records=None))
    with tarfile.open(root / ARCHIVE, "r:") as archive:
        binary = archive.extractfile(member)
        assert binary is not None
        with binary, zipfile.ZipFile(binary) as zipped, zipped.open(name) as stream, \
                pa.OSFile(str(output), "wb") as sink, \
                pa.ipc.new_stream(sink, SCHEMA, options=ipc_options) as writer:
            batch = []
            for command in export_commands(root, member, name, stream, budget):
                batch.append(command)
                if len(batch) >= batch_size:
                    writer.write_table(command_table(batch, root.name))
                    batch.clear()
            if batch:
                writer.write_table(command_table(batch, root.name))
    return output


def read_tables(path):
    """Yield spooled batches and remove their file even when iteration closes."""
    try:
        with pa.OSFile(str(path), "rb") as source:
            for batch in pa.ipc.open_stream(source):
                yield pa.Table.from_batches([batch])
    finally:
        path.unlink()
