"""Read BOTS through Splunk's native bucket exporter and parse original events."""

import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import urllib.request
from collections import defaultdict
from pathlib import Path

from _ingest import Command, normalize, select_files
from _ingest_misc import audit_events, audit_value
from _ingest_windows import event_commands, json_fields, text_fields, xml_events

SPLUNK_URL = "https://download.splunk.com/products/splunk/releases/9.1.3/linux/splunk-9.1.3-d95b3299fa65-Linux-x86_64.tgz"
SPLUNK_SHA256 = "bc57ed6197ea5dc411378b46377641d41ea8d18fc63f43ba7c7a6ed5888e4f69"


def exporter(scratch):
    """Locate exporttool, downloading the pinned native distribution if absent."""
    home = Path(os.environ.get("SPLUNK_HOME", scratch / "splunk"))
    executable = home / "bin" / "splunk"
    if executable.is_file():
        return executable
    if "SPLUNK_HOME" in os.environ:
        raise FileNotFoundError(f"SPLUNK_HOME has no bin/splunk: {home}")
    archive = scratch / "splunk.tgz"
    if not archive.exists():
        partial = archive.with_suffix(".tgz.part")
        print(
            "Downloading native Splunk exporttool (587 MiB); cached under tmp/ingest.",
            flush=True,
        )
        with (
            urllib.request.urlopen(SPLUNK_URL, timeout=60) as response,
            partial.open("wb") as output,
        ):
            shutil.copyfileobj(response, output)
        partial.replace(archive)
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != SPLUNK_SHA256:
        raise ValueError(f"Splunk distribution SHA-256 mismatch: {archive}")
    with tarfile.open(archive) as bundle:
        bundle.extractall(scratch, filter="data")
    return executable


def exports(root, options):
    """Cache verified CSV exports of complete original index buckets."""
    scratch = root.parent.parent / "tmp" / "ingest"
    scratch.mkdir(parents=True, exist_ok=True)
    app = scratch / "bots"
    source = root / "botsv3_data_set.tgz"
    stamp = [source.stat().st_size, source.stat().st_mtime_ns]
    receipt = app / "source.json"
    cached = json.loads(receipt.read_text()) if receipt.exists() else None
    if cached != stamp:
        if app.exists():
            shutil.rmtree(app)
        app.mkdir(exist_ok=True)
        with tarfile.open(source) as archive:
            archive.extractall(app, filter="data")
        receipt.write_text(json.dumps(stamp))
    buckets = [
        p.parent.parent
        for p in (app / "botsv3_data_set/var/lib/splunk/botsv3/db").glob(
            "*/rawdata/journal.gz"
        )
    ]
    if not buckets:
        raise ValueError("BOTS archive contains no index buckets")
    executable = exporter(scratch)
    output_dir = scratch / "bots-exports"
    output_dir.mkdir(exist_ok=True)
    for bucket in select_files(buckets, options):
        output = output_dir / (bucket.name + ".csv")
        mark = output.with_suffix(".json")
        if (
            not output.exists()
            or not mark.exists()
            or json.loads(mark.read_text()) != stamp
        ):
            partial = output.with_suffix(".csv.part")
            subprocess.run(
                [
                    str(executable),
                    "cmd",
                    "exporttool",
                    str(bucket),
                    str(partial),
                    "-csv",
                ],
                check=True,
            )
            partial.replace(output)
            mark.write_text(json.dumps(stamp))
        yield bucket.name, output


def ps_commands(raw, record, session):
    """Read COMMAND and the collector's underscore-separated argument field."""
    lines = raw.splitlines()
    if not lines or "ARGS" not in lines[0]:
        return
    for number, line in enumerate(lines[1:], 1):
        fields = line.split(None, 12)
        if len(fields) != 13 or fields[12] == "<noArgs>":
            continue
        if fields[11].endswith(":") or fields[11].startswith("["):
            continue
        text = fields[11] + " " + fields[12].replace("_", " ")
        for index, (pgm, args) in enumerate(normalize(text)):
            yield Command(
                pgm,
                args,
                f"{record}:ps:{number}:{index}",
                session_id=f"{session}:user:{fields[0]}:tty:{fields[8]}",
            )


def records(root, options):
    """Read all BOTS sourcetypes that contain observed command arguments."""
    csv.field_size_limit(100_000_000)
    audits = defaultdict(list)
    for bucket, path in exports(root, options):
        with path.open(encoding="utf-8", errors="replace", newline="") as stream:
            for number, row in enumerate(csv.DictReader(stream), 1):
                if options.max_records is not None and number > options.max_records:
                    break
                raw = row["_raw"]
                host = row["host"].removeprefix("host::")
                source = row["source"].removeprefix("source::")
                kind = row["sourcetype"].removeprefix("sourcetype::").lower()
                record = f"botsv3_data_set.tgz:{bucket}:{number}"
                session = f"splunk-bots:{host}:{source}"
                if kind == "bash_history":
                    text = re.sub(r"^\s*\d+\s+", "", raw)
                    for i, (pgm, args) in enumerate(normalize(text, shell=True)):
                        yield Command(
                            pgm, args, f"{record}:shell:{i}", session_id=session
                        )
                elif kind == "history-2":
                    for i, text in enumerate(
                        re.findall(r"^Commandline:\s*(.*)$", raw, re.MULTILINE)
                    ):
                        for pgm, args in normalize(text):
                            yield Command(
                                pgm, args, f"{record}:apt:{i}", session_id=session
                            )
                elif kind == "ps":
                    yield from ps_commands(raw, record, session)
                elif kind == "linux_audit":
                    audits[(host, source)].append((record, raw))
                elif kind.startswith("xmlwineventlog"):
                    for i, fields in xml_events(io.StringIO(raw)):
                        fields.setdefault("Computer", host)
                        yield from event_commands(fields, "splunk-bots", record, i)
                elif kind.startswith("wineventlog"):
                    fields = text_fields(raw)
                    fields.setdefault("Computer", host)
                    # Rendered Security events have Creator and Target subjects.
                    logons = re.findall(r"Logon ID:\s*(\S+)", raw)
                    valid = [v for v in logons if v.lower() not in ("0x0", "0", "-")]
                    if valid:
                        fields["SubjectLogonId"] = valid[-1]
                    yield from event_commands(fields, "splunk-bots", record, 1)
                elif kind == "osquery:results":
                    decoder = json.JSONDecoder()
                    position = 0
                    index = 0
                    while position < len(raw):
                        while position < len(raw) and raw[position].isspace():
                            position += 1
                        if position == len(raw):
                            break
                        obj, position = decoder.raw_decode(raw, position)
                        index += 1
                        fields = json_fields(obj)
                        fields["host"] = host
                        fields["ParentProcessId"] = fields.get("parent", "")
                        if (
                            isinstance(fields.get("cmdline"), str)
                            and fields["cmdline"].strip()
                        ):
                            for command in event_commands(
                                fields, "splunk-bots", record, index
                            ):
                                command.session_id = f"splunk-bots:{host}:uid:{fields.get('uid', '?')}:parent:{fields.get('parent') or fields.get('auid', '?')}"
                                yield command
                elif kind == "winhostmon":
                    fields = text_fields(raw)
                    for key in fields:
                        if key != "CommandLine":
                            fields[key] = (
                                fields[key].removeprefix('"').removesuffix('"')
                            )
                    commandline = fields.get("CommandLine", "")
                    if commandline.startswith('"') and commandline.endswith('"'):
                        first_quoted = commandline[1 : commandline.find('"', 1)]
                        name = fields.get("Name", "")
                        # WMI sometimes wraps the whole value and sometimes preserves
                        # the original quoted executable. A first quoted segment
                        # ending in the process name is already executable quoting.
                        if commandline.startswith('""') or (
                            name and not first_quoted.lower().endswith(name.lower())
                        ):
                            fields["CommandLine"] = commandline[1:-1]
                    if fields.get("Type") != "Process":
                        continue
                    fields["host"] = host
                    fields["Image"] = fields.get("Path", "")
                    for command in event_commands(fields, "splunk-bots", record, 1):
                        if fields.get("ProcessId") and fields.get("StartTime"):
                            command.session_id = (
                                f"splunk-bots:{host}:process:{fields['ProcessId']}:"
                                f"start:{fields['StartTime']}"
                            )
                        yield command
                elif "COMMAND=" in raw and kind in ("syslog", "linux_secure"):
                    for i, (pgm, args) in enumerate(
                        normalize(raw.split("COMMAND=", 1)[1])
                    ):
                        yield Command(
                            pgm, args, f"{record}:sudo:{i}", session_id=session
                        )
    # Audit companion records can be in separate exported buckets; join by host/event.
    # The release has only 112 audit rows, so this small cross-bucket join is bounded.
    for (host, source), entries in audits.items():
        lines = []
        locations = []
        for record, raw in entries:
            for line in raw.splitlines():
                lines.append(line)
                locations.append(record)
        for event, fields, argv, number, _ in audit_events(lines):
            ses = fields.get("ses", "")
            if ses in ("", "-1", "4294967295"):
                ses = "parent:" + fields.get("ppid", event)
            yield Command(
                audit_value(fields.get("exe", "")) or argv[0],
                argv[1:],
                f"{locations[number - 1]}:audit:{event}",
                session_id=f"splunk-bots:{host}:{source}:{ses}",
            )
