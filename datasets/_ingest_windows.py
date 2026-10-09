"""Streaming Windows and mixed endpoint log readers for the released archives."""

from __future__ import annotations

import csv
import html
import io
import json
import re
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from _ingest import Command, normalize, select_files

EVENT_START = re.compile(r"<Event(?=[\s>])")
TEXT_START = re.compile(r"^\d{1,2}/\d{1,2}/\d{4}\s")


class Budget:
    """Count source records across files in a bounded exploratory run."""

    def __init__(self, options):
        self.remaining = options.max_records
        self.process_labels: set[str] = set()
        self.audit_state = {}

    def take(self):
        """Return whether another source record may be examined."""
        if self.remaining is None:
            return True
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True

    @property
    def done(self):
        """Whether the requested raw-record bound has been reached."""
        return self.remaining is not None and self.remaining <= 0


def raw_xml_events(stream):
    """Frame events in linear time, retaining chunks of an unfinished event."""
    buffer = ""
    parts: list[str] | None = None
    while True:
        chunk = stream.read(65536)
        buffer += chunk
        offset = 0
        while True:
            if parts is None:
                start = EVENT_START.search(buffer, offset)
                if not start:
                    buffer = buffer[max(offset, len(buffer) - 16):]
                    break
                offset = start.start()
                parts = []
            end = buffer.find("</Event>", offset)
            if end < 0:
                # Only a split closing delimiter can cross into the next chunk.
                tail = max(offset, len(buffer) - 7)
                parts.append(buffer[offset:tail])
                buffer = buffer[tail:]
                break
            end += 8
            parts.append(buffer[offset:end])
            yield "".join(parts)
            parts = None
            offset = end
        if not chunk:
            if parts is not None:
                raise ValueError("Truncated XML Event at end of file")
            break


def xml_events(stream, commands_only=False):
    """Yield numbered events, optionally leaving command-free events unparsed.

    Empty fields still count toward source-record limits and progress. Broad
    markers cover all command fields accepted by event_commands; escaped Name
    attributes fall back to XML parsing so encoded field names are preserved.
    """
    for number, raw in enumerate(raw_xml_events(stream), 1):
        if (
            commands_only
            and not any(
                marker in raw
                for marker in ("Command", "command", "cmdline", "HostApplication")
            )
            and not re.search(r"Name\s*=\s*[^<>]*&", raw)
        ):
            yield number, {}
            continue
        try:
            event = ET.fromstring(raw)
        except ET.ParseError:
            # Some publisher exports leave &, <, and > unescaped inside Data,
            # or contain a typo in an unrelated System closing tag. Named
            # field delimiters still preserve the complete recorded value.
            fields = {}
            for data_match in re.finditer(
                r"<Data\s+Name=['\"]([^'\"]+)['\"][^>]*>(.*?)</Data>",
                raw,
                re.DOTALL,
            ):
                fields[data_match[1]] = html.unescape(data_match[2])
            for tag in ["Computer", "Channel", "EventID", "EventRecordID"]:
                match = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", raw, re.DOTALL)
                if match:
                    fields[tag] = html.unescape(match[1])
            for tag, attr, field in [
                ("Provider", "Name", "Provider"),
                ("TimeCreated", "SystemTime", "TimeCreated"),
            ]:
                match = re.search(rf"<{tag}\b[^>]*\b{attr}=['\"]([^'\"]*)", raw)
                if match:
                    fields[field] = html.unescape(match[1])
            yield number, fields
            continue
        fields = {}
        for element in event.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            if tag == "Data" and "Name" in element.attrib:
                fields[element.attrib["Name"]] = element.text or ""
            elif tag in {"Computer", "Channel", "EventID", "EventRecordID"}:
                fields[tag] = element.text or ""
            elif tag == "Provider":
                fields["Provider"] = element.get("Name", "")
            elif tag == "TimeCreated":
                fields["TimeCreated"] = element.get("SystemTime", "")
        yield number, fields


def value(fields, *names):
    """Get the first nonempty scalar field from alternative source spellings."""
    for name in names:
        v = fields.get(name)
        if isinstance(v, (str, int)) and str(v).strip() not in {
            "",
            "-",
            "null",
            "(null)",
        }:
            return str(v)
    return ""


def event_commands(fields, dataset, source, number, label="unknown", group=None, *, argv=None):
    """Convert recorded command lines while retaining their observed executable."""
    fields = dict(fields)
    if fields.get("_reapr_attack"):
        label, group = "malicious", None
    text = value(
        fields,
        "CommandLine",
        "ProcessCommandLine",
        "process_cmdline",
        "command_line",
        "cmdline",
        "process.command_line",
        "HostApplication",
    )
    if not text and not argv:
        return
    pgm = (
        value(
            fields,
            "Image",
            "NewProcessName",
            "process_path",
            "path",
            "ExecutablePath",
            "process.executable",
        )
        or None
    )
    # COMISET and Carbon Black exports escape backslashes a second time.
    if dataset == "comiset" or "process_cmdline" in fields:
        text = text.replace("\\\\", "\\")
        if pgm:
            pgm = pgm.replace("\\\\", "\\")
    provider = value(fields, "Provider", "source_name")
    osname = (
        "linux"
        if ("linux" in provider.lower() or (pgm or text).startswith("/"))
        else "windows"
    )
    host = (
        value(
            fields,
            "Computer",
            "ComputerName",
            "host_name",
            "device_name",
            "hostname",
            "host",
            "ComputerName",
        )
        or "unknown-host"
    )
    guid = value(fields, "LogonGuid")
    if guid.strip("{}0-"):
        session = f"{dataset}:{host}:logon-guid:{guid.lower()}"
    else:
        login = ""
        for name in ["LogonId", "TargetLogonId", "SubjectLogonId", "TerminalSessionId"]:
            candidate = value(fields, name)
            if candidate and candidate.lower() not in {"0", "0x0", "-1", "4294967295"}:
                login = candidate
                break
        if not login:
            login = "parent:" + (
                value(
                    fields,
                    "ParentProcessGuid",
                    "parent_guid",
                    "ParentProcessId",
                    "ParentProcessID",
                    "ParentId",
                    "ppid",
                )
                or value(fields, "User", "user_name", "process_username")
                or "unknown"
            )
        if dataset == "atlasv2":
            scope = Path(source).stem.rsplit("-", 1)[-1]
        elif dataset == "aviator":
            scope = source.split(".zip/", 1)[0]
        else:
            scope = str(Path(source).parent)
        date = value(
            fields, "UtcTime", "TimeCreated", "event_original_time", "@timestamp"
        )[:10]
        session = f"{dataset}:{scope}:{host}:{date}:{login}"
    eventid = value(
        fields, "_id", "EventRecordID", "RecordNumber", "record_number"
    ) or str(number)
    record = f"{source}:{eventid}:{number}"
    pairs = [(pgm or argv[0], argv[1:])] if argv else normalize(text, os=osname, pgm=pgm)
    for index, (program, args) in enumerate(pairs):
        yield Command(
            program,
            args,
            f"{record}:{index}",
            label=label,
            group_id=group if label == "malicious-group" else None,
            session_id=session,
            os=osname,
        )


def json_fields(obj):
    """Resolve common Elasticsearch, osquery, Sysmon and EDR event envelopes."""
    if not isinstance(obj, dict):
        return {}
    fields = dict(obj.get("_source", obj))
    if obj.get("_id"):
        fields["_id"] = str(obj.get("_index", "")) + ":" + str(obj["_id"])
    for name in ["EventData", "event_data", "columns", "event", "data"]:
        if isinstance(fields.get(name), dict):
            fields.update(fields[name])
    process = fields.get("process")
    if isinstance(process, dict):
        fields["process.command_line"] = process.get("command_line")
        fields["process.executable"] = process.get("executable")
        parent = process.get("parent", {})
        fields["ppid"] = parent.get("pid") if isinstance(parent, dict) else None
    if isinstance(fields.get("host"), dict):
        fields["host"] = fields["host"].get("name") or fields["host"].get("hostname")
    if isinstance(fields.get("Event"), dict):
        fields.update(json_fields(fields["Event"]))
    return fields


def text_fields(block):
    """Read Windows rendered-event fields, preserving spaces in command text."""
    fields = {}
    names = {
        "Process Command Line": "CommandLine",
        "New Process Name": "NewProcessName",
        "Logon ID": "SubjectLogonId",
        "Creator Process ID": "ParentProcessId",
    }
    for line in block.splitlines():
        match = re.match(r"^\s*([A-Za-z][\w ]*?)\s*[:=]\s*(.*)$", line)
        if match:
            name, val = match.groups()
            fields[names.get(name, name)] = val
    return fields


def bounded_lines(stream, budget):
    """Count audit source lines before the event-joining reader buffers them."""
    for line in stream:
        if not budget.take():
            return
        yield line


def parse_log(binary, source, dataset, budget, label="unknown", group=None):
    """Stream XML, JSONL, rendered Windows events, and Linux audit records."""
    print(f"{dataset}: reading {source}", file=sys.stderr, flush=True)
    # BufferedReader also works for archive members without materializing them.
    buffered = io.BufferedReader(binary)
    prefix = buffered.peek(4096)[:4096]
    encoding = (
        "utf-16" if prefix.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    )
    stream = io.TextIOWrapper(buffered, encoding=encoding, errors="replace")
    sample = prefix.decode(encoding, errors="replace")
    if EVENT_START.search(sample):
        for number, fields in xml_events(stream, commands_only=True):
            if not budget.take():
                return
            if number % 100000 == 0:
                print(
                    f"{dataset}: {number:,} XML events scanned in {source}",
                    file=sys.stderr,
                    flush=True,
                )
            if fields:
                yield from event_commands(fields, dataset, source, number, label, group)
    elif re.search(r"\btype=(?:SYSCALL|EXECVE|PROCTITLE|PATH|USER_CMD)\b", sample):
        from _ingest_misc import audit_events, audit_value

        for event_id, fields, argv, number, _ in audit_events(
            bounded_lines(stream, budget), state=budget.audit_state,
            scope=f"{dataset}:{source.split('.zip/', 1)[0] if dataset == 'aviator' else str(Path(source).parent)}",
        ):
            if not argv:
                continue
            ses = fields["_session"]
            yield Command(
                audit_value(value(fields, "exe")) or argv[0],
                argv[1:],
                f"{source}:{event_id}:{number}",
                label=label,
                group_id=group if label == "malicious-group" else None,
                session_id=ses,
                os="linux",
            )
    elif sample.lstrip().startswith("{"):
        import simdjson

        parser = simdjson.Parser()
        for number, line in enumerate(stream, 1):
            if not budget.take():
                return
            if not line.strip():
                continue
            try:
                # Every supported command alias contains one of these markers.
                # Keep wrapped raw events and escaped keys conservatively too.
                if not ("ommand" in line or "cmdline" in line
                        or "HostApplication" in line or "_raw" in line or "\\u" in line):
                    try:
                        # Validate syntax without allocating Python dictionaries.
                        # Discard the proxy before this parser is reused.
                        parser.parse(line)
                    except (ValueError, RuntimeError):
                        # Preserve stdlib handling of NaN, huge integers, and errors.
                        json.loads(line)
                    continue
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Some exports are pretty-printed JSON objects; stream these separately.
                raise ValueError(
                    f"{source}:{number}: expected a complete JSON event"
                ) from None
            if isinstance(obj, dict) and isinstance(obj.get("_raw"), str):
                yield from parse_log(
                    io.BytesIO(obj["_raw"].encode()),
                    f"{source}:{number}",
                    dataset,
                    Budget(type("Options", (), {"max_records": None})()),
                    label,
                    group,
                )
            else:
                fields = json_fields(obj)
                if fields.get("process_guid") in budget.process_labels:
                    fields["_reapr_attack"] = True
                yield from event_commands(fields, dataset, source, number, label, group)
                target = value(fields, "target_cmdline")
                if target and target != value(fields, "process_cmdline"):
                    related = dict(fields)
                    related["process_cmdline"] = target
                    related["process_path"] = value(
                        fields, "childproc_name", "crossproc_name"
                    )
                    related["process_guid"] = value(
                        fields, "childproc_guid", "crossproc_guid"
                    )
                    related["parent_guid"] = value(fields, "process_guid")
                    related["_reapr_attack"] = (
                        related["process_guid"] in budget.process_labels
                    )
                    yield from event_commands(
                        related, dataset, source, f"{number}:target", label, group
                    )
    else:
        block: list[str] = []
        number = 0
        for line in stream:
            if TEXT_START.match(line) and block:
                number += 1
                if not budget.take():
                    return
                yield from event_commands(
                    text_fields("".join(block)), dataset, source, number, label, group
                )
                block = []
            block.append(line)
            # Non-Windows logs are delimited by lines; avoid retaining a whole file.
            if len(block) == 1 and not TEXT_START.match(line):
                if not budget.take():
                    return
                number += 1
                yield from event_commands(
                    text_fields(line), dataset, source, number, label, group
                )
                block = []
        if block and budget.take():
            yield from event_commands(
                text_fields("".join(block)), dataset, source, number + 1, label, group
            )


def comiset(root, options):
    """Read COMISET JSONL directly from each large ZIP member."""
    budget = Budget(options)
    for path in select_files(root.glob("*.zip"), options):
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if name.endswith(".json"):
                    with archive.open(name) as stream:
                        yield from parse_log(
                            stream, f"{path.name}/{name}", root.name, budget
                        )
                    if budget.done:
                        return


def atlasv2(root, options):
    """Stream ATLAS Sysmon, Security, and Carbon Black logs from its archive."""
    budget = Budget(options)
    for label_file in (root / "reapr" / "atlasv2").glob("*.labels"):
        with label_file.open() as stream:
            for row in csv.DictReader(stream, skipinitialspace=True):
                if row.get("label", "").strip() == "attack":
                    budget.process_labels.add(row["process_uuid"].strip())
    path = root / "atlasv2.tar.gz"
    from _ingest_processes import ProcessCommands

    with ProcessCommands() as processes, tarfile.open(path, "r:gz") as archive:
        selected = None
        if options.sample_files:
            eligible = [
                Path(m.name)
                for m in archive.getmembers()
                if m.isfile()
                and m.name.endswith((".xml", ".jsonl"))
                and any(
                    part in m.name for part in ["/sysmon/", "/msft-security/", "/cbc-"]
                )
            ]
            selected = {str(p) for p in select_files(eligible, options)}
        for member in archive:
            if not member.isfile() or not member.name.endswith((".xml", ".jsonl")):
                continue
            if not any(
                part in member.name for part in ["/sysmon/", "/msft-security/", "/cbc-"]
            ):
                continue
            if selected is not None and member.name not in selected:
                continue
            benign = "/benign/" in member.name
            scenario = Path(member.name).stem.rsplit("-", 1)[-1]
            label = "benign" if benign else "malicious-group"
            group = None if benign else f"atlasv2:{scenario}"
            stream = archive.extractfile(member)
            assert stream is not None
            with stream:
                if "/cbc-" in member.name:
                    for number, line in enumerate(stream, 1):
                        if not budget.take():
                            break
                        if not line.strip():
                            continue
                        fields = json_fields(json.loads(line))
                        for identity, command, creation in carbon_black_commands(
                            fields, f"{path.name}/{member.name}", number, budget, label, group
                        ):
                            processes.add(identity, command, creation)
                else:
                    yield from parse_log(
                        stream, f"{path.name}/{member.name}", root.name, budget, label, group,
                    )
            if budget.done:
                break
        yield from processes.commands()


def carbon_black_commands(fields, source, number, budget, label, group):
    """Assign actor and child observations to their own scoped process GUIDs."""
    scope = source.split("/cbc-", 1)[0]
    scenario = Path(source).stem.rsplit("-", 1)[-1]
    host = value(fields, "device_name", "host_name", "hostname", "host")
    kind = value(fields, "type", "event_type")
    candidates = [(dict(fields), False, str(number))]
    target = value(fields, "target_cmdline")
    if target:
        child = dict(fields)
        child["process_cmdline"] = target
        child["process_path"] = value(fields, "childproc_name", "crossproc_name")
        child["process_guid"] = value(fields, "childproc_guid", "crossproc_guid")
        child["parent_guid"] = value(fields, "process_guid")
        candidates.append((child, "procstart" in kind.lower(), f"{number}:target"))
    for candidate, creation, occurrence in candidates:
        guid = value(candidate, "process_guid")
        if not guid or not guid.strip("{}0-"):
            if not creation:
                continue
            guid = f"record:{source}:{occurrence}"
        candidate["_reapr_attack"] = guid in budget.process_labels
        for command in event_commands(candidate, "atlasv2", source, occurrence, label, group):
            yield (scope, scenario, host, guid), command, creation


def aviator_priority(name):
    """Put command-rich exports first so bounded scans produce useful samples."""
    return (0 if "sysmon" in name else 1 if "auditd" in name else 2, name)


def aviator(root, options):
    """Read AVIATOR exports with bounded, ordered parallelism for full runs."""
    from _ingest_aviator import records

    yield from records(root, options)


def splunkad(root, options):
    """Read observed events and associate each log with its exercise catalog."""
    import yaml

    budget = Budget(options)
    source_root = root / "source"
    groups = {}
    for path in sorted(source_root.rglob("*.yml")):
        with path.open() as stream:
            metadata = yaml.safe_load(stream)
        if not isinstance(metadata, dict):
            continue
        exercise = metadata.get("id")
        if not exercise:
            continue
        for entry in metadata.get("datasets", []):
            if isinstance(entry, dict) and entry.get("path"):
                rel = str(entry["path"]).lstrip("/")
                groups[rel] = f"splunkad:{exercise}"
    files = [
        p
        for p in source_root.rglob("*")
        if p.suffix in {".log", ".json", ".raw"}
        and not p.name.endswith(".download.json")
    ]
    for path in select_files(files, options):
        rel = path.relative_to(source_root).as_posix()
        group = groups.get(rel)
        # Honeypot and mixed unrelated logs lack an identified attack exercise.
        label = (
            "malicious-group" if group and "/honeypots/" not in "/" + rel else "unknown"
        )
        with path.open("rb") as stream:
            yield from parse_log(
                stream, f"source/{rel}", root.name, budget, label, group
            )
        if budget.done:
            return
