"""Read OTRF capture releases and merge alternate observations of one launch."""

import io
import json
import re
import tarfile
import zipfile
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml
from _ingest import Command, normalize, select_files, shell_commands
from _ingest_acme import ordinary_launch
from _ingest_windows import (
    Budget,
    bounded_lines,
    event_commands,
    json_fields,
    parse_log,
    value,
    xml_events,
)

ARCHIVE = "security-datasets.tar.gz"
# Two links in the pinned publisher metadata use names absent from its tree.
RENAMES = {
    "cmd_copy_ntds_from_volume_shadow_copy.zip": "cmd_dumping_ntds_dit_file_volume_shadow_copy.zip",
    "empire_dcom_shellwindows_stager.zip": "empire_dcom_shellwindows.zip",
}


def command_key(program, args):
    """Compare executable basenames and exact arguments across metadata and logs."""
    return program.replace("\\", "/").rsplit("/", 1)[-1].lower(), tuple(args)


def attack_commands(capture):
    """Extract submitted commands from the publisher's adversary terminal transcript."""
    keys = set()
    text = (capture.get("simulation") or {}).get("adversary_view", "") or ""
    linux = "linux" in str(capture.get("platform", [])).lower()
    for line in text.splitlines():
        prompt = re.match(r"^(?:PS )?[A-Za-z]:\\[^>]*>\s*(.+)$", line)
        if not prompt:
            prompt = re.match(r"^[\w.-]+@[\w.-]+:[^$#]*[$#]\s*(.+)$", line)
        if not prompt:
            # Some captures omit the prompt but retain both commands and output.
            # Require a command-like first word and flag, assignment or path
            # argument; this excludes checksum and byte-count result lines.
            if not re.match(r"^[A-Za-z_./\\][\w./\\-]*\s+(?:-[A-Za-z]|/|\w+=)", line):
                continue
            command_text = line
        else:
            command_text = prompt[1]
        commands = shell_commands(command_text) if linux else normalize(command_text, os="windows")
        for command in commands:
            keys.add(command_key(command[0], command[1]))
    return keys


def metadata(archive):
    """Associate released files with their capture's platform and attack context."""
    captures = {}
    with tarfile.open(archive, "r|gz") as source:
        for member in source:
            if not member.isfile() or "/_metadata/" not in member.name:
                continue
            data = yaml.safe_load(source.extractfile(member))
            data["_commands"] = attack_commands(data)
            for entry in data.get("files", []) or []:
                relative = "datasets/" + entry["link"].split("/datasets/", 1)[-1]
                if "/network/" in relative or "cmd_copy_ntds" in relative:
                    name = Path(relative).name
                    relative = str(Path(relative).with_name(RENAMES.get(name, name)))
                captures[relative.lower()] = data
    return captures


def unescape(text):
    """Decode the additional JSON escaping used by Azure's exported fields."""
    try:
        return json.loads('"' + text + '"')
    except (ValueError, TypeError):
        return text


def decoded_fields(obj):
    """Decode flattened events and the JSON/XML fields in Azure log exports."""
    fields = json_fields(obj)
    nested = fields.get("EventData")
    if isinstance(nested, str):
        nested = unescape(nested)
        if nested.lstrip().startswith("{"):
            fields.update(json.loads(nested))
        elif "<EventData" in nested:
            fields.update(next(xml_events(io.StringIO("<Event>" + nested + "</Event>")))[1])
    message = fields.get("SyslogMessage", "")
    if message:
        message = unescape(message)
        if "<Event" in message:
            if not message.rstrip().endswith("</Event>"):
                # Azure truncates some released syslog payloads at 2,048 bytes.
                # Recover complete fields only; never invent the partial field.
                last = message.rfind("</Data>")
                if last < 0:
                    return fields
                message = message[:last + 7] + "</EventData></Event>"
            fields.update(next(xml_events(io.StringIO(message)))[1])
        elif "type=AUOMS_EXECVE" in message:
            # AUOMS carries argv in a single quoted cmdline field. Retain failed
            # attempts too; they have a new invocation but no successful image.
            from _ingest_misc import audit_value

            pairs = dict(re.findall(r'(\w+)=("(?:\\.|[^"\\])*"|\S+)', message))
            fields.update(pairs)
            command = re.search(r'\bcmdline=(.*?)\s+redactors=', message)
            fields["CommandLine"] = command[1][1:-1] if command and command[1].startswith('"') else command[1] if command else ""
            failed = pairs.get("success") == "no"
            fields["Image"] = audit_value(pairs.get("name" if failed else "exe", ""))
            if failed and not command:
                # Failed exec has no argv export, but its attempted path is
                # useful. The proctitle and exe describe the calling JVM.
                fields["CommandLine"] = fields["Image"]
            fields["Provider"] = "Linux-AUOMS"
            fields["_otrf_failed"] = failed
    for key in ("Image", "NewProcessName", "CommandLine", "ParentImage"):
        if isinstance(fields.get(key), str):
            fields[key] = fields[key].replace("\\\\", "\\")
    fields["Computer"] = value(fields, "Computer", "Hostname", "HostName", "host")
    return fields


def launch_identity(fields):
    """Return host/PID/image/time data only when a process creation is identified."""
    event = value(fields, "EventID", "EventId", "event_id")
    provider = value(fields, "Provider", "SourceName", "EventSourceName", "Channel").lower()
    if "auoms" in provider and not fields.get("_otrf_failed"):
        event = "auoms"
    if event not in {"1", "4688", "auoms"} or (event == "1" and "sysmon" not in provider):
        return None
    pid = value(fields, "NewProcessId") if event == "4688" else value(fields, "ProcessId", "ProcessID", "pid")
    try:
        number = int(pid, 16 if pid.lower().startswith("0x") else 10)
        stamp = value(fields, "TimeCreated", "TimeGenerated", "EventTime", "UtcTime")
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        timestamp = parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).timestamp()
    except (ValueError, TypeError):
        return None
    image = value(fields, "Image", "NewProcessName").lower()
    return (value(fields, "Computer").lower(), number, image), timestamp, event


def final_label(command, capture, descendant=False):
    """Refine capture labels where the invocation supplies more specific evidence."""
    name = command.pgm.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if ordinary_launch(command.pgm, command.args):
        return "benign"
    if any(tool in name for tool in ("mimikatz", "dumpert", "nanodump", "sharphound", "rubeus")):
        return "malicious"
    if command_key(command.pgm, command.args) in capture.get("_commands", set()) or descendant:
        return "malicious"
    if capture.get("attack_mappings"):
        return "malicious-group"
    return "unknown"


def complete_attempt(block, first_line):
    """Join one audit event, retaining failed target-only attempts without caller argv."""
    from _ingest_misc import audit_events, audit_value

    result = list(audit_events(block))
    if result:
        event, fields, argv, _, _ = result[0]
        yield event, fields, argv, first_line
        return
    fields = {}
    target = ""
    for line in block:
        row = dict(re.findall(r'(?<![\w-])([\w]+)=("[^"]*"|[^\s\']+)', line))
        fields.update(row)
        if row.get("type") == "PATH" and not target and row.get("nametype") != "PARENT":
            target = audit_value(row.get("name", ""))
    if fields.get("success") == "no" and target:
        event = re.search(r"msg=audit\(([^)]+)\)", block[0])[1]
        fields["name"] = '"' + target + '"'
        yield event, fields, [target], first_line


def audit_attempts(lines):
    """Keep at most 1,024 unfinished audit events before using the shared joiner."""
    pending = OrderedDict()
    for number, raw in enumerate(lines, 1):
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        match = re.search(r"msg=audit\(([^)]+)\)", line)
        if not match:
            continue
        event = match[1]
        block, first = pending.setdefault(event, ([], number))
        block.append(line)
        if re.search(r"\btype=EOE\b", line):
            pending.pop(event)
            yield from complete_attempt(block, first)
        if len(pending) > 1024:
            _, (block, first) = pending.popitem(last=False)
            yield from complete_attempt(block, first)
    for block, first in pending.values():
        yield from complete_attempt(block, first)


def audit_commands(stream, source, dataset, capture, budget, state):
    """Keep audit exec attempts, excluding non-exec proctitle observations."""
    from _ingest_misc import audit_value

    for event, fields, argv, number in audit_attempts(bounded_lines(stream, budget)):
        syscall = value(fields, "syscall")
        architecture = value(fields, "arch")
        exec_calls = {"c000003e": {"59", "322"}, "40000003": {"11", "358"},
                      "c00000b7": {"221", "281"}}
        if "argc" not in fields and syscall not in exec_calls.get(architecture, {"execve", "execveat"}):
            continue
        failed = value(fields, "success") == "no"
        attempted = audit_value(value(fields, "name")) if failed else ""
        program = (attempted or argv[0]) if failed else (audit_value(value(fields, "exe")) or argv[0])
        arguments = argv[1:] if not failed or "argc" in fields else []
        session = value(fields, "ses").strip('"')
        if session in {"", "-1", "4294967295", "unset"}:
            session = ""
        else:
            session = f"{dataset}:{capture.get('id', source)}:{value(fields, 'node', 'host')}:{session}"
        command = Command(program, arguments, f"{source}:{event}:{number}", session_id=session)
        host = value(fields, "node", "host").lower() or source
        descendant = False
        try:
            timestamp = float(event.split(":", 1)[0])
            pid = int(value(fields, "pid"))
            parent = int(value(fields, "ppid"))
            previous = state["pids"].get((host, parent))
            descendant = bool(previous and previous[0] <= timestamp and previous[1] == "malicious")
        except ValueError:
            timestamp = None
        command.label = final_label(command, capture, descendant)
        if timestamp is not None and not failed:
            previous = state["pids"].get((host, pid))
            if not previous or previous[0] <= timestamp:
                state["pids"][host, pid] = timestamp, command.label
        command.group_id = f"{dataset}:{capture.get('id', source)}" if command.label == "malicious-group" else None
        yield command


def capture_commands(binary, source, dataset, capture, budget, state):
    """Parse one host export, deduplicating matching Security/Sysmon launches."""
    buffered = io.BufferedReader(binary)
    prefix = buffered.peek(1024).lstrip()
    if not prefix.startswith(b"{"):
        if re.search(rb"\btype=(?:SYSCALL|EXECVE|PROCTITLE)\b", prefix):
            yield from audit_commands(buffered, source, dataset, capture, budget, state)
            return
        for command in parse_log(buffered, source, dataset, budget):
            command.label = final_label(command, capture)
            command.group_id = f"{dataset}:{capture.get('id', source)}" if command.label == "malicious-group" else None
            yield command
        return
    with io.TextIOWrapper(buffered, encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            if not budget.take():
                return
            if not line.strip():
                continue
            obj = json.loads(line)
            fields = decoded_fields(obj)
            event = value(fields, "EventID", "EventId", "event_id")
            if event and event not in {"1", "4688"}:
                continue
            identity = launch_identity(fields)
            provider = value(fields, "Provider", "SourceName", "EventSourceName", "Channel").lower()
            if (event == "4688" or (event == "1" and "sysmon" in provider)) and not value(fields, "CommandLine"):
                image = value(fields, "Image", "NewProcessName")
                if image:
                    fields["CommandLine"] = '"' + image + '"'
            if identity:
                key, stamp, kind = identity
                observations = state["seen"][key]
                guid = value(fields, "ProcessGuid")
                if any((guid and guid == old_guid) or
                       (kind != old_kind and abs(stamp - old_stamp) <= 0.01)
                       for old_stamp, old_kind, old_guid in observations):
                    if guid:
                        previous = state["pids"].get((key[0], key[1]))
                        if previous:
                            state["guids"][key[0], guid] = previous[1]
                    continue
            for command in event_commands(fields, dataset, source, number):
                if identity:
                    observations.append((stamp, kind, guid))
                host = value(fields, "Computer").lower()
                parent = value(fields, "ParentProcessGuid")
                descendant = state["guids"].get((host, parent)) == "malicious" if parent else False
                if not parent and identity:
                    parent_pid = value(fields, "ProcessId") if event == "4688" else value(fields, "ParentProcessId")
                    try:
                        parent_pid = int(parent_pid, 16 if parent_pid.lower().startswith("0x") else 10)
                        prior = state["pids"].get((host, parent_pid))
                        descendant = bool(prior and prior[0] <= identity[1] and prior[1] == "malicious")
                    except ValueError:
                        pass
                command.label = final_label(command, capture, descendant)
                process = value(fields, "ProcessGuid")
                if process:
                    state["guids"][host, process] = command.label
                if identity:
                    key, stamp, _ = identity
                    state["pids"][host, key[1]] = stamp, command.label
                command.group_id = f"{dataset}:{capture.get('id', source)}" if command.label == "malicious-group" else None
                # Only native login or process lifetime identifiers form sessions.
                native = value(fields, "LogonGuid", "LogonId", "SubjectLogonId", "ses")
                if native.strip('"') in {"0", "0x0", "-1", "4294967295"}:
                    native = ""
                command.session_id = f"{dataset}:{capture.get('id', source)}:{fields.get('Computer', '')}:{native or process}" if native or process else ""
                if "linux" in str(capture.get("platform", [])).lower() or "mac" in str(capture.get("platform", [])).lower():
                    command.os = "linux"
                yield command


def records(root, options):
    """Traverse all released archives and standalone host captures in order."""
    archive_path = root / ARCHIVE
    captures = metadata(archive_path)
    budget = Budget(options)
    with tarfile.open(archive_path, "r:gz") as archive:
        files = [m for m in archive if m.isfile() and "/datasets/" in m.name
                 and m.name.lower().endswith((".zip", ".tar.gz", ".json", ".log"))
                 and "/network/" not in m.name and "/zeek/" not in m.name
                 and "/pcaps/" not in m.name]
    selected = {str(p) for p in select_files([Path(m.name) for m in files], options)}
    observations = {}
    with tarfile.open(archive_path, "r|gz") as archive:
        for member in archive:
            if member.name not in selected:
                continue
            source = member.name.split("/", 1)[1]
            capture = captures.get(source.lower(), {})
            state = observations.setdefault(capture.get("id", source),
                                            {"seen": defaultdict(list), "guids": {}, "pids": {}})
            binary = archive.extractfile(member)
            if member.name.lower().endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(binary.read())) as zipped:
                    for name in zipped.namelist():
                        if name.lower().endswith((".json", ".log", ".jsonl", ".xml")) and not name.startswith("__MACOSX/"):
                            with zipped.open(name) as stream:
                                yield from capture_commands(stream, source + "/" + name, root.name, capture, budget, state)
                            if budget.done:
                                return
            elif member.name.endswith(".tar.gz"):
                with tarfile.open(fileobj=io.BytesIO(binary.read()), mode="r:gz") as nested:
                    for entry in nested:
                        if entry.isfile() and entry.name.endswith((".json", ".log", ".jsonl", ".xml")):
                            stream = nested.extractfile(entry)
                            yield from capture_commands(stream, source + "/" + entry.name, root.name, capture, budget, state)
                            if budget.done:
                                return
            else:
                yield from capture_commands(io.BytesIO(binary.read()), source, root.name, capture, budget, state)
            if budget.done:
                return
