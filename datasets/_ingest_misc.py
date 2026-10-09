"""Readers for audit, honeypot, training and Wazuh command collections."""

from __future__ import annotations

import csv
import gzip
import hashlib
import html
import io
import json
import re
import subprocess
import sys
import zipfile
import zlib
from collections import OrderedDict
from datetime import datetime
from itertools import islice
from pathlib import Path
from typing import Any

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
        return event, fields, argv, line, attack
    return None


def audit_events(lines, labels=None):
    """Join audit records by event ID; yield ID, fields, argv, line, attack flag."""
    pending: OrderedDict[str, list[Any]] = OrderedDict()
    labels = labels or set()
    for number, raw in enumerate(lines, 1):
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        match = re.search(r"msg=audit\(([^)]+)\)", text)
        if not match:
            continue
        event = match[1]
        fields = dict(re.findall(r'(?<![\w-])([\w]+)=("[^"]*"|[^\s\']+)', text))
        entry = pending.setdefault(event, [{}, {}, "", "", number, False])
        entry[0].update(fields)
        entry[5] |= number in labels
        kind = fields.get("type")
        if kind == "EXECVE":
            if "/" in event:
                # ausearch -i emits unquoted, already-decoded arguments.
                arguments = re.findall(
                    r"(?<!\S)a(\d+)=(.*?)(?=\s+a\d+=|$)", text.rstrip()
                )
                for key, value in arguments:
                    entry[1][int(key)] = value
            else:
                for key, value in fields.items():
                    if re.fullmatch(r"a\d+", key):
                        entry[1][int(key[1:])] = audit_value(value)
        if kind == "PROCTITLE":
            entry[2] = audit_value(fields.get("proctitle", ""))
        if kind == "USER_CMD":
            entry[3] = audit_value(fields.get("cmd", ""))
        if kind == "EOE":
            result = complete_audit_event(event, pending.pop(event))
            if result:
                yield result
        while len(pending) > 1024:
            key, value = pending.popitem(last=False)
            result = complete_audit_event(key, value)
            if result:
                yield result
    for key, value in pending.items():
        result = complete_audit_event(key, value)
        if result:
            yield result


def ait(root, options):
    """Read audit commands and sudo records with per-line attack annotations."""
    for path in select_files(root.glob("*.zip"), options):
        with zipfile.ZipFile(path) as archive:
            members = set(archive.namelist())
            for name in sorted(members):
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
                            limited(stream, options), attacks
                        ):
                            ses = fields.get("ses", "")
                            if ses in ("", "4294967295", "-1"):
                                ses = "parent:" + fields.get(
                                    "ppid", fields.get("pid", eid)
                                )
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
                                f"{prefix}:{ses}",
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
            if "type=PROCTITLE" in log or "type=EXECVE" in log:
                fragments = re.split(r" (?=type=[A-Z_]+ msg=audit)", log)
                for eid, fields, argv, _, _ in audit_events(fragments):
                    ses = fields.get("ses", "")
                    if ses in ("", "4294967295", "-1"):
                        ses = "parent:" + fields.get("ppid", fields.get("pid", eid))
                    audit_session = f"linux-apt-2024:{row.get('_source.agent.name', '')}:{day}:{ses}"
                    yield Command(
                        audit_value(fields.get("exe", "")) or argv[0],
                        argv[1:],
                        rid + ":" + eid,
                        label,
                        None,
                        audit_session,
                    )
            else:
                argv = sudo_command_argv(command)
                if argv:
                    yield Command(argv[0], argv[1:], rid + ":0", label, session_id=session)


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
            if not command:
                image = row.get("_source.data.process.cmd", "").strip()
                arguments = row.get("_source.data.process.args", "").strip()
                if not image or not arguments:
                    continue
                os = "linux" if image.startswith("/") else "windows"
                command = f'"{image}" {arguments}'
            # Wazuh CSV fields retain doubled JSON backslashes.
            if os == "windows":
                command = command.replace("\\\\", "\\")
                image = image.replace("\\\\", "\\")
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
                os=os,
                pgm=image or None,
            )


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
                            break
                    session = (
                        f"publicarena:{path.stem}:{row.get('pc', host)}:"
                        f"{date.date()}:{row.get('SessionID', 'unknown')}"
                    )
                    rid = f"{path.name}:{name}:{row.get('uuid', index)}"
                    yield from emitted(
                        html.unescape(row["CommandLine"]).replace("\\\\", "\\"),
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
