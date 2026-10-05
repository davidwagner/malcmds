"""Shared command normalization and transactional native DuckDB ingestion."""

import argparse
import json
import random
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

import duckdb
import pyarrow as pa
import tree_sitter_bash
from tree_sitter import Language, Parser

SHELL = Parser(Language(tree_sitter_bash.language()))


@dataclass
class Command:
    """One source command, before adding its dataset and program basename."""

    pgm: str
    args: list[str]
    record_id: str
    label: str = "unknown"
    group_id: str | None = None
    session_id: str = ""
    os: str = "linux"


def windows_split(text):
    """Split a Windows process command line using CRT quote/backslash rules."""
    result = []
    i = 0
    while i < len(text):
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
        if i == len(text):
            break
        word = []
        quoted = False
        while i < len(text) and (quoted or text[i] not in " \t\r\n"):
            slashes = 0
            while i < len(text) and text[i] == "\\":
                slashes += 1
                i += 1
            if i < len(text) and text[i] == '"':
                word.append("\\" * (slashes // 2))
                if slashes % 2:
                    word.append('"')
                elif quoted and i + 1 < len(text) and text[i + 1] == '"':
                    word.append('"')
                    i += 1
                else:
                    quoted = not quoted
                i += 1
            else:
                word.append("\\" * slashes)
                if i < len(text) and (quoted or text[i] not in " \t\r\n"):
                    word.append(text[i])
                    i += 1
        result.append("".join(word))
    return result


def _ansi_escape(match):
    value = match[1]
    simple = {
        "a": "\a",
        "b": "\b",
        "e": "\x1b",
        "E": "\x1b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        "'": "'",
        '"': '"',
    }
    if value in simple:
        return simple[value]
    if value[0] in "xXuU":
        number = int(value[1:], 16)
        return (
            chr(number)
            if number <= 0x10FFFF and not 0xD800 <= number <= 0xDFFF
            else "\\" + value
        )
    if value[0] in "01234567":
        return chr(int(value, 8))
    return "\\" + value


def _unescape(match):
    return "" if match[1] == "\n" else match[1]


def _word(node):
    text = node.text.decode("utf-8", "replace")
    kind = node.type
    if kind == "raw_string":
        return text[1:-1]
    if kind == "ansi_c_string":
        return re.sub(
            r"\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|.)",
            _ansi_escape,
            text[2:-1],
        )
    if kind in ("string", "concatenation", "command_name"):
        return "".join(_word(child) for child in node.named_children)
    if kind == "string_content":
        return re.sub(r'\\([$`"\\\n])', _unescape, text)
    if kind == "word":
        return re.sub(r"\\(.)", _unescape, text, flags=re.DOTALL)
    return text


def shell_split(text):
    """Parse Bash syntax into commands without executing or expanding input."""
    data = text.encode("utf-8", "replace")
    tree = SHELL.parse(data)
    if b"\\\n" in data:
        # Bash removes continuations before tokenizing, except in single quotes.
        spans = []
        nodes = [tree.root_node]
        while nodes:
            node = nodes.pop()
            if node.type == "raw_string":
                spans.append((node.start_byte, node.end_byte))
            else:
                nodes.extend(node.named_children)
        pieces: list[bytes] = []
        start = 0
        for left, right in sorted(spans):
            pieces.extend((data[start:left].replace(b"\\\n", b""), data[left:right]))
            start = right
        pieces.append(data[start:].replace(b"\\\n", b""))
        tree = SHELL.parse(b"".join(pieces))
    result = []
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "command":
            name = node.child_by_field_name("name")
            if name is not None:
                words = [_word(name)]
                for i, child in enumerate(node.children):
                    if node.field_name_for_child(i) == "argument":
                        words.append(_word(child))
                if words[0]:
                    result.append(words)
        elif node.type in ("declaration_command", "unset_command"):
            keyword = node.children[0].text
            assert keyword is not None
            words = [keyword.decode()]
            words.extend(_word(c) for c in node.named_children)
            result.append(words)
        pending.extend(reversed(node.named_children))
    return result


def normalize(text, os="linux", shell=False, pgm=None):
    """Return program/argument pairs; process telemetry retains literal operators."""
    if (
        not isinstance(text, str)
        or not text.strip()
        or text.strip() in ("-", "(null)", "null")
    ):
        return []
    if "\x00" in text:
        vectors = [text.removesuffix("\x00").split("\x00")]
    elif shell and os == "linux":
        vectors = shell_split(text)
    elif os == "windows":
        # An observed image disambiguates unquoted executable paths with spaces.
        image = str(pgm or "").strip('"')
        if (
            image
            and text.lower().startswith(image.lower())
            and (len(text) == len(image) or text[len(image)].isspace())
        ):
            vectors = [[image, *windows_split(text[len(image) :])]]
        else:
            vectors = [windows_split(text)]
    else:
        try:
            vectors = [shlex.split(text, comments=False)]
        except ValueError:
            vectors = [text.split()]
    result = []
    for vector in vectors:
        if vector and vector[0]:
            program = str(pgm).strip('"') if pgm and not shell else vector[0]
            if program.strip():
                result.append((program, vector[1:]))
    return result


def select_files(paths, options):
    """Choose a reproducible random subset of sorted input paths when requested."""
    paths = sorted(paths)
    count = getattr(options, "sample_files", None)
    if count is not None and count < len(paths):
        paths = sorted(random.Random(options.seed).sample(paths, count))
    return paths


def _positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def arguments(dataset_dir):
    """Parse the CLI shared by every dataset entry point."""
    parser = argparse.ArgumentParser(
        description=f"Ingest {dataset_dir.name} commands into native DuckDB"
    )
    parser.add_argument(
        "--db", type=Path, default=dataset_dir.parent.parent / "cmds.duckdb"
    )
    parser.add_argument(
        "--limit", type=_positive, help="maximum emitted commands (default: all)"
    )
    parser.add_argument(
        "--max-records", type=_positive, help="maximum source records per input stream"
    )
    parser.add_argument(
        "--sample-files", type=_positive, help="sample this many input files"
    )
    parser.add_argument("--seed", type=int, default=0)
    return parser.parse_args()


def _initialize(con):
    for name, values in (
        ("command_label", "'malicious', 'benign', 'unknown', 'malicious-group'"),
        ("command_os", "'windows', 'linux'"),
    ):
        con.execute(f"CREATE TYPE IF NOT EXISTS {name} AS ENUM ({values})")
    con.execute("""CREATE TABLE IF NOT EXISTS COMMANDS (
        pgm VARCHAR NOT NULL, pgm_base VARCHAR NOT NULL, args VARCHAR[] NOT NULL,
        dataset VARCHAR NOT NULL, record_id VARCHAR NOT NULL, label command_label NOT NULL,
        group_id VARCHAR, session_id VARCHAR NOT NULL, os command_os NOT NULL,
        PRIMARY KEY (dataset, record_id),
        CHECK ((label = 'malicious-group') = (group_id IS NOT NULL)))""")


def _insert(con, rows):
    schema = pa.schema(
        [
            (name, pa.list_(pa.string()) if name == "args" else pa.string())
            for name in (
                "pgm",
                "pgm_base",
                "args",
                "dataset",
                "record_id",
                "label",
                "group_id",
                "session_id",
                "os",
            )
        ]
    )
    batch = pa.Table.from_pylist(rows, schema=schema)
    con.register("ingest_batch", batch)
    con.execute("INSERT OR IGNORE INTO COMMANDS SELECT * FROM ingest_batch")
    con.unregister("ingest_batch")


def run(dataset_dir, records_callable):
    """Ingest an iterator atomically; repeats preserve one row per source command."""
    root = Path(dataset_dir).resolve()
    options = arguments(root)
    options.db.parent.mkdir(parents=True, exist_ok=True)
    scratch = root.parent.parent / "tmp" / "ingest" / "duckdb-spill"
    scratch.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(options.db))
    con.execute("SET memory_limit='2GB'")
    con.execute("SET threads=2")
    con.execute("SET temp_directory=?", [str(scratch)])
    _initialize(con)
    count = 0
    rows = []
    con.execute("BEGIN TRANSACTION")
    try:
        records = iter(records_callable(root, options))
        try:
            for command in records:
                if not command.pgm or not command.record_id:
                    raise ValueError("Command requires nonempty pgm and record_id")
                separators = r"[/\\]" if command.os == "windows" else "/"
                rows.append(
                    {
                        "pgm": command.pgm,
                        "pgm_base": re.split(separators, command.pgm)[-1],
                        "args": command.args,
                        "dataset": root.name,
                        "record_id": command.record_id,
                        "label": command.label,
                        "group_id": command.group_id,
                        "session_id": command.session_id
                        or f"{root.name}:record:{command.record_id}",
                        "os": command.os,
                    }
                )
                count += 1
                if len(rows) >= 100000:
                    _insert(con, rows)
                    rows.clear()
                    print(
                        f"{root.name}: {count:,} commands processed",
                        file=sys.stderr,
                        flush=True,
                    )
                if options.limit is not None and count >= options.limit:
                    break
        finally:
            close = getattr(records, "close", None)
            if close is not None:
                close()
        if rows:
            _insert(con, rows)
        print(
            f"{root.name}: committing {count:,} commands", file=sys.stderr, flush=True
        )
        con.execute("COMMIT")
        total = con.execute(
            "SELECT count(*) FROM COMMANDS WHERE dataset=?", [root.name]
        ).fetchall()[0][0]
        print(
            json.dumps(
                {
                    "dataset": root.name,
                    "processed": count,
                    "stored": total,
                    "db": str(options.db),
                }
            ),
            flush=True,
        )
    except BaseException:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()
