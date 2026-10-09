"""Shared command normalization and dataset-level native DuckDB ingestion."""

import argparse
import json
import os
import random
import re
import shlex
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic

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
    shell_input: str | None = None
    other_tokens: list[str] = field(default_factory=list)


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
        # Tree-sitter omits literal newlines between string_content children.
        # Keep those source gaps while removing only the surrounding quotes.
        offset = 1 if kind == "string" else 0
        end = len(node.text) - (1 if kind == "string" else 0)
        pieces = []
        for child in node.named_children:
            start = child.start_byte - node.start_byte
            pieces.append(node.text[offset:start].decode("utf-8", "replace"))
            pieces.append(_word(child))
            offset = child.end_byte - node.start_byte
        pieces.append(node.text[offset:end].decode("utf-8", "replace"))
        return "".join(pieces)
    if kind == "string_content":
        return re.sub(r'\\([$`"\\\n])', _unescape, text)
    if kind == "word":
        return re.sub(r"\\(.)", _unescape, text, flags=re.DOTALL)
    return text


def _shell_commands(text, include_tokens):
    from _shell_input import heredoc_spans, syntax_result

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
        data = b"".join(pieces)
        tree = SHELL.parse(data)
    source_text = data.decode("utf-8")
    spans, complete = heredoc_spans(source_text)
    if not complete:
        return []
    if (tree.root_node.has_error or spans or re.search(r"[\w)]\s*\(", source_text)) and not syntax_result(text)[0]:
        return []
    extra_tokens = []
    if spans:
        masked = bytearray(data)
        for start, end in spans:
            left, right = len(source_text[:start].encode()), len(source_text[:end].encode())
            extra_tokens.append((left, source_text[start:end]))
            masked[left:right] = bytes(10 if byte == 10 else 32 for byte in data[left:right])
        tree = SHELL.parse(bytes(masked))
    result = []
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "command":
            name = node.child_by_field_name("name")
            if name is not None:
                # tree-sitter-bash 0.25 treats a leading 0 in 0<&3 as a
                # command name. It is a descriptor, not a program invocation.
                leading = []
                if name.text.isdigit() and data[name.end_byte:name.end_byte + 1] in (b"<", b">"):
                    redirects = [n for n in node.parent.named_children if n.type == "file_redirect"]
                    destinations = [n for i, n in enumerate(redirects[0].children)
                                    if redirects[0].field_name_for_child(i) == "destination"] if redirects else []
                    if len(destinations) < 2:
                        pending.extend(reversed(node.named_children))
                        continue
                    name, leading = destinations[1], destinations[2:]
                consumed = [name, *leading]
                words = [_word(name), *[_word(n) for n in leading]]
                for i, child in enumerate(node.children):
                    if node.field_name_for_child(i) == "argument":
                        if child.type == "number" and data[child.end_byte:child.end_byte + 1] in (b"<", b">"):
                            continue
                        words.append(_word(child))
                        consumed.append(child)
                if words[0] == "exec":
                    # Options belong to the shell operation, not the invoked argv.
                    words, consumed = words[1:], consumed[1:]
                    while words and words[0] in {"-a", "-c", "-l", "--"}:
                        option = words[0]
                        count = 2 if option == "-a" else 1
                        words, consumed = words[count:], consumed[count:]
                        if option == "--":
                            break
                dynamic = consumed[:1]
                unresolved = False
                while dynamic:
                    part = dynamic.pop()
                    if part.type in {"command_substitution", "simple_expansion", "expansion", "process_substitution"}:
                        unresolved = True
                    dynamic.extend(part.named_children)
                if words and words[0] and not unresolved:
                    result.append((words, consumed))
        elif node.type in ("declaration_command", "unset_command"):
            keyword = node.children[0].text
            assert keyword is not None
            words = [keyword.decode()]
            words.extend(_word(c) for c in node.named_children)
            result.append((words, list(node.children)))
        pending.extend(reversed(node.named_children))
    if not include_tokens:
        return [words for words, _ in result]
    output = []
    for words, consumed in result:
        spans = [(n.start_byte, n.end_byte) for n in consumed]
        tokens = list(extra_tokens)
        pending = [tree.root_node]
        while pending:
            node = pending.pop()
            if any(left <= node.start_byte and node.end_byte <= right for left, right in spans):
                continue
            overlaps = any(left < node.end_byte and node.start_byte < right for left, right in spans)
            if not overlaps and (not node.children or node.type in (
                "word", "string", "raw_string", "ansi_c_string", "concatenation",
                "variable_assignment", "heredoc_body", "simple_expansion", "expansion",
            )):
                value = node.text.decode("utf-8", "replace")
                if value.strip():
                    tokens.append((node.start_byte, value))
            else:
                pending.extend(reversed(node.children))
        output.append((words[0], words[1:], [value for _, value in sorted(tokens)]))
    return output


def shell_commands(text):
    """Return program, arguments, and unused source tokens for each Bash command."""
    return _shell_commands(text, True)


def shell_command_fragments(parts):
    """Yield fragment index, complete input, program, argv and unused tokens."""
    from _shell_input import complete_inputs

    for index, text in complete_inputs(parts):
        for program, args, other in shell_commands(text):
            yield index, text, program, args, other


def shell_split(text):
    """Parse Bash syntax into argv lists without executing or expanding input."""
    return _shell_commands(text, False)


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
    parser.add_argument(
        "--batch-size", type=_positive, default=100000,
        help="commands per durable transaction (default: 100000)",
    )
    parser.add_argument(
        "--tc-workers", type=_positive, default=min(8, os.cpu_count() or 1),
        help="parallel TC Avro decoders (default: up to 8; --limit uses one)",
    )
    parser.add_argument(
        "--memory-limit", default="2GB", help="DuckDB memory budget (default: 2GB)"
    )
    parser.add_argument(
        "--workers", type=_positive, default=os.cpu_count() or 1,
        help="processes reading input files in parallel for OpTC and unbounded AVIATOR runs "
        "(default: number of CPUs)",
    )
    return parser.parse_args()


def _initialize(con):
    for name, values in (
        ("command_label", "'malicious', 'benign', 'unknown', 'malicious-group'"),
        ("command_os", "'windows', 'linux'"),
    ):
        con.execute(f"CREATE TYPE IF NOT EXISTS {name} AS ENUM ({values})")
    con.execute("""CREATE TABLE IF NOT EXISTS COMMANDS (
        pgm VARCHAR NOT NULL, pgm_base VARCHAR NOT NULL, args VARCHAR[] NOT NULL,
        shell_input VARCHAR, other_tokens VARCHAR[] NOT NULL,
        dataset VARCHAR NOT NULL, record_id VARCHAR NOT NULL, label command_label NOT NULL,
        group_id VARCHAR, session_id VARCHAR NOT NULL, os command_os NOT NULL,
        CHECK ((label = 'malicious-group') = (group_id IS NOT NULL)))""")


COLUMNS = (
    "pgm",
    "pgm_base",
    "args",
    "shell_input",
    "other_tokens",
    "dataset",
    "record_id",
    "label",
    "group_id",
    "session_id",
    "os",
)
SCHEMA = pa.schema(
    [(name, pa.list_(pa.string()) if name in ("args", "other_tokens") else pa.string()) for name in COLUMNS]
)


def command_table(commands, dataset):
    """Convert Commands into an Arrow table holding one batch of COMMANDS rows.

    Adds `dataset`, `pgm_base` and a per-record default `session_id`. Raises
    ValueError for a Command with an empty pgm or record_id. Input records are
    assumed to be unique; no deduplication is performed.
    """
    columns: dict[str, list] = {name: [] for name in COLUMNS}
    for command in commands:
        if not command.pgm or not command.record_id:
            raise ValueError("Command requires nonempty pgm and record_id")
        separators = r"[/\\]" if command.os == "windows" else "/"
        columns["pgm"].append(command.pgm)
        columns["pgm_base"].append(re.split(separators, command.pgm)[-1])
        columns["args"].append(command.args)
        columns["shell_input"].append(command.shell_input)
        columns["other_tokens"].append(command.other_tokens)
        columns["dataset"].append(dataset)
        columns["record_id"].append(command.record_id)
        columns["label"].append(command.label)
        columns["group_id"].append(command.group_id)
        columns["session_id"].append(
            command.session_id or f"{dataset}:record:{command.record_id}"
        )
        columns["os"].append(command.os)
    return pa.table(columns, schema=SCHEMA)


def _insert(con, batch):
    con.register("ingest_batch", batch)
    try:
        # Autocommit makes each batch atomic, including constraint/commit failures.
        con.execute("INSERT INTO COMMANDS (" + ", ".join(COLUMNS) + ") SELECT "
                    + ", ".join(COLUMNS) + " FROM ingest_batch")
    finally:
        con.unregister("ingest_batch")


def _connect(options, scratch):
    return duckdb.connect(str(options.db), config={
        "memory_limit": options.memory_limit,
        "threads": 1,
        "preserve_insertion_order": False,
        "temp_directory": str(scratch),
    })


def _commit(con, batch, dataset, count, started, write_seconds):
    batch_started = monotonic()
    _insert(con, batch)
    batch_seconds = monotonic() - batch_started
    write_seconds += batch_seconds
    elapsed = monotonic() - started
    print(
        f"{dataset}: {count:,} commands processed (batches committed); "
        f"{elapsed:.1f}s elapsed, {count / elapsed:,.0f} commands/s; "
        f"batch write {batch_seconds:.2f}s, "
        f"total write {write_seconds:.2f}s",
        file=sys.stderr,
        flush=True,
    )
    return write_seconds


def run(dataset_dir, records_callable):
    """Commit bounded batches and track successful runs per dataset.

    records_callable(root, options) yields Commands, or pyarrow Tables built
    by command_table(); each Table is committed as one batch, in order.
    Completed datasets are skipped. Otherwise, discard the previous attempt
    before reading. Failures leave ingested=false; a retry starts over. A
    successful complete run sets it true; bounded inspections remain retryable.
    """
    root = Path(dataset_dir).resolve()
    options = arguments(root)
    options.db.parent.mkdir(parents=True, exist_ok=True)
    scratch = root.parent.parent / "tmp" / "ingest" / "duckdb-spill"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="duckdb-", dir=scratch) as spill:
        con = _connect(options, spill)
        started = monotonic()
        write_seconds = 0.0
        count = 0
        commands: list[Command] = []
        try:
            con.execute("CREATE TABLE IF NOT EXISTS INGESTED (dataset VARCHAR, ingested BOOLEAN)")
            existing = con.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name='COMMANDS' ORDER BY ordinal_position"
            ).fetchall()
            if existing and [row[0] for row in existing] != list(COLUMNS):
                raise ValueError(
                    "COMMANDS uses an older schema. Use --db with a new database "
                    "and reingest the datasets to populate shell_input and other_tokens."
                )
            if con.execute(
                "SELECT 1 FROM INGESTED WHERE dataset=? AND ingested=true LIMIT 1", [root.name]
            ).fetchone():
                print(
                    json.dumps({"dataset": root.name, "processed": 0, "skipped": True, "db": str(options.db)}),
                    flush=True,
                )
                return
            _initialize(con)
            con.execute("BEGIN TRANSACTION")
            try:
                con.execute("DELETE FROM COMMANDS WHERE dataset=?", [root.name])
                con.execute("DELETE FROM INGESTED WHERE dataset=?", [root.name])
                con.execute("INSERT INTO INGESTED VALUES (?, false)", [root.name])
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise
            records = iter(records_callable(root, options))
            try:
                for item in records:
                    if isinstance(item, pa.Table):
                        # Readers that build batches in worker processes yield
                        # command_table() results; earlier Commands go first.
                        if commands:
                            batch = command_table(commands, root.name)
                            write_seconds = _commit(
                                con, batch, root.name, count, started, write_seconds
                            )
                            commands.clear()
                        if options.limit is not None:
                            item = item.slice(0, options.limit - count)
                        count += item.num_rows
                        write_seconds = _commit(
                            con, item, root.name, count, started, write_seconds
                        )
                    else:
                        commands.append(item)
                        count += 1
                        if len(commands) >= options.batch_size:
                            batch = command_table(commands, root.name)
                            write_seconds = _commit(
                                con, batch, root.name, count, started, write_seconds
                            )
                            commands.clear()
                    if options.limit is not None and count >= options.limit:
                        break
            finally:
                close = getattr(records, "close", None)
                if close is not None:
                    close()
            print(
                f"{root.name}: committing {count:,} commands", file=sys.stderr, flush=True
            )
            if commands:
                batch = command_table(commands, root.name)
                batch_started = monotonic()
                _insert(con, batch)
                write_seconds += monotonic() - batch_started
            complete = all(getattr(options, key) is None for key in ("limit", "max_records", "sample_files"))
            con.execute("UPDATE INGESTED SET ingested=? WHERE dataset=?", [complete, root.name])
            elapsed = monotonic() - started
            print(
                f"{root.name}: finished in {elapsed:.1f}s; "
                f"read/normalize {elapsed - write_seconds:.2f}s, "
                f"write {write_seconds:.2f}s",
                file=sys.stderr, flush=True,
            )
            print(
                json.dumps(
                    {
                        "dataset": root.name,
                        "processed": count,
                        "stored": count,
                        "db": str(options.db),
                    }
                ),
                flush=True,
            )
        finally:
            con.close()
