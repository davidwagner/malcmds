"""Read shell submissions from Microsoft CMD and PowerShell 5.1 examples."""

import json
import re
import tarfile
from pathlib import Path

from _ingest import Command, ShellInput, select_files
from _ingest_lade import cmd_commands, powershell, ps_commands

RULES = json.loads((Path(__file__).resolve().parents[1] / "datasets" /
                    "microsoft-command-docs" / "extraction-rules.json").read_text())
SOURCES = (
    ("windowsserverdocs.tar.gz", "/WindowsServerDocs/administration/windows-commands/", "cmd"),
    ("powershell-docs.tar.gz", "/reference/5.1/", "powershell"),
)
PROMPT = re.compile(
    r"^(?:(?:\[[^\]]+\]:?\s*)*(?:[\w.-]+\\)?PS(?:\s+[^>]*?)?\s*>>?|[A-Za-z]+:\\[^>]*>|PC />)[ \t]*",
    re.IGNORECASE,
)


def example_blocks(text):
    """Yield globally numbered Markdown fences under an Examples heading."""
    active = 0
    fence = None
    language = ""
    lines = []
    number = 0
    for line in text.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})(.*)", line)
        if fence:
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence):
                if active:
                    yield number, language, "\n".join(lines)
                fence = None
            else:
                lines.append(line)
        elif marker:
            number += 1
            fence, language, lines = marker[1], marker[2].strip().lower(), []
        elif heading := re.match(r"^(#{1,6})\s+(.*)", line):
            level, title = len(heading[1]), heading[2]
            if re.match(r"examples?\b", title, re.IGNORECASE):
                active = level
            elif active and level <= active:
                active = 0


def continues(lines, next_line):
    """Recognize displayed continuation lines without evaluating shell text."""
    text = "\n".join(lines)
    # Quoted delimiters do not open a block. Backtick escapes stay literal.
    syntax = re.sub(r'''`.|"(?:`.|[^"`])*"|'(?:''|[^'])*'|\#.*''', "", text)
    return (text.rstrip().endswith(("|", "`", "^", ","))
            or syntax.count("{") > syntax.count("}")
            or syntax.count("(") > syntax.count(")")
            or next_line.lstrip().startswith("{"))


def submissions(code):
    """Split prompted transcripts, excluding output and retaining continuations."""
    lines = code.splitlines()
    # Prompts quoted inside a here-string or comment are part of the script.
    masked = code
    for match in reversed(list(re.finditer(r"(?ms)<#.*?#>|@(['\"])\r?\n.*?^\1@", code))):
        blank = "".join("\n" if char == "\n" else " " for char in match[0])
        masked = masked[:match.start()] + blank + masked[match.end():]
    prompts = {index for index, line in enumerate(masked.splitlines()) if PROMPT.match(line)}
    if not prompts:
        if code.strip():
            yield re.sub(r"(?m)^\s*>>\s?", "", code.strip())
        return
    pending = []
    for index, line in enumerate(lines):
        prompt = PROMPT.match(line) if index in prompts else None
        if prompt:
            if pending:
                yield "\n".join(pending).rstrip()
            command = line[prompt.end():]
            # One upstream example accidentally repeats its prompt.
            while nested := PROMPT.match(command):
                command = command[nested.end():]
            pending = [command] if command.strip() else []
        elif pending and (line.lstrip().startswith(">>") or continues(pending, line)):
            pending.append(re.sub(r"^\s*>>\s?", "", line))
        elif pending:
            yield "\n".join(pending).rstrip()
            pending = []
    if pending:
        yield "\n".join(pending).rstrip()


def document_inputs(text, source):
    """Yield stable occurrence ID, shell name and complete example input."""
    platform, relative = source.split("/", 1)
    if source in RULES["excluded_documents"] or any(
        source.startswith(prefix) for prefix in RULES["excluded_prefixes"]
    ):
        return
    if platform == "cmd" and not any(
        relative == name + ".md" or relative.startswith(name + "-")
        for name in RULES["cmd_documents"]
    ):
        return
    for number, language, code in example_blocks(text):
        if language not in {"", "cmd", "command", "cli", "shell", "powershell"}:
            continue
        shell = "powershell" if platform == "powershell" or language == "powershell" else "cmd"
        key = f"{source}:{number}"
        if key in RULES["line_ranges"]:
            lines = code.splitlines()
            chunks = ["\n".join(lines[start - 1:end]) for start, end in RULES["line_ranges"][key]]
        else:
            chunks = [code]
        occurrence = 0
        for chunk in chunks:
            for command in submissions(chunk):
                occurrence += 1
                if re.search(r"(?m)^\s*(?:\.\.\.|(?:DISKRAID|DISKPART)>|>)\s*", command):
                    continue
                # Reference placeholders are not literal executable examples.
                if re.search(r"(?<![\\^])<[A-Za-z][A-Za-z0-9_ .|/\[\]-]*>", command):
                    continue
                if shell == "cmd":
                    first = re.split(r"[\s>]+", command.lstrip("@"))[0].lower()
                    if first not in RULES["cmd_programs"] and not first.startswith((":", "cd\\", "echo.")):
                        continue
                elif not language and not re.match(
                    r"(?:[\w]+-[\w]+|\$|function\b|workflow\b|\[|\(|powershell\.exe)", command,
                    re.IGNORECASE,
                ):
                    continue
                yield f"{key}:{occurrence}", shell, command


def records(root, options):
    """Read pinned archives and create benign Windows shell and program rows."""
    count = 0
    with powershell(root) as parser:
        for filename, prefix, shell in SOURCES:
            with tarfile.open(root / filename) as archive:
                names = [member.name for member in archive
                         if member.isfile() and prefix in member.name and member.name.endswith(".md")]
                for name in select_files(names, options):
                    source = shell + "/" + name.split(prefix, 1)[1]
                    text = archive.extractfile(name).read().decode("utf-8-sig")
                    for record_id, syntax, command in document_inputs(text, source):
                        if options.max_records is not None and count >= options.max_records:
                            return
                        count += 1
                        # The CMD manual wraps long option lists without showing
                        # a continuation caret; this affects parsing, not storage.
                        parse_text = re.sub(r"\n\s*(?=/[A-Za-z])", " ", command)
                        parsed = ps_commands(command, parser) if syntax == "powershell" else cmd_commands(parse_text)
                        commands = [Command(pgm, args, f"{record_id}:{index}", label="benign", os="windows")
                                    for index, (pgm, args, _) in enumerate(parsed)]
                        yield ShellInput(command, record_id, commands, label="benign", os="windows")
