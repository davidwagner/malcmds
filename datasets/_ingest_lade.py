"""Read LADE's canonical sequences, using static parsers for each shell."""

import contextlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

from _ingest import Command, normalize, select_files, shell_commands
from _ingest_acme import ordinary_launch
from _ingest_windows import Budget

ARCHIVE = "lade.tar.gz"
RUNTIME = "powershell-7.6.6-linux-x64.tar.gz"
ANNOTATIONS = "aviator-ground-truth-and-tools.tar.gz"
GROUND_TRUTH = re.compile(r"\[ Code-snippet \]:\s*\n(.*?)\n\[ Resolved Code \]:.*?\[ GROUND-TRUTH & ALL INFORMATION \]:\s*\n(.*?)(?=\n-{10,}|\Z)", re.DOTALL)
PROCESS = re.compile(r'^(?:"[^"\n]+\.exe"|[^\s"\n]+\.exe|Auditpol|WevtUtil|logman)(?:\s|$)', re.IGNORECASE)


@contextlib.contextmanager
def powershell(root=None):
    """Start a parser-only PowerShell worker, installing the fetched runtime locally."""
    executable = os.environ.get("LADE_PWSH") or shutil.which("pwsh")
    if not executable:
        root = root or Path(__file__).parent / "lade"
        scratch = root.parent.parent / "tmp" / "lade-powershell-7.6.6"
        executable = str(scratch / "pwsh")
        if not Path(executable).exists():
            scratch.mkdir(parents=True, exist_ok=True)
            with tarfile.open(root / RUNTIME) as runtime:
                runtime.extractall(scratch, filter="data")
            Path(executable).chmod(0o755)
    with subprocess.Popen(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
         str(Path(__file__).with_name("_lade_powershell.ps1"))],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8",
    ) as process:
        try:
            yield process
        finally:
            process.stdin.close()
            process.wait()
            if process.returncode:
                raise RuntimeError(f"PowerShell syntax parser failed with status {process.returncode}")


def ps_commands(text, parser, other=True):
    """Return only AST command invocations, preserving expressions without evaluation."""
    parser.stdin.write(json.dumps({"text": text, "other": other}) + "\n")
    parser.stdin.flush()
    line = parser.stdout.readline()
    if not line:
        raise RuntimeError("PowerShell syntax parser ended before returning its result")
    for row in json.loads(line):
        yield row["program"], row["arguments"], row["other"]


def cmd_tokens(text):
    """Tokenize cmd quoting, caret escapes, separators and redirections statically."""
    tokens = []
    word = []
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        if not quoted and not word:
            redirect = re.match(r"\d*[<>]{1,2}(?:&\d+)?", text[index:])
            if redirect:
                tokens.append(redirect[0])
                index += len(redirect[0])
                continue
        if char == "^" and index + 1 < len(text):
            word.append(text[index:index + 2])
            index += 2
            continue
        if char == '"':
            quoted = not quoted
        if not quoted and (char.isspace() or char in "&|<>"):
            if word:
                tokens.append("".join(word))
                word = []
            if char in "&|<>":
                if index + 1 < len(text) and text[index + 1] == char:
                    char += char
                    index += 1
                tokens.append(char)
            elif char in "\r\n" and (not tokens or tokens[-1] != "\n"):
                tokens.append("\n")
        else:
            word.append(char)
        index += 1
    if word:
        tokens.append("".join(word))
    return tokens


def cmd_commands(text):
    """Split cmd command lists and omit redirects from each process's arguments."""
    tokens = cmd_tokens(text)
    groups = []
    current = []
    redirect = False
    for index, token in enumerate(tokens):
        if token in {"&", "&&", "|", "||", "\n"}:
            if current:
                groups.append(current)
            current = []
            redirect = False
        elif re.fullmatch(r"\d*[<>]{1,2}(?:&\d+)?", token):
            redirect = "&" not in token
        elif redirect:
            redirect = False
        else:
            current.append(index)
    if current:
        groups.append(current)
    for indices in groups:
        words = [tokens[i] for i in indices]
        if words[0].lower() in {"rem", "::"}:
            continue
        argv = [re.sub(r"\^(.)", r"\1", token.replace('"', "")) for token in words]
        if not argv[0]:
            continue
        yield argv[0], argv[1:], [token for i, token in enumerate(tokens)
                                  if i not in indices and token != "\n"]


def inferred_platform(text, platform):
    """Resolve unspecified platforms from unambiguous Unix paths or shell names."""
    platform = platform.lower()
    if any(name in platform for name in ("linux", "windows", "powershell", "psh", "pwsh")):
        return platform
    if re.match(r"^(?:/[^\s]+|(?:ba|da|z|k)?sh|sudo|env)(?:\s|$)", text.lstrip()):
        return "platform.linux.proc.command" if ".proc." in platform else "platform.linux.sh.command"
    return "Windows PowerShell"


def snippet_commands(text, platform, *, parser=None, other=True):
    """Yield program, arguments and omitted tokens using the declared command syntax."""
    platform = inferred_platform(text, platform)
    if ".proc." in platform:
        for program, args in normalize(text, os="linux" if "linux" in platform else "windows"):
            yield program, args, []
    elif "linux" in platform:
        yield from shell_commands(text)
    elif ".cmd." in platform and not re.search(r"\$[?\w]|\bif\s*\(", text):
        yield from cmd_commands(text)
    else:
        if parser is None:
            with powershell() as worker:
                yield from ps_commands(text, worker, other)
        else:
            yield from ps_commands(text, parser, other)


def sequence_snippets(text, name):
    """Select original GroundTruth snippets or the full processed sequence once."""
    if "/GroundTruth/" in name:
        for match in GROUND_TRUTH.finditer(text):
            code, information = match.groups()
            platform = re.search(r"^- PLATFORM:\s*(.*)$", information, re.MULTILINE)
            truth = re.search(r"^- GROUND-TRUTH:\s*(.*)$", information, re.MULTILINE)
            label = "benign" if truth and "BENIGN" in truth[1] else "malicious"
            yield code.strip(), platform[1] if platform else "unknown", label, True
        return
    label = "benign" if "Benign_labeled_sequences" in name else "malicious-group"
    # Processed sequences omit snippet delimiters. Preserve multiline scripts,
    # but remove recognisable process telemetry lines before AST parsing.
    pending = []
    for line in text.splitlines(keepends=True):
        if PROCESS.match(line):
            if "".join(pending).strip():
                yield "".join(pending).strip(), "Windows PowerShell", label, False
            pending = []
            yield line.strip(), "platform.windows.proc.command", label, False
        else:
            pending.append(line)
    if "".join(pending).strip():
        yield "".join(pending).strip(), "Windows PowerShell", label, False


def command_key(program, args):
    """Match annotated commands by executable basename and exact argument values."""
    return program.replace("\\", "/").rsplit("/", 1)[-1].lower(), tuple(args)


def scenario_annotations(root, parser):
    """Read explicit attack commands from the matching original AVIATOR plans."""
    result = {}
    with tarfile.open(root / ANNOTATIONS) as archive:
        for member in archive:
            if not member.isfile() or "/ground_truth/" not in member.name or not member.name.endswith(".sh"):
                continue
            relative = member.name.split("/ground_truth/", 1)[1]
            actor, filename = relative.split("/", 1)
            scenario = "2" if "scenario2" in filename else "1"
            keys = result.setdefault((actor, scenario), set())
            text = archive.extractfile(member).read().decode("utf-8-sig")
            text = text.split("scenario start", 1)[-1].split("scenario end", 1)[0]
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for program, args, _ in ps_commands(line, parser, False):
                    name, arguments = command_key(program, args)
                    # Scenario scripts also drive SSH, collection and prompts.
                    # A shared bare shell launch is insufficient attribution.
                    if not args or name in {"echo", "ssh", "sleep", "exit", "cd", "shell", "sessions"}:
                        continue
                    keys.add((name, arguments))
    return result


def scenario_key(source):
    """Recover AVIATOR's actor and scenario from the released sequence filename."""
    name = Path(source).name.lower()
    for actor in ("oilrig_ext", "sandworm_ext", "wizard_spider", "oilrig", "sandworm", "apt29"):
        if actor.replace("_", "") in name.replace("_", ""):
            return actor, "2" if "scenario2" in name else "1"
    return None


def best_label(program, args, label, annotations):
    """Prefer ordinary launch evidence and exact scenario matches to sequence labels."""
    name, arguments = command_key(program, args)
    if ordinary_launch(program, args):
        return "benign"
    if label == "malicious" and name in {"sleep", "start-sleep", "out-null", "cd", "set-location"}:
        return "benign"
    if label == "malicious-group" and (name, arguments) in annotations:
        return "malicious"
    return label


def records(root, options):
    """Read all 133 canonical LADE sequences, preserving source occurrence IDs."""
    budget = Budget(options)
    with tarfile.open(root / ARCHIVE) as archive, powershell(root) as parser:
        annotations = scenario_annotations(root, parser)
        members = [m for m in archive if m.isfile() and m.name.endswith(".txt")
                   and "/APT_labeled_sequences/Processed/" not in m.name]
        selected = {str(p) for p in select_files([Path(m.name) for m in members], options)}
        for member in members:
            if member.name not in selected:
                continue
            source = member.name.split("/", 1)[1]
            text = archive.extractfile(member).read().decode("utf-8-sig")
            for number, (code, platform, label, submitted) in enumerate(sequence_snippets(text, source), 1):
                if not budget.take():
                    return
                platform = inferred_platform(code, platform)
                for index, (program, args, other) in enumerate(snippet_commands(code, platform, parser=parser, other=submitted)):
                    final = best_label(program, args, label, annotations.get(scenario_key(source), set()))
                    group = f"lade:{source}" if final == "malicious-group" else None
                    yield Command(program, args, f"{source}:{number}:{index}", label=final,
                                  group_id=group, os="linux" if "linux" in platform.lower() else "windows",
                                  shell_input=code if submitted and ".proc." not in platform else None,
                                  other_tokens=other if submitted and ".proc." not in platform else [])
