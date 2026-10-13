"""Fill the pinned tldr examples using checked-in, exact substitution rules."""

import hashlib
import json
import random
import re
import shlex
import sys
import tarfile
from pathlib import Path

from _ingest import Command, ShellInput, select_files, shell_commands
from _ingest_lade import cmd_commands

ARCHIVE = "tldr.tar.gz"
DATA = Path(__file__).resolve().parents[1] / "datasets" / "tldr-pages"
PLACEHOLDER = re.compile(r"{{(.*?)}}")


def _quote_context(prefix, shell):
    quote = None
    escape = "\\" if shell == "bash" else "^"
    skip = False
    for char in prefix:
        if skip:
            skip = False
        elif char == escape and quote != "'":
            skip = True
        elif char == quote:
            quote = None
        elif quote is None and char in ('"', "'"):
            quote = char
    return quote


def _render(value, prefix, shell, kind):
    if kind == "fragment":
        return value
    if kind == "glob":
        return _render(value[:-2], prefix, shell, "argument") + "/*"
    quote = _quote_context(prefix, shell)
    if shell == "bash":
        if quote == "'":
            return value.replace("'", "'\"'\"'")
        if quote == '"':
            return re.sub(r'([\\"$`])', r'\\\1', value)
        return shlex.quote(value)
    if quote == '"':
        return value.replace('"', '""')
    if re.search(r'[\s&|<>^()]', value):
        return '"' + value.replace('"', '""') + '"'
    return value


def variants(template, example_id, shell, pools, rules, *, seed=0, count=3):
    """Yield reproducible concrete inputs; unknown placeholders fail by location.

    Rules name an exact placeholder or override it for one source example.
    ``bind`` shares the pool index among related arguments, so source and
    destination paths retain the same filename. Repeated placeholders always
    share their selected value. ``fragment`` values represent shell syntax;
    ordinary argument values are escaped in their surrounding quote context.
    """
    matches = list(PLACEHOLDER.finditer(template))
    if not matches:
        if '{{' in template or '}}' in template:
            raise ValueError(f"{example_id}: malformed template markup")
        yield 0, template
        return
    overrides = rules.get("examples", {}).get(example_id, {}).get("placeholders", {})
    for variant in range(count):
        digest = hashlib.sha256(json.dumps([seed, example_id, variant]).encode()).digest()
        rng = random.Random(int.from_bytes(digest, "big"))
        values = {}
        bindings = {}
        parts = []
        end = 0
        for match in matches:
            name = match[1]
            rule = overrides.get(name, rules["placeholders"].get(name))
            if rule is None:
                raise ValueError(f"{example_id}: no substitution rule for {name!r}")
            if name not in values:
                choices = rule.get("values")
                if choices is None:
                    pool = rule["pool"].replace("{os}", "linux" if shell == "bash" else "windows")
                    choices = pools[pool]
                if not choices:
                    raise ValueError(f"{example_id}: empty substitution pool for {name!r}")
                if "bind" in rule:
                    key = rule["bind"]
                    if key not in bindings:
                        bindings[key] = rng.randrange(len(choices))
                    choice = bindings[key] % len(choices)
                else:
                    choice = rng.randrange(len(choices))
                value = choices[choice]
                if "extension" in rule:
                    value = re.sub(r'\.[^./\\]+$', '', value) + rule["extension"]
                if "suffix" in rule:
                    value = re.sub(r'(\.[^./\\]+)?$', rule["suffix"] + r'\1', value, count=1)
                if rule.get("glob"):
                    value += "/*"
                values[name] = value
            parts.append(template[end:match.start()])
            parts.append(_render(values[name], template[:match.start()], shell, rule.get("kind", "argument")))
            end = match.end()
        parts.append(template[end:])
        text = ''.join(parts)
        if '{{' in text or '}}' in text:
            raise ValueError(f"{example_id}: unresolved template markup in {text!r}")
        yield variant, text


def examples(root, options, rules):
    """Yield shell examples in source order, excluding documented interactive input."""
    with tarfile.open(root / ARCHIVE, "r:gz") as archive:
        members = {}
        for member in archive:
            parts = Path(member.name).parts
            if (member.isfile() and len(parts) == 4 and parts[1] == "pages"
                    and parts[2] in {"common", "linux", "windows"}
                    and parts[3].endswith(".md")):
                members['/'.join(parts[2:])] = member
        if not members:
            raise ValueError(f"{root / ARCHIVE}: no English tldr pages")
        scanned = 0
        for path in select_files([Path(name) for name in members], options):
            name = path.as_posix()
            with archive.extractfile(members[name]) as stream:
                lines = stream.read().decode("utf-8").splitlines()
            for number, line in enumerate(lines, 1):
                if not (line.startswith('`') and line.endswith('`')):
                    continue
                if options.max_records is not None and scanned >= options.max_records:
                    return
                scanned += 1
                identity = f"{name}:{number}"
                rule = rules["examples"].get(identity, {})
                if "skip" in rule:
                    continue
                template = rule.get("template", line[1:-1])
                yield identity, "cmd" if path.parts[0] == "windows" else "bash", template


def records(root, options):
    """Generate benign complete inputs and statically parsed program invocations."""
    pools = json.loads((DATA / "pools.json").read_text())
    rules = json.loads((DATA / "rules.json").read_text())
    inputs = 0
    for identity, shell, template in examples(root, options, rules):
        for variant, text in variants(template, identity, shell, pools, rules,
                                      seed=rules["seed"], count=rules["count"]):
            record = f"{identity}:{variant}"
            osname = "linux" if shell == "bash" else "windows"
            parsed = shell_commands(text) if shell == "bash" else cmd_commands(text)
            commands = [Command(program, args, f"{record}:{index}", label="benign", os=osname)
                        for index, (program, args, _) in enumerate(parsed)]
            inputs += 1
            yield ShellInput(text, record, commands, label="benign", os=osname)
    print(f"tldr-pages: generated {inputs:,} complete shell inputs", file=sys.stderr)
