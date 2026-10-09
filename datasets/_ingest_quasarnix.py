"""Read every published QuasarNix command string without executing its contents."""

import argparse
import ast
import json
import re
import warnings
from collections.abc import Iterator
from pathlib import Path

from _ingest import Command, select_files, shell_commands

FILES = (
    'X_train_malicious_cmd_orig.json', 'X_train_malicious_cmd_adv.json',
    'X_test_malicious_cmd_orig.json', 'X_test_malicious_cmd_adv.json', 'nl2bash.json',
)


def _background(text):
    # The published JSON contains invalid backslash escapes and literal controls.
    # Repair only invalid JSON escapes; valid escapes retain their JSON meaning.
    repaired = []
    quoted = False
    i = 0
    while i < len(text):
        char = text[i]
        if char == '"':
            quoted = not quoted
        if quoted and char == '\\' and i + 1 < len(text):
            next_char = text[i + 1]
            valid = next_char in '"\\/bfnrt' or (
                next_char == 'u' and re.fullmatch(r'[0-9a-fA-F]{4}', text[i + 2:i + 6])
            )
            if valid:
                repaired.extend((char, next_char))
                i += 2
                continue
            repaired.append('\\')
        repaired.append(char)
        i += 1
    return json.loads(''.join(repaired), strict=False)


def _print_only(pgm, args):
    if not Path(pgm).name.startswith('python') or '-c' not in args:
        return False
    index = args.index('-c') + 1
    if index >= len(args):
        return False
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(args[index])
    except (SyntaxError, ValueError):
        return False
    return bool(tree.body) and all(
        isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name) and node.value.func.id == 'print'
        and all(isinstance(arg, ast.Constant) for arg in node.value.args)
        and not node.value.keywords
        for node in tree.body
    )


def _label(pgm, args, text):
    if _print_only(pgm, args):
        return 'benign'
    name = Path(pgm).name
    invocation = ' '.join(args)
    if name in ('sh', 'bash', 'dash', 'zsh', 'ksh'):
        if re.search(r'/dev/(tcp|udp)/', text) and (
            any(arg.startswith('-') and 'i' in arg for arg in args) or re.search(r'<&\d', text)
        ):
            return 'malicious'
        if '-c' in args and re.search(r'/dev/(tcp|udp)/|socket|\bnc\b|\btelnet\b', invocation):
            return 'malicious'
    if name == 'rcat' and '-r' in args:
        return 'malicious'
    if name in ('nc', 'ncat', 'netcat', 'socat') and (
        any(arg in ('-e', '-c', '--exec') for arg in args) or 'exec:' in invocation.lower()
    ):
        return 'malicious'
    if re.match(r'^(?:python[\d.]*|perl|php|ruby|lua[\d.]*|awk|gawk)$', name) and re.search(
        r'socket|fsockopen|TCPSocket|/inet/(tcp|udp)|Socket', invocation
    ):
        return 'malicious'
    return 'malicious-group'


def records(root: Path, options: argparse.Namespace) -> Iterator[Command]:
    """Import all five arrays with source-occurrence IDs and command-level labels."""
    paths = [root / name for name in FILES]
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f'Missing QuasarNix release file {path}; run ./fetch')
    for path in select_files(paths, options):
        background = path.name == 'nl2bash.json'
        text = path.read_text()
        strings = _background(text) if background else json.loads(text)
        if not isinstance(strings, list) or any(not isinstance(s, str) for s in strings):
            raise ValueError(f'{path}: expected the published array of command strings')
        for index, text in enumerate(strings):
            if options.max_records is not None and index >= options.max_records:
                break
            for command_index, (pgm, args, other) in enumerate(shell_commands(text)):
                label = 'benign' if background else _label(pgm, args, text)
                yield Command(
                    pgm, args, f'{path.name}:{index}:{command_index}', label=label,
                    group_id=f'quasarnix:{path.name}:{index}' if label == 'malicious-group' else None,
                    shell_input=text, other_tokens=other,
                )
