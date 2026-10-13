"""Import pinned command-example tables while preserving complete source strings."""

import argparse
import csv
import json
import sys
from collections.abc import Iterator
from pathlib import Path

import pyarrow.parquet as pq
from _ingest import Command, ShellInput, select_files, shell_commands
from _ingest_quasarnix import reference_commands

FILES = {
    'nl2sh-alfa': ('train.csv', 'test.csv'),
    'mecha': ('linuxcommands.json',),
    'shellrisk-bench': ('data/train-00000-of-00001.parquet', 'data/test-00000-of-00001.parquet'),
    'cli-commands-explained': ('cli_commands_explained.json',),
}


def command_text(text: str, occurrence: str) -> str:
    """Remove the three inspected Markdown wrappers in the pinned releases."""
    if text.startswith('```toml\n'):
        # CLI Commands Explained has two configuration examples. Only one
        # includes a command, immediately following the closing TOML fence.
        _, separator, command = text.partition('\n```')
        if not separator:
            raise ValueError(f'{occurrence}: unclosed configuration example')
        return command.removeprefix('\n')
    if text.startswith('```') and text.endswith('```'):
        # ALFA has one inline fenced shell command, with no language marker.
        return text[3:-3]
    return text


def source_rows(path: Path) -> Iterator[dict]:
    """Read source records in original order without modifying command text."""
    if path.suffix == '.csv':
        with path.open(encoding='utf-8', newline='') as stream:
            yield from csv.DictReader(stream)
    elif path.suffix == '.parquet':
        with pq.ParquetFile(path) as source:
            for batch in source.iter_batches(columns=['command', 'label']):
                yield from batch.to_pylist()
    else:
        rows = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(rows, list):
            raise ValueError(f'{path}: expected an array of source records')
        yield from rows


def records(root: Path, options: argparse.Namespace) -> Iterator[ShellInput]:
    """Label full submissions and parsed invocations, excluding exact QuasarNix overlap."""
    dataset = root.name
    paths = [root / name for name in FILES[dataset]]
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f'Missing release file {path}; run ./fetch')
    filtered = dataset in ('nl2sh-alfa', 'shellrisk-bench')
    reference = reference_commands(root.parent / 'quasarnix') if filtered else set()
    examined = removed = 0
    try:
        for path in select_files(paths, options):
            for index, row in enumerate(source_rows(path)):
                if options.max_records is not None and index >= options.max_records:
                    break
                label = 'unknown' if dataset == 'cli-commands-explained' else 'benign'
                if dataset == 'nl2sh-alfa':
                    fields = ('bash', 'bash2') if path.name == 'test.csv' else ('bash',)
                elif dataset == 'mecha':
                    fields = ('output',)
                elif dataset == 'shellrisk-bench':
                    fields = ('command',)
                    risk = row.get('label')
                    if risk not in ('not_risky', 'risky'):
                        raise ValueError(f'{path}:{index}: unexpected risk label {risk!r}')
                    label = 'benign' if risk == 'not_risky' else 'unknown'
                else:
                    fields = ('code',)
                for field in fields:
                    occurrence = f'{path.relative_to(root).as_posix()}:{index}:{field}'
                    text = row.get(field)
                    if not isinstance(text, str):
                        raise TypeError(f'{occurrence}: expected command text')
                    text = command_text(text, occurrence)
                    if not text.strip():
                        continue
                    examined += 1
                    if text in reference:
                        removed += 1
                        continue
                    commands = [Command(pgm, args, f'{occurrence}:{number}', label=label)
                                for number, (pgm, args, _) in enumerate(shell_commands(text))]
                    yield ShellInput(text, occurrence, commands, label=label)
    finally:
        if filtered:
            print(json.dumps({'dataset': dataset, 'candidates_examined': examined,
                              'quasarnix_overlap_removed': removed}), file=sys.stderr)
