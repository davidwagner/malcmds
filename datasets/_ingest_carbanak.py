"""Read process subjects from a PostgreSQL custom dump without executing SQL."""

import argparse
import csv
import os
import re
import shlex
import subprocess
from collections.abc import Iterator
from pathlib import Path

from _ingest import Command, windows_split
from _ingest_acme import ordinary_launch


def _copy_value(value):
    if value == r'\N':
        return None
    return re.sub(r'\\([0-7]{1,3}|x[0-9a-fA-F]{1,2}|.)',
                  _copy_escape, value)


def _copy_escape(match):
    value = match[1]
    if value[0] in '01234567':
        return chr(int(value, 8))
    if value[0] == 'x' and len(value) > 1:
        return chr(int(value[1:], 16))
    return {'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v'}.get(value, value)


def records(root: Path, options: argparse.Namespace) -> Iterator[Command]:
    """Join distinct attack UUIDs to each subject in the complete source dump."""
    with (root / 'ground_truth.csv').open(newline='') as stream:
        malicious = {row[0] for row in csv.reader(stream) if row}
    dump = root / 'carbanakv2_edr.dump'
    restore = os.environ.get('PG_RESTORE', 'pg_restore')
    seen = set()
    # No --dbname: pg_restore writes COPY text; no source SQL is executed.
    process = subprocess.Popen([restore, '--data-only', '--table=subject_node_table', '--file=-', str(dump)],
                               stdout=subprocess.PIPE, text=True, encoding='utf-8')
    columns = None
    found_subjects = False
    count = 0
    try:
        for line in process.stdout:
            if line.startswith('COPY public.subject_node_table ('):
                found_subjects = True
                columns = line.split('(', 1)[1].split(')', 1)[0].split(', ')
                if not {'node_uuid', 'path', 'cmd'}.issubset(columns):
                    raise ValueError('CARBANAK subject schema changed: expected node_uuid, path, cmd')
                continue
            if columns is None:
                continue
            if line.rstrip('\n') == r'\.':
                columns = None
                continue
            if options.max_records is not None and count >= options.max_records:
                return
            count += 1
            values = [_copy_value(value) for value in line.rstrip('\n').split('\t')]
            if len(values) != len(columns):
                raise ValueError('Malformed CARBANAK subject COPY row')
            row = dict(zip(columns, values))
            identity = row['node_uuid']
            if identity in seen:
                continue
            seen.add(identity)
            pgm = row['path']
            if not pgm or pgm == 'None':
                continue
            platform = 'windows' if re.match(r'^[a-zA-Z]:[\\/]', pgm) or '\\' in pgm else 'linux'
            text = row['cmd'] or ''
            if text == 'None':
                text = ''
            if platform == 'windows':
                if text[:len(pgm)].lower() == pgm.lower() and (
                    len(text) == len(pgm) or text[len(pgm)].isspace()
                ):
                    text = '"' + pgm + '"' + text[len(pgm):]
                args = windows_split(text)
            else:
                try:
                    args = shlex.split(text)
                except ValueError:
                    args = text.split()
            base = pgm.replace('\\', '/').rsplit('/', 1)[-1].lower()
            if args and args[0].replace('\\', '/').lower() in {pgm.replace('\\', '/').lower(), base}:
                args = args[1:]
            label = 'benign' if ordinary_launch(pgm, args) else 'malicious' if identity in malicious else 'unknown'
            yield Command(pgm, args, identity, label=label, os=platform)
        if not found_subjects:
            raise ValueError('CARBANAK subject schema changed: pg_restore returned no subject_node_table COPY data')
        if process.wait() != 0:
            raise RuntimeError('pg_restore failed; install PostgreSQL 17+ or set PG_RESTORE to its executable')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
        process.wait()
