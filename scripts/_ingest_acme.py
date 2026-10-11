"""LLNL ACME process summaries, including their reviewed process annotations."""

import argparse
from collections.abc import Iterator
from pathlib import Path

import duckdb
from _ingest import Command, windows_split
from pyarrow import parquet


def ordinary_launch(pgm, args):
    """Recognize narrowly defined desktop launches and normal browser helpers."""
    name = pgm.replace('\\', '/').rsplit('/', 1)[-1].lower()
    if not args and name in {'explorer.exe', 'notepad.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe'}:
        return True
    if name in {'chrome.exe', 'msedge.exe', 'chrome', 'chromium'}:
        return any(arg in {'--type=renderer', '--type=gpu-process', '--type=utility', '--type=crashpad-handler'} for arg in args) and not any(
            arg.startswith(('--load-extension', '--disable-web-security', '--remote-debugging', '--renderer-cmd-prefix', '--utility-cmd-prefix')) for arg in args
        )
    return False


def records(root: Path, options: argparse.Namespace) -> Iterator[Command]:
    """Read every process once, merging annotations across repeated summaries."""
    source = root / 'process_uber_summary.parquet'
    columns = set(parquet.ParquetFile(source).schema_arrow.names)
    if not {'pid_hash', 'args'}.issubset(columns):
        raise ValueError('ACME summary changed: expected pid_hash and argument-only args columns')
    fields = ['process_path', 'filename', 'process_name', 'args', 'hostname', 'user_name']
    selected = [f'any_value("{field}") AS "{field}"' if field in columns else f'NULL AS "{field}"' for field in fields]
    for field in ['label_num_hits', 'red_team', 'bad_user']:
        selected.append(f'max("{field}") AS "{field}"' if field in columns else f'NULL AS "{field}"')
    labels = set()
    annotation = root / 'labels_graph_process_summary.parquet'
    if annotation.exists():
        for batch in parquet.ParquetFile(annotation).iter_batches(columns=['pid_hash']):
            labels.update(batch.column(0).to_pylist())
    with duckdb.connect() as con:
        con.execute('SET threads=2')
        con.execute('SELECT pid_hash, ' + ', '.join(selected) + ' FROM read_parquet(?) GROUP BY pid_hash', [str(source)])
        count = 0
        while rows := con.fetchmany(10000):
            for identity, path, filename, name, arguments, host, user, hits, red, bad_user in rows:
                if options.max_records is not None and count >= options.max_records:
                    return
                count += 1
                pgm = path or filename or name
                if not pgm:
                    continue
                args = windows_split(arguments or '')
                group = None
                if ordinary_launch(pgm, args):
                    label = 'benign'
                elif identity in labels or (hits or 0) > 0:
                    label = 'malicious'
                elif bad_user:
                    label = 'malicious-group'
                    group = f'{root.name}:{host or "unknown-host"}:{user or "unknown-user"}'
                elif red == 1:
                    label = 'malicious'
                elif red == 0:
                    label = 'benign'
                else:
                    label = 'unknown'
                yield Command(pgm, args, f'{root.name}:{identity}', label=label, group_id=group, os='windows')
