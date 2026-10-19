"""Shared CSV import implementation for AI labels and human overrides."""

import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path

import duckdb


def import_labels(database, table, labels, *, override=False):
    """Apply CSV labels atomically and refresh the stored final label."""
    if not database.is_file():
        raise ValueError(f'Database does not exist: {database}')
    if labels.resolve() == database.resolve():
        raise ValueError('Labels and database must be separate files')
    csv.field_size_limit(sys.maxsize)
    rows = []
    final_labels = {}
    with labels.open(newline='', encoding='utf-8') as stream:
        for number, row in enumerate(csv.reader(stream, strict=True), 1):
            if (len(row) < 2 or row[0] not in ('malicious', 'benign', 'unknown')
                    or (table == 'SHELL_INPUTS' and len(row) != 2)):
                raise ValueError(f'Invalid CSV record {number}: expected label and exact command fields')
            command = tuple(row[1:])
            rows.append((row[0], command))
            final_labels[command] = row[0]

    column = 'override_label' if override else 'ai_label'
    label_kind = 'override' if override else 'AI'
    updated = 0
    if rows:
        predicate = ('target.shell_input = incoming.command[1]' if table == 'SHELL_INPUTS'
                     else 'target.pgm = incoming.command[1] AND target.args = incoming.command[2:]')
        with duckdb.connect(str(database)) as con:
            con.execute('BEGIN')
            # One row per exact command keeps both joins bounded by the table size,
            # even when the CSV and database contain many copies of that command.
            # Bind only a file path, not a huge constant that the binder SQL-escapes.
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.jsonl') as staged:
                maximum_object_size = 16 * 1024 * 1024
                for command, label in final_labels.items():
                    record = json.dumps({'command': command, 'label': label})
                    staged.write(record + '\n')
                    maximum_object_size = max(maximum_object_size, len(record) + 1)
                staged.flush()
                con.execute('''CREATE TEMP TABLE incoming AS
                    SELECT * FROM read_json(?, format='newline_delimited',
                        columns={command: 'VARCHAR[]', label: 'VARCHAR'},
                        maximum_object_size=?)''',
                    [staged.name, maximum_object_size])
            counts = {}
            for command, old_label, count in con.execute(f'''
                    SELECT incoming.command, target.{column}, count(*)
                    FROM {table} AS target JOIN incoming ON {predicate}
                    GROUP BY incoming.command, target.{column} ORDER BY target.{column}''').fetchall():
                counts.setdefault(tuple(command), {})[old_label] = count

            # Replay only the label counts in CSV order, without querying or updating
            # the database per record. A repeated record sees the previous CSV label.
            for number, (label, command) in enumerate(rows, 1):
                previous = counts.get(command, {})
                count = sum(previous.values())
                for old_label, conflicts in previous.items():
                    if conflicts and old_label in ('benign', 'malicious') and old_label != label:
                        description = (f'shell_input={command[0]!r}' if table == 'SHELL_INPUTS'
                                       else f'pgm={command[0]!r}, args={list(command[1:])!r}')
                        print(f'Warning: CSV record {number} overwrites {conflicts} conflicting {label_kind} labels: '
                              f'{old_label!r} -> {label!r}; {description}', file=sys.stderr)
                counts[command] = {label: count}
                updated += count

            final_label = (
                'incoming.label' if override else
                "COALESCE(target.override_label, NULLIF(incoming.label, 'unknown'), "
                "NULLIF(target.dataset_label::VARCHAR, 'malicious-group'), 'unknown')"
            )
            con.execute(f'''UPDATE {table} AS target
                SET {column} = incoming.label, label = {final_label}
                FROM incoming WHERE {predicate}''')
            con.execute('COMMIT')
    print(f'Updated {updated} matching rows.')


def main(description, *, override=False):
    """Read import options and report invalid input without a traceback."""
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--db', type=Path, default=Path('cmds.duckdb'))
    parser.add_argument('--table', choices=('SHELL_INPUTS', 'PROCESS_LAUNCHES'), required=True)
    parser.add_argument('--labels', type=Path, required=True)
    options = parser.parse_args()
    try:
        import_labels(options.db, options.table, options.labels, override=override)
    except (OSError, ValueError, csv.Error, duckdb.Error) as error:
        parser.exit(1, f'{parser.prog}: {error}\n')
