"""Temporary disk-backed selection of one representative per process."""
import json
import sqlite3
import tempfile
from dataclasses import asdict
from pathlib import Path

from _ingest import Command


class ProcessCommands:
    """Keep the preferred observation of each process without a permanent table."""

    def __init__(self):
        scratch = Path(__file__).resolve().parent.parent / 'tmp'
        scratch.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='processes-', dir=scratch)
        self.db = sqlite3.connect(str(Path(self.temporary.name) / 'commands.sqlite'))
        self.db.execute('CREATE TABLE commands (identity TEXT PRIMARY KEY, priority INTEGER, command TEXT)')

    def __enter__(self):
        """Return the bounded-memory process selector."""
        return self

    def __exit__(self, *exception):
        """Close and remove the temporary process database."""
        self.db.close()
        self.temporary.cleanup()

    def add(self, identity, command, creation=False):
        """Prefer a creation record, then the most complete command observation."""
        priority = int(creation) * 100000000 + len(command.pgm) + sum(map(len, command.args))
        self.db.execute(
            'INSERT INTO commands VALUES (?,?,?) ON CONFLICT(identity) DO UPDATE SET priority=excluded.priority, command=excluded.command WHERE excluded.priority > priority',
            (json.dumps(identity), priority, json.dumps(asdict(command))),
        )

    def commands(self):
        """Yield the selected commands in deterministic process-identity order."""
        for (text,) in self.db.execute('SELECT command FROM commands ORDER BY identity'):
            yield Command(**json.loads(text))
