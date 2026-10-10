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
        self.db.execute('CREATE TABLE commands (identity TEXT PRIMARY KEY, priority INTEGER, command TEXT, attack INTEGER)')

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
            'INSERT INTO commands VALUES (?,?,?,?) ON CONFLICT(identity) DO UPDATE SET attack=max(attack,excluded.attack), command=CASE WHEN excluded.priority > priority THEN excluded.command ELSE command END, priority=max(priority,excluded.priority)',
            (json.dumps(identity), priority, json.dumps(asdict(command)), int(command.label == "malicious")),
        )

    def commands(self):
        """Yield the selected commands in deterministic process-identity order."""
        for text, attack in self.db.execute('SELECT command,attack FROM commands ORDER BY identity'):
            command = Command(**json.loads(text))
            if attack:
                command.label, command.group_id = 'malicious', None
            yield command
