"""Stream the native CDM18/CDM20 Avro command observations."""

import gzip
import hashlib
import json
import re
import shlex
import sqlite3
import sys
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import fastavro
from _ingest import Command, normalize, select_files

# Successful attacks described in TC_Ground_Truth_Report_E3_Update.pdf,
# sections 3 and 4. Dates refer to the attack host's calendar day.
E3_DAYS = {
    'cadets': {'2018-04-06', '2018-04-11', '2018-04-12', '2018-04-13'},
    'fivedirections': {'2018-04-09', '2018-04-11', '2018-04-12', '2018-04-13'},
    'theia': {'2018-04-10', '2018-04-12', '2018-04-13'},
    'trace': {'2018-04-10', '2018-04-12', '2018-04-13'},
}
# TA51_Final_report_E5.pdf sections 4.3, 4.4, 5.2, 7.3, 8.4, 8.6,
# 9.3, 9.4, 10.4, 10.6, 10.8 and 10.11. Explicit host instances only.
E5_DAYS = {
    'cadets-1': {'2019-05-10', '2019-05-16', '2019-05-17'},
    'cadets-2': {'2019-05-16', '2019-05-17'},
    'fivedirections-1': {'2019-05-16', '2019-05-17'},
    'fivedirections-2': {'2019-05-09', '2019-05-15'},
    'fivedirections-3': {'2019-05-10', '2019-05-17'},
    'marple-1': {'2019-05-09', '2019-05-17'},
    'theia-1': {'2019-05-10', '2019-05-15'},
    'trace-2': {'2019-05-10', '2019-05-14'},
}
EASTERN = ZoneInfo('America/New_York')


def identifier(value):
    """Convert Avro fixed UUID values, including named union values, to text."""
    if isinstance(value, tuple):
        value = value[1]
    if isinstance(value, bytes):
        return str(uuid.UUID(bytes=value)) if any(value) else ''
    return str(value) if value else ''


def avro_blocks(stream, source):
    """Recover after malformed records using the container's block boundaries."""
    for number, block in enumerate(fastavro.block_reader(
        stream, return_record_name=True, handle_unicode_errors='replace'
    )):
        try:
            yield from block
        except (EOFError, ValueError, IndexError, OverflowError) as error:
            print(f'{source}: malformed Avro block {number}; skipping remainder: {error}',
                  file=sys.stderr)


def avro_records(path):
    """Read gzip Avro or every regular Avro member in an E3 tar archive."""
    if '.tar.' in path.name:
        with tarfile.open(path, 'r|gz') as archive:
            for member in archive:
                if member.isfile() and '.bin' in member.name:
                    stream = archive.extractfile(member)
                    assert stream is not None  # Regular tar members always have a stream.
                    with stream:
                        yield from avro_blocks(stream, f'{path.name}:{member.name}')
    else:
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rb') as stream:
            yield from avro_blocks(stream, path.name)


def command_line(text, collector, pgm=None, require_arguments=True):
    """Normalize captured argv text without interpreting it as typed shell input."""
    if not text or text.strip() in {'N/A', '(null)', 'null', '<unknown>'}:
        return []
    text = text.removesuffix('\0') if '\0' in text else text.strip()
    # Titles such as "sshd: admin [priv]" are not an executed argv vector.
    if re.match(r'^(?:sshd|sshd-session|sudo|postgres|sendmail|pickup|qmgr):\s', text):
        return []
    os_name = 'windows' if collector in {'fivedirections', 'marple'} else 'linux'
    if os_name == 'linux' and '\0' in text:
        tokens = text.split('\0')
    elif collector == 'trace':
        # TRACE's audit exporter concatenates a0..aN; audit hex strings each
        # represent one argv item, even when decoded bytes contain whitespace.
        tokens = shlex.split(text)
        for index, token in enumerate(tokens):
            if len(token) >= 4 and len(token) % 2 == 0 and re.fullmatch('[0-9A-F]+', token):
                try:
                    decoded = bytes.fromhex(token).decode('utf-8')
                except UnicodeDecodeError:
                    continue
                if any(c.isspace() or c in '\\"' for c in decoded):
                    tokens[index] = decoded
    else:
        commands = normalize(text, os=os_name, shell=False)
        if not commands:
            return []
        executable, args = commands[0]
        tokens = [executable, *args]
    # Flattened, unquoted shell -c observations lose the script's argv boundary.
    # Infer one script argument from the remainder; quoted strings and decoded
    # audit hex tokens already preserve that argument.
    if os_name == 'linux' and tokens and Path(tokens[0]).name in {'sh', 'bash', 'dash', 'ksh', 'zsh'}:
        match = re.match(r'^\S+\s+(-[a-zA-Z]*c)\s+(.+)$', text, re.DOTALL)
        if match and match[2][0] not in "\"'" and len(tokens) > 3:
            tokens = [tokens[0], match[1], match[2]]
    # Check the parsed executable: raw whitespace splitting can be empty, split
    # a quoted executable, or include NUL-delimited arguments in the first word.
    if (not tokens or (require_arguments and len(tokens) < 2) or not tokens[0]
            or '\ufffd' in tokens[0] or any(ord(c) < 32 for c in tokens[0])):
        return []
    return [(pgm or tokens[0], tokens[1:])]


def attack_group(dataset, instance, host, timestamp):
    """Identify explicitly attacked host/day groups, leaving other records unknown."""
    if not timestamp:
        return None
    zone = timezone.utc if '-e3-' in dataset else EASTERN
    day = datetime.fromtimestamp(timestamp / 1_000_000_000, zone).date().isoformat()
    collector = dataset.split('-')[-1]
    dates = E3_DAYS.get(collector, set()) if '-e3-' in dataset else E5_DAYS.get(instance, set())
    if day in dates:
        return f'{dataset}:{host}:attack-day:{day}'
    return None


def records(root, options):
    """Yield process command snapshots and execution records with bounded RAM."""
    collector = root.name.split('-')[-1]
    os_name = 'windows' if collector in {'fivedirections', 'marple'} else 'linux'
    paths = [p for p in (root / 'data').iterdir()
             if p.is_file() and (p.name.endswith('.gz') or re.search(r'\.bin(?:\.\d+)?$', p.name))]
    scratch = root.parents[1] / 'tmp'
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='tc-ingest-', dir=scratch) as temporary:
        db = sqlite3.connect(str(Path(temporary) / 'subjects.sqlite'))
        try:
            db.execute('PRAGMA journal_mode=OFF')
            db.execute('PRAGMA synchronous=OFF')
            db.execute('CREATE TABLE subjects (host TEXT, id TEXT, parent TEXT, PRIMARY KEY(host,id)) WITHOUT ROWID')
            db.execute('CREATE TABLE seen (id TEXT PRIMARY KEY) WITHOUT ROWID')
            for path in select_files(paths, options):
                match = re.search(r'ta1-([a-z]+-\d+)-e5', path.name)
                instance = match[1] if match else collector
                stream_id = path.name.split('.bin')[0]
                for count, outer in enumerate(avro_records(path), 1):
                    if options.max_records and count > options.max_records:
                        break
                    branch, record = outer['datum']
                    kind = branch.rsplit('.', 1)[-1]
                    if kind not in {'Subject', 'Event'}:
                        continue
                    host = identifier(outer.get('hostId') or record.get('hostId')) or stream_id
                    restart = outer.get('sessionNumber', 0)
                    scope = f'{host}:{restart}'
                    props = record.get('properties') or {}
                    record_uuid = identifier(record.get('uuid'))
                    executable = None
                    if kind == 'Subject':
                        subject = record_uuid
                        parent = identifier(record.get('parentSubject'))
                        db.execute('INSERT OR REPLACE INTO subjects VALUES (?,?,?)', (scope, subject, parent))
                        if record.get('type') != 'SUBJECT_PROCESS':
                            continue
                        text = record.get('cmdLine')
                        timestamp = record.get('startTimestampNanos')
                    else:
                        event_type = record.get('type')
                        if event_type not in {'EVENT_EXECUTE', 'EVENT_FORK', 'EVENT_EXIT'}:
                            continue
                        # fork copies argv on Unix; it is not a new execution.
                        if event_type in {'EVENT_FORK', 'EVENT_EXIT'} and os_name != 'windows':
                            continue
                        text = props.get('cmdLine') or props.get('CommandLine')
                        subject = identifier(record.get('predicateObject') if event_type == 'EVENT_FORK' else record.get('subject'))
                        found = db.execute('SELECT parent FROM subjects WHERE host=? AND id=?', (scope, subject)).fetchone()
                        parent = found[0] if found else ''
                        timestamp = record.get('timestampNanos')
                        if collector == 'cadets':
                            executable = record.get('predicateObjectPath')
                    if not text:
                        continue
                    try:
                        commands = command_line(text, collector, executable, kind == 'Subject')
                    except ValueError:
                        # Unmatched quotes occur in corrupted/truncated cmdLine.
                        continue
                    for pgm, args in commands:
                        native_session = props.get('SessionId', props.get('SessionID'))
                        if native_session is not None:
                            session = f'{root.name}:{scope}:windows-session:{native_session}'
                        else:
                            session = f'{root.name}:{scope}:parent:{parent or subject or record_uuid}'
                        # Same process creation can be repeated as Subject, FORK,
                        # and EXECUTE records. Retain one exact observation.
                        identity = json.dumps([scope, subject, timestamp, pgm, args], ensure_ascii=True)
                        digest = hashlib.sha256(identity.encode()).hexdigest()
                        if db.execute('INSERT OR IGNORE INTO seen VALUES (?)', (digest,)).rowcount == 0:
                            continue
                        group = attack_group(root.name, instance, host, timestamp)
                        yield Command(pgm=pgm, args=args,
                                      record_id=f'{host}:{kind}:{record_uuid}:{digest[:16]}',
                                      label='malicious-group' if group else 'unknown',
                                      group_id=group, session_id=session, os=os_name)
        finally:
            db.close()
