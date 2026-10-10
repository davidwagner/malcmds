"""Stream the native CDM18/CDM20 Avro command observations."""

import hashlib
import io
import json
import multiprocessing
import pickle
import re
import shlex
import sqlite3
import sys
import tarfile
import tempfile
import uuid
from collections import deque
from datetime import datetime, timezone
from multiprocessing.pool import AsyncResult
from pathlib import Path
from time import monotonic
from zoneinfo import ZoneInfo

import fastavro
from _ingest import Command, normalize, select_files
from isal import igzip as gzip

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


class _AvroStream:
    """Track forward reads without gzip's expensive seek-based tell calls."""

    def __init__(self, stream):
        self.stream = stream
        self.position = 0

    def read(self, size=-1):
        """Read bytes and account for their uncompressed position."""
        data = self.stream.read(size)
        self.position += len(data)
        return data

    def tell(self):
        """Return the position used by fastavro's block metadata."""
        return self.position


def avro_blocks(stream, source):
    """Recover after malformed records using the container's block boundaries."""
    for number, block in enumerate(fastavro.block_reader(
        # fastavro needs read/tell, although its stub requires the full IO API.
        _AvroStream(stream), return_record_name=True, handle_unicode_errors='replace',  # type: ignore[arg-type]
    )):
        try:
            yield from block
        except (EOFError, ValueError, IndexError, OverflowError) as error:
            print(f'{source}: malformed Avro block {number}; skipping remainder: {error}',
                  file=sys.stderr)


def avro_records(path):
    """Read gzip Avro or every regular Avro member in an E3 tar archive."""
    if '.tar.' in path.name:
        with gzip.open(path, 'rb') as compressed, tarfile.open(fileobj=compressed, mode='r|') as archive:
            for member in archive:
                if member.isfile() and '.bin' in member.name:
                    stream = archive.extractfile(member)
                    assert isinstance(stream, io.BufferedIOBase)  # Regular members are ExFileObjects.
                    with io.BufferedReader(stream) as buffered:
                        yield from avro_blocks(buffered, f'{path.name}:{member.name}')
    else:
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rb') as stream, io.BufferedReader(stream) as buffered:
            yield from avro_blocks(buffered, path.name)


def _candidates(path, max_records, windows):
    """Scan all source records, retaining subjects and command-bearing events."""
    started = reported = monotonic()
    count = retained = 0
    print(f'{path.name}: scanning', file=sys.stderr, flush=True)
    source = avro_records(path)
    try:
        for outer in source:
            count += 1
            branch, record = outer['datum']
            kind = branch.rsplit('.', 1)[-1]
            keep = kind == 'Subject'
            if kind == 'Event':
                event_type = record.get('type')
                props = record.get('properties') or {}
                keep = (event_type == 'EVENT_EXECUTE' or
                        (windows and event_type in {'EVENT_FORK', 'EVENT_EXIT'})) and bool(
                            props.get('cmdLine') or props.get('CommandLine'))
            if keep:
                retained += 1
                yield outer
            if count % 100000 == 0 and monotonic() - reported >= 10:
                reported = monotonic()
                elapsed = reported - started
                print(f'{path.name}: {count:,} scanned, {retained:,} retained; '
                      f'{count / elapsed:,.0f} records/s, {elapsed:.1f}s elapsed',
                      file=sys.stderr, flush=True)
            if max_records and count >= max_records:
                break
    finally:
        source.close()
        print(f'{path.name}: finished scanning {count:,} records, '
              f'{retained:,} retained in {monotonic() - started:.1f}s',
              file=sys.stderr, flush=True)


def _spool(path, destination, max_records, windows):
    """Decode one file to a private spool; database state stays in the parent."""
    with destination.open('wb') as stream:
        for outer in _candidates(path, max_records, windows):
            pickle.dump(outer, stream, protocol=pickle.HIGHEST_PROTOCOL)


def _ordered_files(paths, options, temporary, windows):
    """Prefetch at most one file per worker and consume in original order."""
    workers = min(getattr(options, 'tc_workers', 8), len(paths))
    if workers <= 1 or getattr(options, 'limit', None) is not None:
        for path in paths:
            yield path, _candidates(path, options.max_records, windows)
        return
    # Spawn avoids inheriting the live DuckDB connection and SQLite state.
    pool = multiprocessing.get_context('spawn').Pool(workers)
    pending: deque[tuple[Path, Path, AsyncResult]] = deque()
    remaining = iter(enumerate(paths))
    try:
        for index, path in remaining:
            destination = Path(temporary) / f'{index}.pickle'
            pending.append((path, destination, pool.apply_async(
                _spool, (path, destination, options.max_records, windows))))
            if len(pending) == workers:
                break
        while pending:
            path, destination, job = pending.popleft()
            job.get()
            with destination.open('rb') as stream:
                yield path, _unspool(stream)
            destination.unlink()
            item = next(remaining, None)
            if item is not None:
                index, path = item
                destination = Path(temporary) / f'{index}.pickle'
                pending.append((path, destination, pool.apply_async(
                    _spool, (path, destination, options.max_records, windows))))
        pool.close()
        pool.join()
    finally:
        # Also stop prefetch promptly when the reader fails or is closed early.
        pool.terminate()
        pool.join()


def _unspool(stream):
    """Read only the trusted pickle stream produced by this invocation."""
    while stream.peek(1):
        yield pickle.load(stream)


def command_line(text, collector, pgm=None):
    """Normalize captured argv text without interpreting it as typed shell input."""
    if not text or text.strip() in {'N/A', '(null)', 'null', '<unknown>'}:
        return []
    if collector == 'fivedirections' and text.lstrip().startswith(('/', '-')):
        # Argument-only Windows observations need image metadata (#54).
        return []
    text = text.removesuffix('\0') if '\0' in text else text.strip()
    # Titles such as "sshd: admin [priv]" are not an executed argv vector.
    if re.match(r'^(?:sshd|sshd-session|sudo|postgres|sendmail|pickup|qmgr):\s', text):
        return []
    os_name = 'windows' if collector in {'fivedirections', 'marple'} else 'linux'
    if os_name == 'linux' and '\0' in text:
        tokens = text.split('\0')
    elif collector == 'trace':
        # Flattened cmdLine has no encoding marker. Numeric/hex-looking words
        # are literal; only the raw audit reader can interpret audit encoding.
        tokens = shlex.split(text)
    else:
        commands = normalize(text, os=os_name, shell=False)
        if not commands:
            return []
        executable, args = commands[0]
        tokens = [executable, *args]
    # Flattened, unquoted shell -c observations lose the script's argv boundary.
    # Infer one script argument from the remainder; quoted strings already
    # preserve that argument.
    if os_name == 'linux' and tokens and Path(tokens[0]).name in {'sh', 'bash', 'dash', 'ksh', 'zsh'}:
        match = re.match(r'^\S+\s+(-[a-zA-Z]*c)\s+(.+)$', text, re.DOTALL)
        if match and match[2][0] not in "\"'" and len(tokens) > 3:
            tokens = [tokens[0], match[1], match[2]]
    # Check the parsed executable: raw whitespace splitting can be empty, split
    # a quoted executable, or include NUL-delimited arguments in the first word.
    if (not tokens or not tokens[0]
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
        files = None
        source = None
        try:
            db.execute('PRAGMA journal_mode=OFF')
            db.execute('PRAGMA synchronous=OFF')
            db.execute('CREATE TABLE subjects (host TEXT, id TEXT, parent TEXT, PRIMARY KEY(host,id)) WITHOUT ROWID')
            db.execute('CREATE TABLE seen (id TEXT PRIMARY KEY) WITHOUT ROWID')
            paths = select_files(paths, options)
            files = _ordered_files(paths, options, temporary, os_name == 'windows')
            for file_number, (path, source) in enumerate(files, 1):
                print(f'{root.name}: consuming file {file_number}/{len(paths)}: {path.name}',
                      file=sys.stderr, flush=True)
                match = re.search(r'ta1-([a-z]+-\d+)-e5', path.name)
                instance = match[1] if match else collector
                stream_id = path.name.split('.bin')[0]
                for outer in source:
                    branch, record = outer['datum']
                    kind = branch.rsplit('.', 1)[-1]
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
                        commands = command_line(text, collector, executable)
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
            if source is not None:
                source.close()
            if files is not None:
                files.close()
            db.close()
