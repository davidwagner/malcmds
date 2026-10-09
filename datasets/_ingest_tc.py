"""Stream the native CDM18/CDM20 Avro command observations."""

import hashlib
import io
import json
import multiprocessing
import ntpath
import pickle
import re
import shlex
import sqlite3
import sys
import tarfile
import tempfile
import uuid
from collections import deque
from multiprocessing.pool import AsyncResult
from pathlib import Path
from time import monotonic

import fastavro
from _ingest import Command, normalize, select_files, windows_split
from _tc_labels import TCAnnotations
from isal import igzip as gzip


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


def _candidates(path, max_records, windows, annotated_objects=()):
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
                            props.get('cmdLine') or props.get('CommandLine') or
                            (windows and props.get('ImageFileName')) or
                            (event_type == 'EVENT_EXECUTE' and record.get('predicateObjectPath')))
                keep = keep or any(identifier(record.get(field)).lower() in annotated_objects
                                   for field in ('predicateObject', 'predicateObject2'))
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


def _spool(path, destination, max_records, windows, annotated_objects):
    """Decode one file to a private spool; database state stays in the parent."""
    with destination.open('wb') as stream:
        for outer in _candidates(path, max_records, windows, annotated_objects):
            pickle.dump(outer, stream, protocol=pickle.HIGHEST_PROTOCOL)


def _ordered_files(paths, options, temporary, windows, annotated_objects=()):
    """Prefetch at most one file per worker and consume in original order."""
    workers = min(getattr(options, 'tc_workers', 8), len(paths))
    if workers <= 1 or getattr(options, 'limit', None) is not None:
        for path in paths:
            yield path, _candidates(path, options.max_records, windows, annotated_objects)
        return
    # Spawn avoids inheriting the live DuckDB connection and SQLite state.
    pool = multiprocessing.get_context('spawn').Pool(workers)
    pending: deque[tuple[Path, Path, AsyncResult]] = deque()
    remaining = iter(enumerate(paths))
    try:
        for index, path in remaining:
            destination = Path(temporary) / f'{index}.pickle'
            pending.append((path, destination, pool.apply_async(
                _spool, (path, destination, options.max_records, windows, annotated_objects))))
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
                    _spool, (path, destination, options.max_records, windows, annotated_objects))))
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


def usable_image(image):
    """Return an executable image string only when the recorded value is usable."""
    image = (image or '').strip().strip('"')
    if (not image or image in {'N/A', '(null)', 'null', '<unknown>'}
            or image.startswith(('/', '-')) or '\ufffd' in image
            or any(ord(char) < 32 for char in image)):
        return None
    return image


def fivedirections_command(text, image):
    """Recover FiveDirections argv without consuming an argument as its program."""
    image = usable_image(image)
    text = (text or '').strip()
    if text in {'N/A', '(null)', 'null', '<unknown>'}:
        text = ''
    if not text:
        return [(image, [])] if image else []
    tokens = windows_split(text)
    if text.startswith(('/', '-')):
        return [(image, tokens)] if image else []
    # A matching unquoted image suffix makes Program Files part of argv[0].
    end = None
    if image and not text.startswith('"'):
        basename = re.escape(ntpath.basename(image).removesuffix('.exe'))
        if image.lower().endswith('.exe'):
            basename = re.escape(ntpath.basename(image)[:-4])
        # Stop at the first complete executable suffix, before any arguments.
        match = re.match(r'(?:[^"\r\n]*?[\\/])?' + basename + r'(?:\.exe)?(?=\s|$)', text, re.IGNORECASE)
        if match:
            end = match.end()
    if end is None:
        quoted = False
        slashes = 0
        end = len(text)
        for index, char in enumerate(text):
            if char == '"' and slashes % 2 == 0:
                quoted = not quoted
            if char.isspace() and not quoted:
                end = index
                break
            slashes = slashes + 1 if char == '\\' else 0
        prefix = windows_split(text[:end])[0] if tokens else ''
    else:
        prefix = text[:end]
    program = prefix
    if image:
        prefix_name = ntpath.basename(prefix).lower().removesuffix('.exe')
        image_name = ntpath.basename(image).lower().removesuffix('.exe')
        program = image
        if prefix_name == image_name and not ntpath.dirname(image):
            program = prefix
            if image.lower().endswith('.exe') and not prefix.lower().endswith('.exe'):
                program = ntpath.join(ntpath.dirname(prefix), image)
    program = usable_image(program)
    return [(program, windows_split(text[end:]))] if program else []


def image_files(files, db, temporary, limited=False):
    """Index available images and replay a valid prefix before reporting failure.

    A limited preview indexes one file at a time so it can stop before opening
    later input. A complete ingest can recover images across all selected files.
    """
    db.execute('CREATE TABLE images (scope TEXT, subject TEXT, time INTEGER, image TEXT)')
    db.execute('CREATE INDEX process_images ON images (scope,subject,time)')
    saved = deque()
    failure = None
    try:
        try:
            for index, (path, source) in enumerate(files):
                destination = Path(temporary) / f'images-{index}.pickle'
                saved.append((path, destination))
                with destination.open('wb') as stream:
                    for outer in source:
                        pickle.dump(outer, stream, protocol=pickle.HIGHEST_PROTOCOL)
                        kind, record = outer['datum']
                        image = usable_image((record.get('properties') or {}).get('ImageFileName'))
                        if not image:
                            continue
                        host = identifier(outer.get('hostId') or record.get('hostId')) or path.name.split('.bin')[0]
                        scope = f"{host}:{outer.get('sessionNumber', 0)}"
                        subject = identifier(record.get('uuid') if kind.endswith('.Subject') else
                                             record.get('predicateObject') if record.get('type') == 'EVENT_FORK' else record.get('subject'))
                        if subject:
                            timestamp = record.get('timestampNanos') or record.get('startTimestampNanos') or 0
                            db.execute('INSERT INTO images VALUES (?,?,?,?)', (scope, subject, timestamp, image))
                if limited:
                    path, destination = saved.popleft()
                    with destination.open('rb') as stream:
                        yield path, _unspool(stream)
                    destination.unlink()
        except Exception as error:  # noqa: BLE001 - re-raised after replaying valid records
            failure = error
        for path, destination in saved:
            with destination.open('rb') as stream:
                yield path, _unspool(stream)
            destination.unlink()
        if failure is not None:
            raise failure
    finally:
        files.close()


def command_line(text, collector, pgm=None):
    """Normalize captured argv text without interpreting it as typed shell input."""
    if collector == 'fivedirections':
        return fivedirections_command(text, pgm)
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


def annotation_files(files, annotations, temporary):
    """Resolve native object/process relationships before assigning final labels."""
    saved = []
    try:
        for index, (path, source) in enumerate(files):
            destination = Path(temporary) / f'annotations-{index}.pickle'
            saved.append((path, destination))
            with destination.open('wb') as stream:
                for outer in source:
                    pickle.dump(outer, stream, protocol=pickle.HIGHEST_PROTOCOL)
                    kind, record = outer['datum']
                    if not kind.endswith('.Event'):
                        continue
                    host = identifier(outer.get('hostId') or record.get('hostId')) or path.name.split('.bin')[0]
                    scope = f"{host}:{outer.get('sessionNumber', 0)}"
                    annotations.add_relation(scope, identifier(record.get('subject')),
                                             record.get('timestampNanos'),
                                             [identifier(record.get(field)) for field in ('predicateObject', 'predicateObject2')])
        for path, destination in saved:
            with destination.open('rb') as stream:
                yield path, _unspool(stream)
            destination.unlink()
    finally:
        files.close()


def records(root, options):
    """Yield process command snapshots and execution records with bounded RAM."""
    collector = root.name.split('-')[-1]
    os_name = 'windows' if collector in {'fivedirections', 'marple'} else 'linux'
    annotations = TCAnnotations(root)
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
            db.execute('CREATE TABLE subjects (host TEXT, id TEXT, parent TEXT, pid TEXT, PRIMARY KEY(host,id)) WITHOUT ROWID')
            db.execute('CREATE TABLE seen (id TEXT PRIMARY KEY) WITHOUT ROWID')
            db.execute('CREATE TABLE creations (scope TEXT, subject TEXT, priority INTEGER, time INTEGER, pgm TEXT, args TEXT, command BLOB, PRIMARY KEY(scope,subject))')
            db.execute('CREATE TABLE executions (scope TEXT, subject TEXT, time INTEGER, pgm TEXT, args TEXT)')
            db.execute('CREATE INDEX execution_creation ON executions (scope,subject,time,pgm,args)')
            paths = select_files(paths, options)
            files = _ordered_files(paths, options, temporary, os_name == 'windows', set(annotations.objects))
            if collector == 'fivedirections':
                files = image_files(files, db, temporary, options.limit is not None)
            if annotations.objects:
                files = annotation_files(files, annotations, temporary)
            for file_number, (path, source) in enumerate(files, 1):
                print(f'{root.name}: consuming file {file_number}/{len(paths)}: {path.name}',
                      file=sys.stderr, flush=True)
                match = re.search(r'ta1-([a-z]+-\d+)-e5', path.name)
                instance = match[1] if match else collector
                stream_id = path.name.split('.bin')[0]
                for record_number, outer in enumerate(source):
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
                        native_pid = str(record.get('cid', ''))
                        db.execute('INSERT OR REPLACE INTO subjects VALUES (?,?,?,?)', (scope, subject, parent, native_pid))
                        if record.get('type') != 'SUBJECT_PROCESS':
                            continue
                        text = record.get('cmdLine')
                        timestamp = record.get('startTimestampNanos')
                    else:
                        event_type = record.get('type')
                        # Other retained events identify annotation relationships,
                        # not new executions or process-creation snapshots.
                        if event_type not in {'EVENT_EXECUTE', 'EVENT_FORK', 'EVENT_EXIT'}:
                            continue
                        text = props.get('cmdLine') or props.get('CommandLine')
                        subject = identifier(record.get('predicateObject') if event_type == 'EVENT_FORK' else record.get('subject'))
                        found = db.execute('SELECT parent,pid FROM subjects WHERE host=? AND id=?', (scope, subject)).fetchone()
                        parent = found[0] if found else ''
                        native_pid = props.get('ProcessID') or (found[1] if found else '')
                        timestamp = record.get('timestampNanos')
                        if collector == 'cadets' or event_type == 'EVENT_EXECUTE' and not text:
                            executable = record.get('predicateObjectPath')
                    if collector == 'fivedirections':
                        executable = usable_image(props.get('ImageFileName'))
                        if not executable and subject:
                            found = db.execute('SELECT image FROM images WHERE scope=? AND subject=? ORDER BY abs(time-?),time LIMIT 1',
                                               (scope, subject, timestamp or 0)).fetchone()
                            executable = found[0] if found else None
                    if not text and not executable:
                        continue
                    try:
                        if not text and executable and collector != 'fivedirections':
                            valid = (executable.strip() not in {'N/A', '(null)', 'null', '<unknown>'}
                                     and '\ufffd' not in executable
                                     and not any(ord(char) < 32 for char in executable))
                            commands = [(executable, [])] if valid else []
                        else:
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
                        execution = kind == 'Event' and record.get('type') == 'EVENT_EXECUTE'
                        if not execution and not subject:
                            continue
                        # A process UUID groups snapshots; each EXECUTE UUID is
                        # a separate attempt, even for repeated argv in one PID.
                        identity = json.dumps([scope, 'exec', record_uuid or f'{path.name}:{record_number}'] if execution else
                                              [scope, subject, timestamp, pgm, args], ensure_ascii=True)
                        digest = hashlib.sha256(identity.encode()).hexdigest()
                        if execution and db.execute('INSERT OR IGNORE INTO seen VALUES (?)', (digest,)).rowcount == 0:
                            continue
                        label, group = annotations.label(host, restart, subject, timestamp, pgm, args,
                                                         {'instance': instance, 'pid': native_pid})
                        command = Command(pgm=pgm, args=args,
                                          record_id=f'{host}:{kind}:{record_uuid}:{digest[:16]}',
                                          label=label,
                                          group_id=group, session_id=session, os=os_name)
                        if execution:
                            db.execute('INSERT INTO executions VALUES (?,?,?,?,?)',
                                       (scope, subject, timestamp, pgm, json.dumps(args)))
                            yield command
                        else:
                            priority = (0 if record.get('type') == 'EVENT_FORK' and text else
                                        1 if kind == 'Subject' else 2 if record.get('type') == 'EVENT_FORK' else 3)
                            db.execute('INSERT INTO creations VALUES (?,?,?,?,?,?,?) ON CONFLICT(scope,subject) DO UPDATE SET priority=excluded.priority,time=excluded.time,pgm=excluded.pgm,args=excluded.args,command=excluded.command WHERE excluded.priority < creations.priority',
                                       (scope, subject, priority, timestamp, pgm, json.dumps(args), pickle.dumps(command)))
            for row in db.execute('SELECT command FROM creations c WHERE NOT EXISTS (SELECT 1 FROM executions e WHERE e.scope=c.scope AND e.subject=c.subject AND e.time=c.time AND e.pgm=c.pgm AND e.args=c.args) ORDER BY c.rowid'):
                yield pickle.loads(row[0])
        finally:
            if source is not None:
                source.close()
            if files is not None:
                files.close()
            db.close()
