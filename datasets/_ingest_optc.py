"""Stream OpTC eCAR command observations and apply report host/time groups."""
import json
import multiprocessing
import re
import tempfile
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import lru_cache
from multiprocessing.pool import AsyncResult
from pathlib import Path, PureWindowsPath
from zoneinfo import ZoneInfo

import pyarrow as pa
from _ingest import SCHEMA, Command, command_table, normalize, select_files
from isal import igzip as gzip

# The report omits a zone. Interpret its clocks in the observed eCAR -04:00
# offset; America/New_York has that offset on all three exercise dates.
# Group labels deliberately cover every command on the named host in the interval.
# Source: source/OpTCRedTeamGroundTruth.pdf, day 1/2/3 activity logs.
ATTACK_WINDOWS = [
    ('sysclient0201', '2019-09-23T11:23:29', '2019-09-23T15:30:00', 'empire-day1'),
    ('sysclient0402', '2019-09-23T13:24:36', '2019-09-23T14:06:01', 'empire-day1'),
    ('sysclient0660', '2019-09-23T13:35:22', '2019-09-23T14:06:01', 'empire-day1'),
    ('dc1', '2019-09-23T14:04:45', '2019-09-23T15:24:33', 'empire-day1'),
    ('sysclient0501', '2019-09-24T10:36:51', '2019-09-24T15:28:36', 'empire-day2'),
    ('sysclient0811', '2019-09-24T10:40:14', '2019-09-24T13:25:46', 'empire-day2'),
    ('dc1', '2019-09-24T11:20:19', '2019-09-25T09:00:00', 'empire-day2'),
    ('sysclient0974', '2019-09-24T13:46:58', '2019-09-24T15:27:32', 'rdp-day2'),
    ('sysclient0005', '2019-09-24T13:54:43', '2019-09-24T15:23:26', 'rdp-day2'),
    ('sysclient0501', '2019-09-25T10:00:00', '2019-09-25T10:00:00.999999', 'wmi-persistence'),
    ('sysclient0051', '2019-09-25T10:29:42', '2019-09-25T14:24:03', 'meterpreter-day3'),
    ('sysclient0351', '2019-09-25T11:23:31', '2019-09-25T11:24:30', 'meterpreter-day3'),
]
for _host in (104, 170, 205, 255, 321, 355, 419, 462, 503, 559, 609, 771, 874, 955):
    ATTACK_WINDOWS.append((f'sysclient{_host:04}', '2019-09-23T14:45:13', '2019-09-23T15:24:33', 'empire-day1'))
for _host in (10, 69, 203, 358, 618, 851):
    ATTACK_WINDOWS.append((f'sysclient{_host:04}', '2019-09-24T15:42:36', '2019-09-25T09:00:00', 'empire-overnight'))


EASTERN = ZoneInfo('America/New_York')
HOST_WINDOWS: dict[str, list[tuple[datetime, datetime, str]]] = defaultdict(list)
for _machine, _start, _end, _attack in ATTACK_WINDOWS:
    HOST_WINDOWS[_machine].append((
        datetime.fromisoformat(_start), datetime.fromisoformat(_end),
        f'optc:{_attack}:{_machine}:{_start}/{_end}:America_New_York',
    ))


def timestamp(value):
    """Read actual ISO-8601 timestamps and the numeric schema's milliseconds."""
    if isinstance(value, (int, float)) or isinstance(value, str) and value.isdecimal():
        return datetime.fromtimestamp(float(value) / 1000, timezone.utc)
    if not value:
        return None
    result = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    return result.replace(tzinfo=EASTERN) if result.tzinfo is None else result


def label_for(host, time, benign):
    """Return benign partition labels or explicitly reported host/time groups."""
    if benign:
        return 'benign', None
    windows = HOST_WINDOWS.get(host, ())
    if time is not None and windows:
        local = time.astimezone(EASTERN).replace(tzinfo=None)
        for start, end, group in windows:
            if start <= local <= end:
                return 'malicious-group', group
    return 'unknown', None


def usable_id(value):
    """Reject eCAR's sentinel UUIDs and unavailable numeric identifiers."""
    value = str(value or '')
    return value if value.strip('{}0-') and value not in ('-1', 'None') else ''


def observed_command(event):
    """Use image_path only when it identifies the command's own executable."""
    props = event.get('properties') or {}
    text = props.get('command_line')
    if not isinstance(text, str) or not text.strip():
        return []
    image = props.get('image_path') or ''
    # Cache parsing only: labels, IDs, timestamps and sessions belong to events.
    # Bound retained input as well as entry count; oversized commands still parse.
    parse = _cached_command if len(text) + len(image) <= 4096 else _parse_command
    pairs = parse(text, image, event.get('action') == 'OPEN')
    # Consumers may mutate arguments without changing a later cached observation.
    return [(pgm, list(args)) for pgm, args in pairs]


def _parse_command(text, image, is_open):
    plain = normalize(text, os='windows')
    if not plain:
        return []
    # PROCESS OPEN image_path often names the accessor rather than the target.
    if is_open or not image:
        return plain
    parse_image = image
    if image.lower().startswith('\\device\\') and len(text) > 2 and text[1] == ':':
        parts = image.split('\\', 3)
        if len(parts) == 4:
            candidate = text[:2] + '\\' + parts[3]
            if text.lower().startswith(candidate.lower()):
                parse_image = candidate
    own_name = PureWindowsPath(plain[0][0]).name.lower().removesuffix('.exe')
    image_name = PureWindowsPath(image).name.lower().removesuffix('.exe')
    if own_name != image_name and parse_image == image:
        return plain
    parsed = normalize(text, os='windows', pgm=parse_image)
    return [(image, args) for _, args in parsed]


_cached_command = lru_cache(maxsize=4096)(_parse_command)


def records(root, options):
    """Read completed gzip streams, using event UUIDs for repeatable source IDs.

    With more than one worker, each gzip file is parsed in its own process and
    batches are yielded as Arrow tables, in the same file order as one worker.
    A command limit uses one worker to stop without spooling whole source files.
    """
    paths = select_files((root / 'ecar').rglob('*.json.gz'), options)
    if not paths:
        raise FileNotFoundError(f'No completed OpTC eCAR gzip files under {root}')
    workers = min(getattr(options, 'workers', 1), len(paths))
    # Whole-file workers cannot stop when the consumer reaches a command limit.
    if workers > 1 and getattr(options, 'limit', None) is None:
        yield from parallel_tables(root, paths, options, workers)
        return
    for path in paths:
        yield from file_commands(root, path, options.max_records)


def parallel_tables(root, paths, options, workers):
    """Yield every file's command batches, parsing up to `workers` files at once.

    Each worker writes its file's batches to a temporary Arrow IPC file. At most
    `workers` files are pending, which bounds temporary disk use.
    """
    scratch = root.parent.parent / 'tmp' / 'ingest'
    scratch.mkdir(parents=True, exist_ok=True)
    # spawn: forking a parent that holds DuckDB and Arrow threads is unsafe.
    context = multiprocessing.get_context('spawn')
    with tempfile.TemporaryDirectory(prefix='optc-', dir=scratch) as tmp, \
            context.Pool(workers) as pool:
        pending: deque[AsyncResult] = deque()
        for index, path in enumerate(paths):
            output = Path(tmp) / f'{index}.arrow'
            task = (root, path, options.max_records, options.batch_size, output)
            pending.append(pool.apply_async(write_file_tables, task))
            if len(pending) >= workers:
                yield from read_tables(pending.popleft().get())
        while pending:
            yield from read_tables(pending.popleft().get())


def write_file_tables(root, path, max_records, batch_size, output):
    """Write one gzip file's commands to `output` as Arrow batches; return `output`."""
    options = pa.ipc.IpcWriteOptions(compression='lz4')
    with pa.OSFile(str(output), 'wb') as sink, pa.ipc.new_stream(sink, SCHEMA, options=options) as writer:
        batch = []
        for command in file_commands(root, path, max_records):
            batch.append(command)
            if len(batch) >= batch_size:
                writer.write_table(command_table(batch, root.name))
                batch.clear()
        if batch:
            writer.write_table(command_table(batch, root.name))
    return output


def read_tables(path):
    """Yield the batches written by write_file_tables, then delete the file."""
    with pa.OSFile(str(path), 'rb') as source:
        for batch in pa.ipc.open_stream(source):
            yield pa.Table.from_batches([batch])
    path.unlink()


def file_commands(root, path, max_records):
    """Yield the commands in one eCAR gzip file, reading at most max_records lines."""
    relative = path.relative_to(root)
    benign = 'benign' in relative.parts
    with gzip.open(path, 'rt', encoding='utf-8', errors='replace') as stream:
        for number, line in enumerate(stream, 1):
            if max_records is not None and number > max_records:
                break
            # Most eCAR events (85-95% in samples) are not PROCESS events. Skip
            # them without JSON decoding. A JSON string can spell PROCESS with
            # \u00XX escapes, so lines containing one are decoded as well.
            if '"PROCESS"' not in line and '\\u00' not in line:
                continue
            event = json.loads(line)
            if event.get('object') != 'PROCESS':
                continue
            pairs = observed_command(event)
            if not pairs:
                continue
            host = str(event.get('hostname') or relative.parent.name).lower()
            machine = host.split('.')[0]
            time = timestamp(event.get('timestamp_ms', event.get('timestamp')))
            label, group = label_for(machine, time, benign)
            props = event.get('properties') or {}
            login = usable_id(props.get('logon_id') or props.get('logon_guid') or props.get('session_id'))
            target = usable_id(event.get('objectID'))
            actor = usable_id(event.get('actorID'))
            principal = props.get('user') or event.get('principal') or props.get('sid') or 'unknown-user'
            if login:
                session = f'optc:{host}:login:{login}'
            elif event.get('action') == 'CREATE' and actor and actor != target:
                session = f'optc:{host}:{principal}:parent:{actor}'
            elif target:
                session = f'optc:{host}:process:{target}'
            else:
                day = time.date().isoformat() if time else str(relative.parent)
                session = f'optc:{host}:{principal}:{day}:ppid:{event.get("ppid", "unknown")}'
            record = usable_id(event.get('id')) or f'{relative}:{number}'
            for index, (pgm, args) in enumerate(pairs):
                # Ignore control-only/truncated process titles, preserving actual arguments.
                if not pgm.strip() or re.fullmatch(r'[\x00-\x20]+', pgm):
                    continue
                yield Command(pgm, args, f'{record}:{index}', label, group, session, 'windows')
