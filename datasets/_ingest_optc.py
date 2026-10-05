"""Stream OpTC eCAR command observations and apply report host/time groups."""
import gzip
import json
import re
from datetime import datetime, timezone
from pathlib import PureWindowsPath
from zoneinfo import ZoneInfo

from _ingest import Command, normalize, select_files

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


def timestamp(value):
    """Read actual ISO-8601 timestamps and the numeric schema's milliseconds."""
    if isinstance(value, (int, float)) or isinstance(value, str) and value.isdecimal():
        return datetime.fromtimestamp(float(value) / 1000, timezone.utc)
    if not value:
        return None
    result = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    return result.replace(tzinfo=ZoneInfo('America/New_York')) if result.tzinfo is None else result


def label_for(host, time, benign):
    """Return benign partition labels or explicitly reported host/time groups."""
    if benign:
        return 'benign', None
    if time is not None:
        local = time.astimezone(ZoneInfo('America/New_York')).replace(tzinfo=None)
        for machine, start, end, attack in ATTACK_WINDOWS:
            if host == machine and datetime.fromisoformat(start) <= local <= datetime.fromisoformat(end):
                return 'malicious-group', f'optc:{attack}:{host}:{start}/{end}:America_New_York'
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
    parse_image = image
    if image.lower().startswith('\\device\\') and len(text) > 2 and text[1] == ':':
        parts = image.split('\\', 3)
        if len(parts) == 4:
            candidate = text[:2] + '\\' + parts[3]
            if text.lower().startswith(candidate.lower()):
                parse_image = candidate
    parsed = normalize(text, os='windows', pgm=parse_image or None)
    plain = normalize(text, os='windows')
    if not plain:
        return []
    # PROCESS OPEN image_path often names the accessor rather than the target.
    if event.get('action') == 'OPEN':
        return plain
    if not image:
        return plain
    own_name = PureWindowsPath(plain[0][0]).name.lower().removesuffix('.exe')
    image_name = PureWindowsPath(image).name.lower().removesuffix('.exe')
    if own_name != image_name and parse_image == image:
        return plain
    return [(image, args) for _, args in parsed]


def records(root, options):
    """Read completed gzip streams, using event UUIDs for repeatable source IDs."""
    paths = select_files((root / 'ecar').rglob('*.json.gz'), options)
    if not paths:
        raise FileNotFoundError(f'No completed OpTC eCAR gzip files under {root}')
    for path in paths:
        relative = path.relative_to(root)
        benign = 'benign' in relative.parts
        with gzip.open(path, 'rt', encoding='utf-8', errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                if options.max_records is not None and number > options.max_records:
                    break
                if not line.strip():
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
