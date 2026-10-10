"""Transient published OpTC labels; no label evidence is stored in COMMANDS."""

import csv
import json
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from isal import igzip as gzip

EASTERN = ZoneInfo('America/New_York')


def timestamp(value):
    """Read eCAR ISO timestamps or epoch milliseconds."""
    if isinstance(value, (int, float)) or isinstance(value, str) and value.isdecimal():
        return datetime.fromtimestamp(float(value) / 1000, timezone.utc)
    if not value:
        return None
    result = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    return result.replace(tzinfo=EASTERN) if result.tzinfo is None else result


def host_name(value):
    """Normalize the release's mixed-case short host names and DNS names."""
    return str(value or '').lower().split('.')[0]


def process_id(event):
    """Identify the affected process, including the child of PROCESS CREATE."""
    return event.get('objectID') if event.get('object') == 'PROCESS' else event.get('actorID')


def read_events(path):
    """Stream published JSON lines, whether stored in ZIP or gzip archives."""
    if path.suffix == '.zip':
        with zipfile.ZipFile(path) as archive, archive.open('malicious.json') as stream:
            for line in stream:
                if line.strip():
                    yield json.loads(line)
    else:
        with gzip.open(path, 'rt') as stream:
            for line in stream:
                if line.strip():
                    yield json.loads(line)


def load_labels(root):
    """Load reviewed decisions and original-data Inria labels, when installed.

    The official eCAR fetch supplies original data. Corrected-data labels are
    deliberately excluded: their process/event identities belong to other data.
    """
    lookup = {name: {} for name in ('reviewed_events', 'reviewed_processes')}
    lookup.update({name: set() for name in ('ordinary', 'events', 'rejected_events', 'rejected_processes')})
    lookup['intervals'] = defaultdict(list)
    directory = root / 'labels'
    tasks_path = directory / 'reviewed' / 'tasks.zip'
    if tasks_path.exists():
        with zipfile.ZipFile(tasks_path) as archive:
            tasks = json.loads(archive.read('tasks.json'))
        for task in tasks:
            labels = task.get('labels') or []
            host = host_name(task['hostname'])
            process = task.get('object_id')
            event = task.get('event_id')
            if 'invalid' in labels:
                lookup['rejected_events'].add((host, event))
                if 'process' in labels:
                    lookup['rejected_processes'].add((host, process))
                continue
            outcome = 'benign' if 'benign' in labels else 'malicious' if 'malicious' in labels else None
            if outcome is None:
                continue
            # Raw lists sometimes contain two reviewed events, e.g. RPCSS.
            events = {event} | {json.loads(raw)['id'] for raw in task.get('raw') or []}
            for event_id in events - {None, ''}:
                previous = lookup['reviewed_events'].get((host, event_id))
                lookup['reviewed_events'][host, event_id] = 'benign' if previous == 'benign' else outcome
            if process and 'event' in labels:
                lookup['ordinary'].add((host, process))
            elif process and 'process' in labels:
                previous = lookup['reviewed_processes'].get((host, process))
                lookup['reviewed_processes'][host, process] = 'benign' if previous == 'benign' else outcome
    exported = directory / 'reviewed' / 'malicious.zip'
    if exported.exists():
        if not tasks_path.exists():
            raise FileNotFoundError('OpTC malicious.zip requires reviewed tasks.zip to reject invalid correlations')
        for event in read_events(exported):
            host = host_name(event['hostname'])
            key = (host, event['id'])
            process = (host, process_id(event))
            actor = (host, event.get('actorID'))
            if (event.get('object') == 'PROCESS' and key not in lookup['rejected_events']
                    and process not in lookup['rejected_processes']
                    and actor not in lookup['rejected_processes']):
                lookup['events'].add(key)
    inria = directory / 'inria' / 'original'
    for path in sorted(inria.glob('ground_truth_sc*_new.csv')):
        with path.open(newline='') as stream:
            for host, pid, start, end in csv.reader(stream):
                lookup['intervals'][host_name(host), str(pid)].append(
                    (timestamp(start), None if end.lower() == 'infinity' else timestamp(end)))
    for path in sorted(inria.glob('ground_truth_sc*_evts_*.json.gz')):
        for event in read_events(path):
            if event.get('object') == 'PROCESS':
                lookup['events'].add((host_name(event['hostname']), event['id']))
    return lookup


def bound_intervals(paths, lookup, max_records=None):
    """Cap PID intervals at observed reuse or reboot, independent of file order.

    CSV starts are rounded to seconds. A creation during the starting second
    belongs to that interval; later creations end it. Only tracked host/PID
    pairs are retained. Read selected records from every selected stream, even
    with command limits: a later file can supply an earlier creation or reboot.
    """
    intervals = lookup['intervals']
    creations = defaultdict(set)
    reboots = defaultdict(set)
    for path in paths:
        with gzip.open(path, 'rt', encoding='utf-8', errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                if max_records is not None and number > max_records:
                    break
                # Boot markers affect process identity even without PID labels.
                # Without intervals, leave process parsing to the bounded reader.
                if not ('"HOST"' in line or '\\u00' in line or intervals and '"PROCESS"' in line):
                    continue
                event = json.loads(line)
                host = host_name(event.get('hostname'))
                time = timestamp(event.get('timestamp_ms', event.get('timestamp')))
                if time is None:
                    continue
                if event.get('object') == 'HOST' and event.get('action') in ('START', 'BOOT', 'REBOOT'):
                    reboots[host].add(time)
                elif event.get('object') == 'PROCESS' and event.get('action') == 'CREATE':
                    key = (host, str(event.get('pid')))
                    if key in intervals:
                        creations[key].add(time)
    lookup['reboots'] = {host: sorted(times) for host, times in reboots.items()}
    for key, ranges in intervals.items():
        bounded = []
        for start, end in ranges:
            # The end is exclusive only when it comes from a subsequent launch
            # or reboot. Publisher interval ends remain inclusive.
            later = sorted(time for time in creations[key] if time >= start)
            if later and later[0] < start + timedelta(seconds=1):
                later = later[1:]
            stops = later
            stops.extend(time for time in reboots[key[0]] if time > start)
            cutoff = min(stops) if stops else None
            bounded.append((start, end, cutoff))
        intervals[key] = bounded


def optc_command_label(host, process_id, event_id, pid, time, lookup, fallback):
    """Return the final command label, preferring reviewed and exact evidence."""
    host = host_name(host)
    event = (host, event_id)
    process = (host, process_id)
    direct = lookup['reviewed_events'].get(event)
    if direct is not None:
        return direct, None
    reviewed = lookup['reviewed_processes'].get(process)
    if reviewed == 'benign' or process in lookup['ordinary']:
        return 'benign', None
    if reviewed == 'malicious' or event in lookup['events']:
        return 'malicious', None
    if time is not None and pid is not None:
        for start, end, cutoff in lookup['intervals'].get((host, str(pid)), ()):
            if start <= time and (end is None or time <= end) and (cutoff is None or time < cutoff):
                return 'malicious', None
    return fallback[0], fallback[1] if fallback[0] == 'malicious-group' else None
