"""Stream AutoLabel's nested scenario archives without extracting log trees."""

import argparse
import json
import shlex
import tarfile
from collections.abc import Iterator
from pathlib import Path

import orjson
from _ingest import Command, normalize, select_files
from _ingest_acme import ordinary_launch

MARKERS = ('A#t#k#F#1#', 'A#t#k#F#2#', 'A#t#k#F#3#')


def _clean(text):
    for marker in MARKERS:
        text = text.replace(marker, '')
    return text


def _decode_event(line: bytes) -> dict[str, object]:
    """Use fast decoding while preserving fields that affect commands or sessions."""
    try:
        event = orjson.loads(line)
    except orjson.JSONDecodeError:
        # Keep existing support for nonstandard numbers and encodings, and let
        # the original parser report malformed input instead of skipping it.
        return json.loads(line)
    if event.get('evt.type') in {
        'execve', 'execveat', 'clone', 'clone3', 'fork', 'vfork',
        'procexit', 'exit', 'exit_group',
    }:
        # orjson can round large integers without raising an error. Preserve
        # exact attempt/process IDs and all other fields used by these events.
        return json.loads(line)
    return event


def _log_records(stream, run, seen, lifetimes, limit):
    for index, line in enumerate(stream):
        if limit is not None and index >= limit:
            break
        event = _decode_event(line)
        kind = event.get('evt.type')
        container = str(event.get('container.id') or 'host')
        process = str(event.get('proc.vpid') or event.get('thread.vtid') or event.get('proc.pid') or '')
        key = container, process
        number = str(event.get('evt.num', ''))
        if kind in {'clone', 'clone3', 'fork', 'vfork'}:
            child = event.get('evt.rawres')
            if child is not None and str(child).isdigit() and int(child) > 0:
                parent_session = lifetimes.setdefault(key, f'{run}:{container}:process:{process}:{number}')
                lifetimes[container, str(child)] = parent_session
            continue
        if kind in {'procexit', 'exit', 'exit_group'}:
            lifetimes.pop(key, None)
            continue
        if kind not in {'execve', 'execveat'}:
            continue
        if not number:
            raise ValueError('AutoLabel exec is missing evt.num; attempt identity cannot be recovered')
        identity = f'{run}:{container}:{number}'
        if identity in seen:
            continue
        seen.add(identity)
        text = _clean(str(event.get('proc.cmdline') or ''))
        result = event.get('evt.rawres')
        success = result in (0, '0')
        if success:
            pgm = event.get('proc.exepath') or event.get('proc.name')
            parsed = normalize(text, pgm=pgm)
            if parsed:
                pgm, args = parsed[0]
            else:
                args = []
        else:
            pgm = event.get('evt.arg.filename') or event.get('evt.arg.pathname')
            arguments = event.get('evt.arg.args') or event.get('evt.arg.argv')
            if isinstance(arguments, list):
                args = [str(item) for item in arguments]
            elif arguments:
                try:
                    args = shlex.split(_clean(str(arguments)))
                except ValueError:
                    args = _clean(str(arguments)).split()
            else:
                args = []
            if not pgm:
                # Some exports omit the attempted filename and argv. Preserve
                # the remaining process observation instead of dropping an attempt.
                pgm = event.get('proc.exepath') or event.get('proc.name')
                if not arguments:
                    parsed = normalize(text, pgm=pgm)
                    if parsed:
                        pgm, args = parsed[0]
            if args and pgm and args[0] in {pgm, pgm.rsplit('/', 1)[-1]}:
                args = args[1:]
        if not pgm:
            raise ValueError(f'AutoLabel exec {identity} has no executable')
        args = [_clean(arg) for arg in args]
        published = event.get('malicious')
        group = None
        if ordinary_launch(pgm, args):
            label = 'benign'
        elif published is True:
            label = 'malicious'
        elif published is False:
            label = 'benign'
        elif published == 'Suspicious':
            label, group = 'malicious-group', run
        else:
            label = 'unknown'
        session = ''
        if process:
            session = lifetimes.setdefault(key, f'{run}:{container}:process:{process}:{number}')
        yield Command(pgm, args, identity, label=label, group_id=group, session_id=session)


def _archive_records(archive, run, limit):
    seen = set()
    lifetimes = {}
    for member in archive:
        if not member.isfile():
            continue
        name = member.name.lstrip('./')
        if name.endswith(('.tar.gz', '.tgz', '.tar')):
            with archive.extractfile(member) as stream, tarfile.open(fileobj=stream, mode='r|*') as nested:
                yield from _archive_records(nested, f'{run}/{name}', limit)
        elif '/sysdig/' in '/' + name and name.endswith('.log'):
            with archive.extractfile(member) as stream:
                yield from _log_records(stream, run, seen, lifetimes, limit)


def records(root: Path, options: argparse.Namespace) -> Iterator[Command]:
    """Read all scenario archives and every nested run's Sysdig exec attempts."""
    files = select_files([*root.glob('*.tar'), *root.glob('*.tar.gz'), *root.glob('*.tgz')], options)
    if not files:
        raise FileNotFoundError('No AutoLabel archives found; run ./fetch first')
    manifest = root / 'release.json'
    if manifest.exists() and not getattr(options, 'sample_files', None):
        missing = [item['name'] for item in json.loads(manifest.read_text()) if not (root / item['name']).exists()]
        if missing:
            raise FileNotFoundError('AutoLabel release is incomplete; run ./fetch: ' + ', '.join(missing))
    for path in files:
        with tarfile.open(path, mode='r|*') as archive:
            yield from _archive_records(archive, path.name, options.max_records)
