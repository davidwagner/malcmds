"""Combine raw Cowrie connections with unmatched cleaned command occurrences."""

import argparse
import ast
import json
import re
import sys
import tarfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from _ingest import Command, shell_commands


def _lines(archive, member, limit):
    stream = archive.extractfile(member)
    if stream is None:
        return
    with stream:
        for index, line in enumerate(stream, 1):
            if limit is not None and index > limit:
                break
            if line.strip():
                yield index, json.loads(line)


def _period(name, row):
    value = str(row.get('period') or row.get('timestamp') or name)
    return '2024' if '2024' in value else '2021_2022'


def _commands(text, identity, group, session, positive):
    parsed = shell_commands(text)
    for index, (pgm, args, other) in enumerate(parsed):
        # Severity annotates the submitted input, not each constituent command.
        label = 'malicious' if positive and len(parsed) == 1 else 'malicious-group'
        yield Command(pgm, args, f'{identity}:{index}', label=label,
                      group_id=group if label == 'malicious-group' else None,
                      session_id=session, shell_input=text, other_tokens=other)


def records(root: Path, options: argparse.Namespace) -> Iterator[Command]:
    """Read complete raw captures and fill cleaned gaps using occurrence counts."""
    path = root / 'release.tar.gz'
    if not path.is_file():
        raise FileNotFoundError(f'{path}: run ./fetch first')
    groups = {}
    positive = set()
    cleaned = []
    # Read only the small cleaned/annotation files during this pass.
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            name = member.name.split('/', 1)[-1]
            if not member.isfile():
                continue
            if name.startswith('dataset/sessions/') and name.endswith('.jsonl'):
                for line, row in _lines(archive, member, options.max_records):
                    period = _period(name, row)
                    ip = str(row.get('src_ip', ''))
                    group = f"shell-honeypot:{period}:group:{row['session_id']}"
                    groups[period, ip] = group
                    cleaned.append((name, line, period, ip, group, row['commands']))
            elif name.startswith('dataset/request_response/') and name.endswith('.jsonl'):
                for _, row in _lines(archive, member, options.max_records):
                    severity = row.get('severity_vi')
                    if isinstance(severity, (int, float)) and severity > 0:
                        text = row.get('command', row.get('request'))
                        if isinstance(text, str):
                            positive.add(text)
    if not cleaned:
        raise ValueError(f'{path}: missing published cleaned session files')
    connections = {}
    raw_counts = Counter()
    previous_events = Counter()
    raw_count = 0
    retained_cleaned = 0
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            name = member.name.split('/', 1)[-1]
            if not member.isfile() or not (
                '/cowrie/' in name or name.startswith('dataset/raw_samples/')
            ) or PurePosixPath(name).suffix not in ('.json', '.jsonl'):
                continue
            file_events = Counter()
            for line, row in _lines(archive, member, options.max_records):
                period = _period(name, row)
                ip = str(row.get('src_ip', row.get('src_host', '')))
                endpoints = (period, ip, str(row.get('src_port', '')),
                             str(row.get('dst_ip', row.get('dst_host', ''))),
                             str(row.get('dst_port', '')), str(row.get('protocol', '')))
                event = row.get('eventid', row.get('info', ''))
                native = str(row.get('session') or '')
                if event in ('cowrie.session.connect', 'session.connect'):
                    match = re.search(r'\[session:\s*([^\]]+)\]', row.get('tshark', ''))
                    connections[endpoints] = native or (match[1] if match else f'{name}:{line}')
                elif event in ('cowrie.session.closed', 'session.closed'):
                    connections.pop(endpoints, None)
                if event == 'cowrie.command.input':
                    text = row.get('input')
                elif event == 'command.input':
                    text = row.get('tshark', '')
                    if text.startswith('INPUT_COMD:'):
                        text = text[len('INPUT_COMD:'):].lstrip(' ')
                    elif text.startswith('command  found [ ') and text.endswith(']'):
                        encoded = ast.literal_eval(text[len('command  found [ '):-1].strip())
                        text = encoded.decode('utf-8', 'replace') if isinstance(encoded, bytes) else encoded
                else:
                    continue
                if not isinstance(text, str):
                    raise TypeError(f'{name}:{line}: command input is not a string')
                stamp = row.get('timestamp')
                identity = (endpoints, stamp, text)
                file_events[identity] += 1
                # Alternate raw samples can repeat whole-capture events. Keep
                # multiplicities within a capture, and do not merge untimed rows.
                if stamp and file_events[identity] <= previous_events[identity]:
                    continue
                raw_count += 1
                raw_counts[period, ip, text.strip()] += 1
                group = groups.get((period, ip), f'shell-honeypot:{period}:ip:{ip}')
                session = native or connections.get(endpoints, '')
                session = f'shell-honeypot:{period}:{session}' if session else ''
                yield from _commands(text, f'{name}:{line}', group, session, text in positive)
            previous_events |= file_events
    for name, line, period, ip, group, commands in cleaned:
        for index, text in enumerate(commands):
            key = (period, ip, text.strip())
            if raw_counts[key]:
                raw_counts[key] -= 1
                continue
            retained_cleaned += 1
            yield from _commands(text, f'{name}:{line}:{index}', group, '', text in positive)
    print(f'shell-honeypot: {raw_count} raw command inputs; '
          f'{retained_cleaned} unmatched cleaned command inputs', file=sys.stderr)
