"""Import one observation source per period, reconstructing connection intervals."""

import ast
import hashlib
import json
import re
import tarfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from _ingest import Command, ShellInput, normalize
from _shell_honeypot_labels import LabelDecision, classify_input

REVISION = 'd5f7fe120ebd921e04026b6348c3ec5d399c5df6'
RELEASE_SHA256 = '266ed2e6c0923e56f317bf880b7294698cfc5792538cc8f58dbdfda68a9c0c11'
EARLY = 'dataset/sessions/2021_2022.jsonl'
CURATED = 'dataset/request_response/curated.jsonl'
WRAPPER = re.compile(r'^command (?: found|not found) \[\s*(.*?)\s*\]$', re.DOTALL)


@dataclass(frozen=True, slots=True)
class Event:
    """A relevant source event; its position always identifies the original row."""

    record_id: str
    path: str
    line: int
    collection: str
    sensor: str
    protocol: str
    timestamp: float | None
    endpoints: tuple | None
    native_session: str | None
    kind: str
    text: str | None
    transformed: bool


@dataclass(frozen=True, slots=True)
class AssignedEvent:
    """An event and the source of its connection assignment."""

    event: Event
    session_id: str
    method: str


def audit_entry(audit, record_id, action, reason, **details):
    """Write a source-addressable decision without retaining the entire log in RAM."""
    audit.write(json.dumps(dict(record_id=record_id, action=action, reason=reason,
                               **details), ensure_ascii=True) + '\n')


def read_rows(archive, member, audit, counts):
    """Read JSON lines and account for malformed records individually."""
    path = member.name.split('/', 1)[-1]
    with archive.extractfile(member) as stream:
        for line, raw in enumerate(stream, 1):
            record_id = f'{path}:line:{line}'
            try:
                row = json.loads(raw)
                if not isinstance(row, dict):
                    raise TypeError('expected object')
            except (TypeError, ValueError, UnicodeDecodeError) as error:
                counts['malformed-json'] += 1
                audit_entry(audit, record_id, 'skip', 'malformed-json', error=str(error))
                continue
            yield path, line, row


def event_kind(row):
    """Translate native Cowrie and the released transformed event names."""
    name = row.get('eventid', row.get('info', ''))
    name = name.removeprefix('cowrie.') if isinstance(name, str) else ''
    kinds = {'command.input': 'input', 'command.failed': 'failed',
             'session.connect': 'connect', 'session.closed': 'close',
             'session.loseConnection': 'close', 'login.success': 'login_ok',
             'login.failed': 'login_failed'}
    if name == 'userlogin':
        return 'login_ok' if str(row.get('tshark', '')).endswith('succeeded') else 'login_failed'
    return kinds.get(name, 'metadata')


def endpoint_tuple(row):
    """Normalize complete structured endpoints; never share a missing-port sentinel."""
    src = row.get('src_ip', row.get('src_host'))
    dst = row.get('dst_ip', row.get('dst_host'))
    try:
        ports = [row.get('src_port'), row.get('dst_port')]
        if any(isinstance(p, bool) or not re.fullmatch(r'\d+', str(p)) for p in ports):
            return None
        sport, dport = map(int, ports)
        if not (0 < sport <= 65535 and 0 < dport <= 65535):
            return None
        if not isinstance(src, str) or not src or not isinstance(dst, str) or not dst:
            return None
        return src, sport, dst, dport
    except (ValueError, TypeError):
        return None


def read_events(archive, members, audit, counts):
    """Decode supported source records while retaining relevant connection metadata."""
    for member in members:
        for path, line, row in read_rows(archive, member, audit, counts):
            record_id = f'{path}:line:{line}'
            protocol = row.get('protocol')
            if protocol not in ('ssh', 'telnet'):
                counts['unsupported-protocol'] += 1
                audit_entry(audit, record_id, 'skip', 'unsupported-protocol', protocol=protocol)
                continue
            kind = event_kind(row)
            if kind == 'metadata':
                counts['metadata:' + str(row.get('eventid', row.get('info', '')))] += 1
                continue
            transformed = 'eventid' not in row
            text = row.get('tshark') if transformed else row.get('input')
            if kind in ('input', 'failed') and not isinstance(text, str):
                counts['non-string-input'] += 1
                audit_entry(audit, record_id, 'skip', 'non-string-input')
                continue
            try:
                timestamp = datetime.fromisoformat(row['timestamp'])
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                stamp = timestamp.timestamp()
            except (KeyError, TypeError, ValueError, OverflowError):
                stamp = None
            native = row.get('session')
            native = native if isinstance(native, str) and native else None
            if kind == 'connect' and transformed:
                match = re.search(r'\[session:\s*([^\]]+)\]', str(text))
                native = match[1] if match else None
            yield Event(record_id, path, line, '2024', 'deployment', protocol, stamp,
                        endpoint_tuple(row), native, kind, text, transformed)


def event_sort_key(event):
    """Sort all daily files together with numeric source positions as tie breakers."""
    return (event.collection, event.sensor, event.protocol, event.endpoints or ('', 0, '', 0),
            event.timestamp if event.timestamp is not None else float('-inf'),
            event.path, event.line)


def assign_sessions(events, idle_minutes=60, counts=None, source_scope=""):
    """Assign sorted events to explicit connections or login/inactivity estimates."""
    previous_key = None
    current = None
    explicit = False
    has_command = False
    last = None
    for event in events:
        key = (event.collection, event.sensor, event.protocol, event.endpoints)
        if key != previous_key:
            current, explicit, has_command, last = None, False, False, None
            previous_key = key
        namespace = f'shell-honeypot:{event.collection}:{event.sensor}'
        if event.native_session and not event.transformed:
            yield AssignedEvent(event, f'{namespace}:native:{event.native_session}', 'native')
            continue
        namespace += source_scope
        if event.endpoints is None or event.timestamp is None:
            yield AssignedEvent(event, f'shell-honeypot:record:{event.record_id}', 'record')
            continue
        if event.kind == 'connect':
            current = (f'{namespace}:connect:{event.native_session or "unknown"}:{event.record_id}', 'connect')
            explicit, has_command = True, False
        elif event.kind == 'close':
            if current:
                yield AssignedEvent(event, *current)
            elif counts is not None:
                counts['orphan-close'] += 1
            current, explicit, has_command, last = None, False, False, None
            continue
        elif event.protocol == 'ssh' and event.kind.startswith('login') and not explicit:
            if counts is not None:
                counts['orphan-ssh-login'] += 1
            continue
        else:
            idle = last is not None and event.timestamp - last > idle_minutes * 60
            login = event.protocol == 'telnet' and event.kind == 'login_ok' and has_command
            if current is None or (not explicit and idle) or login:
                method = 'login' if event.kind == 'login_ok' else 'idle'
                current = (f'{namespace}:{method}:{event.record_id}', method)
                explicit, has_command = False, False
        last = event.timestamp
        if event.kind in ('input', 'failed'):
            has_command = True
        yield AssignedEvent(event, *current)


def decode_connection(events, audit, counts):
    """Reconstruct fragment text safely; preserve literal input spelling exactly.

    Fragment rows are best-effort shell observations at their own source positions.
    Lost operators or quoting cannot be recovered. In mixed connections, literal
    inputs take precedence and ambiguous fragment messages remain in the audit.
    """
    wrapped = [e for e in events if e.event.kind == 'input' and e.event.transformed
               and WRAPPER.fullmatch(e.event.text)]
    plain = [e for e in events if e.event.kind == 'input' and e not in wrapped]
    for assigned in events:
        event = assigned.event
        match = WRAPPER.fullmatch(event.text) if event.transformed else None
        if match:
            if plain:
                reason = 'ambiguous-mixed-fragment' if event.kind == 'input' else 'failed-with-literal-input'
                counts[reason] += 1
                audit_entry(audit, event.record_id, 'skip', reason, raw_text=event.text,
                            session_id=assigned.session_id)
                continue
            if event.kind == 'failed' and not wrapped:
                counts['isolated-failed-fragment'] += 1
                audit_entry(audit, event.record_id, 'skip', 'isolated-failed-fragment', raw_text=event.text)
                continue
            try:
                text = ast.literal_eval(match[1])
                if isinstance(text, bytes):
                    text = text.decode('utf-8')
                if not isinstance(text, str):
                    raise TypeError('wrapper does not contain a string')
            except (TypeError, ValueError, SyntaxError, UnicodeError) as error:
                counts['malformed-wrapper'] += 1
                audit_entry(audit, event.record_id, 'skip', 'malformed-wrapper',
                            raw_text=event.text, error=str(error))
                continue
            yield assigned, text, 'reconstructed-fragment'
        elif event.kind == 'input':
            # INPUT_COMD is a documented prefix in sample/native format exports.
            text = event.text
            limitation = None
            if event.transformed and text.startswith('INPUT_COMD:'):
                text = text.removeprefix('INPUT_COMD:').lstrip(' ')
                limitation = 'removed-input-prefix'
            yield assigned, text, limitation
        else:
            counts['unassociated-failed-message'] += 1
            audit_entry(audit, event.record_id, 'skip', 'unassociated-failed-message', raw_text=event.text)


def load_replay_annotations(archive, members, audit, counts):
    """Keep exact-text annotations, all scores, and mismatched replay text for review."""
    annotations = defaultdict(list)
    replay_turns = {}
    ordered = sorted(members, key=lambda m: m.name.endswith('curated.jsonl'))
    for member in ordered:
        for path, line, row in read_rows(archive, member, audit, counts):
            text = row.get('command', row.get('request'))
            if not isinstance(text, str):
                counts['non-string-replay'] += 1
                continue
            key = (str(row.get('session_id')), str(row.get('turn_index')))
            if path != CURATED:
                replay_turns[key] = text
                continue
            reference = {'record_id': f'{path}:line:{line}', 'severity': row.get('severity_vi'),
                             'system_change': row.get('system_change', row.get('system_changes'))}
            annotations[text].append(reference)
            if key in replay_turns and replay_turns[key] != text:
                counts['changed-replay-text'] += 1
                audit_entry(audit, reference['record_id'], 'review', 'changed-replay-text',
                            curated_text=text, replay_text=replay_turns[key])
    counts['conflicting-replay-scores'] = sum(
        len({json.dumps(r['severity'], sort_keys=True) for r in refs}) > 1
        for refs in annotations.values())
    return annotations


def read_early_inputs(archive, member, audit, counts):
    """Preserve every earlier list position without equating an IP group to a login."""
    for path, line, row in read_rows(archive, member, audit, counts):
        commands = row.get('commands')
        if not isinstance(commands, list):
            counts['invalid-command-list'] += 1
            audit_entry(audit, f'{path}:line:{line}', 'skip', 'invalid-command-list')
            continue
        for index, text in enumerate(commands):
            record_id = f'{path}:line:{line}:command:{index}'
            if not isinstance(text, str):
                counts['non-string-input'] += 1
                audit_entry(audit, record_id, 'skip', 'non-string-input')
                continue
            event = Event(record_id, path, line, '2021_2022', 'deployment', 'unknown',
                          None, None, None, 'input', text, False)
            yield AssignedEvent(event, f'shell-honeypot:record:{record_id}', 'record'), text, 'unknown-login'


def make_observation(assigned, text, limitation, annotations, audit, totals, distinct, sessions):
    """Parse one input and attach independent shell and invocation behavior labels."""
    event = assigned.event
    commands = [Command(pgm, args, f'{event.record_id}:{index}', session_id=assigned.session_id)
                for index, (pgm, args) in enumerate(normalize(text, os='linux', shell=True))]
    decision, children = classify_input(text, commands)
    if decision.label == 'unknown':
        # Replay annotations describe the full input, not each parsed invocation.
        scores = [ref['severity'] for ref in annotations.get(text, [])
                  if ref['severity'] is not None]
        labels = {({0: 'benign', 1: 'benign', 4: 'malicious'}.get(score, 'unknown')
                   if type(score) is int else 'unknown') for score in scores}
        if len(labels) == 1 and 'unknown' not in labels:
            decision = LabelDecision(labels.pop(), 'replay-severity-vi')
    for command, child in zip(commands, children, strict=True):
        command.label = child.label
    observation = ShellInput(text, event.record_id, commands, label=decision.label,
                             session_id=assigned.session_id)
    key = f'{event.collection}/{event.protocol}'
    totals[key]['shell:' + decision.label] += 1
    totals[key]['reason:' + decision.reason] += 1
    for child in children:
        totals[key]['process:' + child.label] += 1
        totals[key]['process-reason:' + child.reason] += 1
    if text not in distinct[key]:
        distinct[key][text] = [decision.label, 0]
    distinct[key][text][1] += 1
    sessions[key][assigned.session_id] += 1
    audit_entry(audit, event.record_id, 'emit', decision.reason, source=event.path,
                line=event.line, session_id=assigned.session_id, method=assigned.method,
                label=decision.label, child_rules=[c.reason for c in children],
                references=list(decision.references), replay_references=annotations.get(text, []),
                limitation=limitation, raw_text=event.text if limitation == 'reconstructed-fragment' else None)
    return observation


def records(root: Path, options):
    """Read the pinned archive, write audit reports, and feed the shared DB writer."""
    path = root / 'release.tar.gz'
    if not path.is_file():
        raise FileNotFoundError(f'{path}: run ./fetch first')
    counts = Counter()
    totals = defaultdict(Counter)
    distinct = defaultdict(dict)
    sessions = defaultdict(Counter)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    with (root / 'import-audit.jsonl').open('w') as audit, tarfile.open(path, 'r:gz') as archive:
        members = {m.name.split('/', 1)[-1]: m for m in archive if m.isfile()}
        raw = [m for n, m in sorted(members.items()) if n.startswith('2024/cowrie/')
               and n.endswith(('.json', '.jsonl'))]
        early = members.get(EARLY)
        if not raw and early is None:
            raise ValueError('missing supported observation sources')
        annotations = load_replay_annotations(archive, [m for n, m in members.items()
            if n in (CURATED, 'dataset/request_response/vm_replay_2021_2022.jsonl')], audit, counts)
        events = sorted(read_events(archive, raw, audit, counts), key=event_sort_key)
        sensitivity = {}
        for minutes in (5, 15, 30, 60):
            sizes = Counter(a.session_id for a in assign_sessions(events, minutes)
                            if a.event.protocol == 'telnet' and a.event.kind == 'input')
            sensitivity[str(minutes)] = {'sessions': len(sizes), 'singletons': sum(v == 1 for v in sizes.values())}
        connections = defaultdict(list)
        login_sessions = set()
        scope = '' if digest == RELEASE_SHA256 else f':partial:{digest[:16]}'
        for assigned in assign_sessions(events, counts=counts, source_scope=scope):
            if assigned.event.kind in ('input', 'failed'):
                connections[assigned.session_id].append(assigned)
            elif assigned.event.protocol == 'telnet' and assigned.event.kind == 'login_ok':
                login_sessions.add(assigned.session_id)
        counts['telnet-login-sessions'] = len(login_sessions)
        counts['telnet-login-sessions-with-input'] = sum(
            any(a.event.kind == 'input' for a in connections.get(s, ())) for s in login_sessions)
        del events
        complete = False
        emitted = 0
        cap = getattr(options, 'max_records', None)
        manifest = {'revision': REVISION, 'archive_sha256': digest,
                        'full_pinned_archive': digest == RELEASE_SHA256,
                        'sources': [{'path': n, 'bytes': m.size} for n, m in sorted(members.items())
                                 if m in raw or n == EARLY or n in (CURATED, 'dataset/request_response/vm_replay_2021_2022.jsonl')],
                        'idle_minutes': 60, 'session_scope': 'full-selected-sources',
                        'inferred_id_source_scope': scope or 'pinned-release',
                        'output_limit': getattr(options, 'limit', None), 'max_records': cap,
                        'sample_files': getattr(options, 'sample_files', None)}
        (root / 'import-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        try:
            for group in connections.values():
                for assigned, text, limitation in decode_connection(group, audit, counts):
                    if cap is not None and emitted >= cap:
                        return
                    emitted += 1
                    yield make_observation(assigned, text, limitation, annotations, audit, totals, distinct, sessions)
            if early:
                for assigned, text, limitation in read_early_inputs(archive, early, audit, counts):
                    if cap is not None and emitted >= cap:
                        return
                    emitted += 1
                    yield make_observation(assigned, text, limitation, annotations, audit, totals, distinct, sessions)
            complete = True
        finally:
            groups = {}
            for key, values in totals.items():
                labels = Counter(label for label, count in distinct[key].values())
                shell_count = sum(v for k, v in values.items() if k.startswith('shell:'))
                process_count = sum(v for k, v in values.items() if k.startswith('process:'))
                unknowns = Counter({text: count for text, (label, count) in distinct[key].items() if label == 'unknown'})
                groups[key] = {'counts': dict(values), 'distinct_labels': dict(labels),
                                   'shell_unknown_rate': values['shell:unknown'] / shell_count if shell_count else 0,
                                   'process_unknown_rate': values['process:unknown'] / process_count if process_count else 0,
                                   'distinct_unknown_rate': labels['unknown'] / len(distinct[key]),
                                   'sessions': len(sessions[key]), 'singletons': sum(v == 1 for v in sessions[key].values()),
                                   'frequent_unknown_inputs': unknowns.most_common(30)}
            summary = {'output_complete': complete, 'emitted_shell_rows': emitted,
                           'emitted_process_rows': sum(v for c in totals.values() for k, v in c.items() if k.startswith('process:')),
                           'counts': dict(counts), 'groups': groups, 'telnet_timeout_minutes': sensitivity}
            (root / 'import-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
