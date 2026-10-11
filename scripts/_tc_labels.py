"""Match TC commands to published process annotations and timed attack episodes."""

import ast
import csv
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


def nanoseconds(text, zone):
    """Convert a source's declared local time to Unix nanoseconds."""
    return int(datetime.fromisoformat(text).replace(tzinfo=ZoneInfo(zone)).timestamp() * 1_000_000_000)


class TCAnnotations:
    """Temporary dataset-scoped annotations, discarded after native ingestion."""

    def __init__(self, root):
        """Load this release's pinned annotations and report-derived rules once."""
        self.dataset = root.name
        self.episodes = {}
        for rule in json.loads(Path(__file__).with_name('_tc_attacks.json').read_text()):
            if rule['dataset'] != root.name:
                continue
            rule['first'] = nanoseconds(rule['start'], rule['timezone'])
            # A report ending at 12:09 includes 12:09:59.999999999.
            rule['last'] = nanoseconds(rule['end'], rule['timezone']) + 60_000_000_000 - 1
            self.episodes[rule['id']] = rule
        self.processes = defaultdict(set)
        self.objects = defaultdict(set)
        self.network_objects = set()
        self.neighborhood = set()
        self.related = defaultdict(dict)
        self.hosts = {host for rule in self.episodes.values() for host in rule.get('hosts', ())}
        directory = root / 'annotations'
        for path in sorted(directory.glob('*/*/*.csv')):
            if path.parent.name.lower() != root.name.removeprefix('tc-'):
                continue
            attack = path.stem
            if attack not in self.episodes:
                continue
            for line in path.read_text().splitlines():
                if not line.strip():
                    continue
                identifier, _, rest = line.partition(',')
                value, _, _ = rest.rpartition(',')
                details = ast.literal_eval(value)
                lookup = self.processes if 'subject' in details else self.objects
                lookup[identifier.strip().lower()].add(attack)
                if 'netflow' in details:
                    self.network_objects.add(identifier.strip().lower())
        for path in sorted(directory.glob('threatrace/*/ground_truth.txt')):
            if path.parent.name.lower() != root.name.removeprefix('tc-'):
                continue
            self.neighborhood.update(line.strip().lower() for line in path.read_text().splitlines() if line.strip())
        original = directory / 'original-reapr.csv'
        if original.exists():
            with original.open() as stream:
                for row in csv.DictReader(stream, skipinitialspace=True):
                    if row['label'].strip() not in {'attack', 'contaminated'}:
                        continue
                    chain = row['attack_chain'].strip()
                    sections = set(re.findall(r'_(\d+\.\d+)(?:_|$)', chain))
                    attacks = {name for name, rule in self.episodes.items() if rule.get('section') in sections}
                    # Downstream contamination has no per-episode mapping. Its
                    # process IDs remain eligible only inside a report window.
                    self.processes[row['uuid'].strip().lower()].update(attacks or self.episodes)

    def add_relation(self, scope, process, timestamp, objects):
        """Resolve annotated file/network objects to the process using the event."""
        if not process or timestamp is None:
            return
        for identifier in objects:
            identifier = identifier.lower()
            for attack in self.objects.get(identifier, ()):
                rule = self.episodes[attack]
                if identifier not in self.network_objects and not rule['first'] <= timestamp <= rule['last']:
                    # A later read of a shared file does not establish that an
                    # attack connection continued beyond the report window.
                    continue
                # Related activity must start during the documented episode.
                # Later events on that same annotated object can establish that
                # this process's connection continued beyond the reported end.
                key = (scope, process.lower())
                first, last, started = self.related[key].get(attack, (timestamp, timestamp, False))
                started = started or rule['first'] <= timestamp <= rule['last']
                self.related[key][attack] = (min(first, timestamp), max(last, timestamp), started)

    def label(self, host, restart, process, timestamp, pgm, args, context):
        """Return the strongest final command label, with a group only when needed."""
        if timestamp is None:
            return 'unknown', None
        if self.dataset == 'tc-e5-marple':
            instance = context.get('instance')
            if instance not in {'marple-1', 'marple-2', 'marple-3'}:
                return 'unknown', None
            # Report-based benign periods take precedence over annotations of
            # a browser that was compromised later in the exercise.
            if instance != 'marple-1' or not any(
                rule['first'] <= timestamp <= rule['last']
                for rule in self.episodes.values()
            ):
                return 'benign', None
        if self.hosts and host not in self.hosts:
            return 'unknown', None
        process = process.lower()
        scope = f'{host}:{restart}'
        related = self.related.get((scope, process), {})
        active = []
        benign = []
        for name, rule in self.episodes.items():
            if rule.get('instances') and context.get('instance') not in rule['instances']:
                continue
            if rule.get('hosts') and host not in rule['hosts']:
                continue
            in_window = rule['first'] <= timestamp <= rule['last']
            if rule.get('label') == 'benign':
                if in_window:
                    benign.append(rule)
                continue
            # Attack-only executables provide direct evidence at their recorded
            # execution, allowing the report's minute precision on either side.
            if pgm in rule.get('executables', ()) and rule['first'] - 60_000_000_000 <= timestamp <= rule['last'] + 60_000_000_000:
                return 'malicious', None
            interval = related.get(name)
            if interval and interval[2] and rule['first'] <= timestamp <= max(rule['last'], interval[1]):
                return 'malicious', None
            if in_window:
                if name in self.processes.get(process, ()):
                    return 'malicious', None
                for action in rule.get('actions', ()):
                    first = nanoseconds(action['start'], rule['timezone']) if 'start' in action else rule['first']
                    last = nanoseconds(action['end'], rule['timezone']) + 60_000_000_000 - 1 if 'end' in action else rule['last']
                    if not first <= timestamp <= last:
                        continue
                    programs = action.get('programs', ())
                    program = pgm
                    if self.dataset.endswith(('fivedirections', 'marple')):
                        program = pgm.replace('/', '\\').casefold()
                        programs = [value.replace('/', '\\').casefold() for value in programs]
                    if programs and program not in programs:
                        continue
                    if action.get('pids') and str(context.get('pid')) not in action['pids']:
                        continue
                    if not all(argument in args for argument in action.get('arguments', ())):
                        continue
                    if action.get('programs') or action.get('pids'):
                        return 'malicious', None
                active.append(rule)
        if process in self.neighborhood and not active:
            day = datetime.fromtimestamp(timestamp / 1_000_000_000, ZoneInfo('US/Eastern')).date().isoformat()
            return 'malicious-group', f'{self.dataset}:{host}:threatrace-process-set:{day}'
        if active or benign:
            # Prefer the shortest matching episode when report windows overlap.
            rules = active if process in self.neighborhood and active else active + benign
            rule = min(rules, key=lambda row: (row['last'] - row['first'], row['id']))
            if rule.get('label') == 'benign':
                return 'benign', None
            group = f"{self.dataset}:{host}:{rule['id']}:{rule['first']}-{rule['last']}"
            return 'malicious-group', group
        # Absence from positive annotations and training split membership are
        # insufficient evidence for a benign-only collection interval.
        return 'unknown', None
