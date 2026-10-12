"""Measure preliminary scans against a git revision on real gzip prefixes.

Run: python tests/benchmark_optc_preliminary.py --baseline BASE_COMMIT
Copies selected source prefixes under tmp/, compares every interval and reboot,
and reports medians for baseline serial, optimized serial, and six workers.
Short-partition samples are held out from serial tuning. Timings include worker
startup and merging, but exclude label loading and sample preparation.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time
from itertools import islice
from pathlib import Path

from isal import igzip

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
from _optc_labels import bound_intervals, load_labels


def result_digest(lookup):
    """Hash every bounded interval and reboot in deterministic order."""
    evidence = {
        'intervals': [(key, ranges) for key, ranges in sorted(lookup['intervals'].items())],
        'reboots': sorted(lookup['reboots'].items()),
    }
    encoded = json.dumps(evidence, default=str, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def samples(root, paths, lines, output):
    """Copy authentic file prefixes without touching original source archives."""
    metadata = []
    for source in paths:
        destination = output / source.relative_to(root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        count = size = 0
        with igzip.open(source, 'rb') as reader, igzip.open(destination, 'wb') as writer:
            for line in islice(reader, lines):
                writer.write(line)
                count += 1
                size += len(line)
        metadata.append({'source': str(source.relative_to(root)), 'lines': count,
                         'uncompressed_bytes': size, 'compressed_bytes': destination.stat().st_size})
    return [output / entry['source'] for entry in metadata], metadata


def measure(paths, lookup, baseline, repeats):
    """Alternate run order and require exact evidence equality after every scan."""
    durations = {name: [] for name in ('baseline', 'serial', 'six_workers')}
    expected = None
    for repeat in range(repeats):
        order = list(durations)
        if repeat % 2:
            order.reverse()
        for mode in order:
            result = copy.deepcopy(lookup)
            start = time.perf_counter()
            if mode == 'baseline':
                baseline(paths, result)
            else:
                bound_intervals(paths, result, workers=6 if mode == 'six_workers' else 1)
            elapsed = time.perf_counter() - start
            evidence = (result['intervals'], result['reboots'])
            if expected is None:
                expected = evidence
            if evidence != expected:
                raise AssertionError(f'{mode} changed PID lifetime or reboot evidence')
            durations[mode].append(elapsed)
            print(f'{mode}: {elapsed:.3f}s', flush=True)
    medians = {mode: statistics.median(times) for mode, times in durations.items()}
    return {'seconds': durations, 'median_seconds': medians,
            'serial_speedup': medians['baseline'] / medians['serial'],
            'parallel_speedup': medians['serial'] / medians['six_workers'],
            'total_speedup': medians['baseline'] / medians['six_workers'],
            'evidence_sha256': result_digest(result)}


def main():
    """Prepare seeded source prefixes and report verified scan timings."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--root', type=Path, default=REPO / 'datasets/optc')
    parser.add_argument('--lines', type=int, default=1000000)
    parser.add_argument('--files', type=int, default=6)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--seed', type=int, default=23)
    args = parser.parse_args()
    if min(args.lines, args.files, args.repeats) <= 0:
        parser.error('--lines, --files, and --repeats must be positive')
    root = args.root.resolve()
    if not (root / 'labels').is_dir():
        parser.error('--root must contain published labels')
    groups = {}
    rng = random.Random(args.seed)
    for name, partitions in (('primary', ('benign', 'evaluation')), ('held_out', ('short',))):
        paths = sorted(path for partition in partitions
                       for path in (root / 'ecar' / partition).rglob('*.json.gz'))
        if not paths:
            parser.error(f'No {name} gzip files under {root}')
        groups[name] = rng.sample(paths, min(args.files, len(paths)))
    revision = subprocess.check_output(
        ['git', 'rev-parse', '--verify', args.baseline + '^{commit}'], cwd=REPO, text=True).strip()
    scratch = REPO / 'tmp'
    scratch.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='optc-preliminary-', dir=scratch))
    print(f'Artifacts: {output}', flush=True)
    source = subprocess.check_output(['git', 'show', f'{revision}:scripts/_optc_labels.py'], cwd=REPO)
    baseline_path = output / 'baseline_labels.py'
    baseline_path.write_bytes(source)
    spec = importlib.util.spec_from_file_location('baseline_labels', baseline_path)
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)
    lookup = load_labels(root)
    report = {'baseline': revision, 'python': sys.version, 'platform': platform.platform(),
              'seed': args.seed, 'line_limit_per_file': args.lines, 'groups': {}}
    for name, paths in groups.items():
        selected, metadata = samples(root, paths, args.lines, output / name)
        report['groups'][name] = {'samples': metadata,
                                 **measure(selected, lookup, baseline.bound_intervals, args.repeats)}
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
