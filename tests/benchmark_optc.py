"""Compare serial OpTC CLI ingestion and every output row against a git revision.

Run with the ingestion requirements installed:
    python tests/benchmark_optc.py --baseline 86da625

Copies bounded authentic samples into tmp/, includes published label loading and
fresh database writes in every timed run, and alternates baseline/current order.
The short partition is held out from performance tuning. No timing assertion is
used in CI: inspect the reported medians rather than assuming a fixed speedup.
"""

import argparse
import hashlib
import io
import json
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from itertools import islice
from pathlib import Path

import duckdb
from isal import igzip

REPO = Path(__file__).resolve().parents[1]


def snapshot(baseline, output):
    """Snapshot baseline and current scripts so both runs use stable source files."""
    revision = subprocess.check_output(
        ['git', 'rev-parse', '--verify', baseline + '^{commit}'], cwd=REPO, text=True,
    ).strip()
    archive = subprocess.check_output(['git', 'archive', revision, 'scripts'], cwd=REPO)
    with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
        stream.extractall(output / 'baseline', filter='data')
    shutil.copytree(REPO / 'scripts', output / 'current/scripts',
                    ignore=shutil.ignore_patterns('__pycache__'))
    return revision


def sample(root, partition, seed, lines, output):
    """Copy a seeded file prefix and link its original, read-only label archives."""
    files = sorted((root / 'ecar' / partition).rglob('*.json.gz'))
    if not files:
        raise FileNotFoundError(f'No {partition} eCAR files under {root}')
    source = random.Random(seed).choice(files)
    target = output / partition / 'optc' / source.relative_to(root)
    target.parent.mkdir(parents=True)
    count = 0
    with igzip.open(source, 'rb') as reader, igzip.open(target, 'wb') as writer:
        for line in islice(reader, lines):
            writer.write(line)
            count += 1
    labels = root / 'labels'
    (output / partition / 'optc' / 'labels').symlink_to(labels, target_is_directory=True)
    return {'partition': partition, 'seed': seed, 'source': str(source.relative_to(root)),
            'lines': count, 'compressed_bytes': target.stat().st_size}


def ingest(scripts, root, database):
    """Time a fresh single-worker CLI process, then read all persistent tables."""
    driver = (
        'import sys; from pathlib import Path; '
        f'sys.path.insert(0, {str(scripts)!r}); '
        'from _ingest import run; from _ingest_optc import records; '
        f'run(Path({str(root)!r}), records)'
    )
    start = time.perf_counter()
    result = subprocess.run(
        [sys.executable, '-c', driver, '--db', str(database), '--workers', '1'],
        text=True, capture_output=True, check=True,
    )
    elapsed = time.perf_counter() - start
    database.with_suffix('.log').write_text(result.stdout + result.stderr)
    with duckdb.connect(str(database), read_only=True, config={'threads': 1}) as connection:
        tables = {name: connection.execute(f'SELECT * FROM "{name}" ORDER BY ALL').fetchall()
                  for (name,) in connection.execute('SHOW TABLES').fetchall()}
    return elapsed, tables


def main():
    """Prepare three samples, alternate serial runs, and report verified medians."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--root', type=Path, default=REPO / 'datasets/optc')
    parser.add_argument('--lines', type=int, default=200000)
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    if args.lines <= 0 or args.repeats <= 0:
        parser.error('--lines and --repeats must be positive')
    root = args.root.resolve()
    if not (root / 'labels').is_dir():
        parser.error('--root must contain published labels for an end-to-end comparison')
    scratch = REPO / 'tmp'
    scratch.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='benchmark-optc-', dir=scratch))
    report = {'baseline': snapshot(args.baseline, output), 'python': sys.version,
              'platform': platform.platform(), 'workers': 1, 'samples': []}
    print(f'Artifacts: {output}', flush=True)
    for partition, seed in [('benign', 71), ('evaluation', 71), ('short', 91)]:
        entry = sample(root, partition, seed, args.lines, output)
        timings = {'baseline': [], 'current': []}
        expected = None
        for repeat in range(args.repeats):
            order = ('baseline', 'current') if repeat % 2 == 0 else ('current', 'baseline')
            for variant in order:
                elapsed, tables = ingest(output / variant / 'scripts', output / partition / 'optc',
                                         output / f'{partition}-{variant}-{repeat}.duckdb')
                timings[variant].append(elapsed)
                if expected is None:
                    expected = tables
                assert tables == expected, f'{partition}: {variant} changed database output'
                print(f'{partition} {variant} {repeat + 1}: {elapsed:.3f}s', flush=True)
        entry.update(seconds=timings, speedup=statistics.median(timings['baseline']) /
                     statistics.median(timings['current']), rows=len(expected['PROCESS_LAUNCHES']),
                     output_sha256=hashlib.sha256(json.dumps(expected).encode()).hexdigest())
        report['samples'].append(entry)
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(entry), flush=True)


if __name__ == '__main__':
    main()
