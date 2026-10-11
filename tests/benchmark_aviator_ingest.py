"""Compare complete single-worker ingests on prefixes of real AVIATOR exports.

Example (Python needs scripts/ingest-requirements.txt):
    python tests/benchmark_aviator_ingest.py --source datasets/aviator \
        --baseline-ref main --output tmp/aviator-benchmark

Preparation is excluded from timing. Every timed run uses a fresh DuckDB file;
wall time includes interpreter startup, imports, parsing, commits and shutdown.
The JSON report includes every run, medians, source hashes and exact row checks.
"""

import argparse
import hashlib
import io
import json
import shutil
import statistics
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import duckdb

REPO = Path(__file__).resolve().parents[1]
ARCHIVE = '10.35097-8s5b0u5yqgfs2y0d.tar'
KINDS = ('sysmon', 'msft_security', 'powershell', 'alpc')


def prepare_sample(source, output, scenario, size):
    """Preserve the first export of each kind, ending its prefix at a full event."""
    root = output / scenario / 'aviator'
    root.mkdir(parents=True)
    manifest = []
    with tarfile.open(source / ARCHIVE, 'r:') as original:
        member = next(m for m in original if Path(m.name).name == f'ex_{scenario}.zip')
        payload = io.BytesIO()
        with original.extractfile(member) as binary, zipfile.ZipFile(binary) as zipped, \
                zipfile.ZipFile(payload, 'w', compression=zipfile.ZIP_DEFLATED) as sample:
            for kind in KINDS:
                names = sorted(name for name in zipped.namelist()
                               if Path(name).name.lower().startswith(kind)
                               and name.endswith('.xml'))
                if not names:
                    continue
                name = names[0]
                with zipped.open(name) as stream:
                    raw = stream.read(size)
                end = raw.rfind(b'</Event>')
                if end < 0:
                    raise ValueError(f'No complete byte-encoded XML event in {name}')
                raw = raw[:end + 8]
                sample.writestr(name, raw)
                manifest.append({'name': name, 'bytes': len(raw),
                                 'sha256': hashlib.sha256(raw).hexdigest()})
        with tarfile.open(root / ARCHIVE, 'w') as archive:
            info = tarfile.TarInfo(member.name)
            info.size = payload.tell()
            payload.seek(0)
            archive.addfile(info, payload)
    ground_truth = source / 'aviator-ground-truth-and-tools.tar.gz'
    if ground_truth.exists():
        shutil.copy2(ground_truth, root / ground_truth.name)
    return root, manifest


def snapshot_scripts(reference, output):
    """Save the selected committed baseline without altering either checkout."""
    revision = subprocess.check_output(['git', 'rev-parse', reference], cwd=REPO, text=True).strip()
    data = subprocess.check_output(['git', 'archive', revision, 'scripts'], cwd=REPO)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(output, filter='data')
    return output / 'scripts', revision


def ingest(scripts, root, database):
    """Time one actual CLI driver with one reader and DuckDB's existing one thread."""
    code = (f'import sys,time,json; from pathlib import Path; '
            f'sys.path.insert(0, {str(scripts)!r}); '
            'from _ingest import run; from _ingest_aviator import records; '
            'start=time.process_time(); '
            f'run(Path({str(root)!r}), records); '
            'print(json.dumps({"cpu_seconds":time.process_time()-start}))')
    start = time.monotonic()
    result = subprocess.run([sys.executable, '-c', code, '--db', str(database),
                             '--workers', '1'], capture_output=True, text=True, check=True)
    elapsed = time.monotonic() - start
    database.with_suffix('.log').write_text(result.stdout + result.stderr)
    return {'wall_seconds': elapsed, **json.loads(result.stdout.splitlines()[-1])}


def compare_rows(first, second):
    """Compare every stored column in insertion order, including completion state."""
    counts = {}
    with duckdb.connect(str(first), read_only=True, config={'threads': 1}) as before, \
            duckdb.connect(str(second), read_only=True, config={'threads': 1}) as after:
        for table in ('PROCESS_LAUNCHES', 'SHELL_INPUTS', 'INGESTED'):
            old = before.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()
            new = after.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()
            if old != new:
                raise AssertionError(f'{table}: optimized rows differ from the baseline')
            counts[table] = len(new)
    return counts


def main():
    """Prepare samples, alternate baseline/optimized runs, and report measured speedups."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--baseline-ref', default='main')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scenario', action='append')
    parser.add_argument('--sample-mib', type=int, default=4096)
    parser.add_argument('--repeat', type=int, default=3)
    options = parser.parse_args()
    if options.sample_mib <= 0 or options.repeat <= 0:
        parser.error('sample-mib and repeat must be positive')
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    baseline, revision = snapshot_scripts(options.baseline_ref, output / 'baseline')
    report = {'baseline_revision': revision, 'workers': 1, 'scenarios': {}}
    for scenario in options.scenario or ['Sandworm-1', 'Oilrig']:
        root, manifest = prepare_sample(options.source.resolve(), output, scenario,
                                        options.sample_mib * 1024 * 1024)
        runs = []
        for index in range(options.repeat):
            measurements = {}
            order = ('baseline', 'optimized') if index % 2 == 0 else ('optimized', 'baseline')
            databases = {mode: output / f'{scenario}-{mode}-{index}.db' for mode in order}
            for mode in order:
                scripts = baseline if mode == 'baseline' else REPO / 'scripts'
                measurements[mode] = ingest(scripts, root, databases[mode])
                print(f'{scenario} {index + 1} {mode}: {measurements[mode]}',
                      file=sys.stderr, flush=True)
            counts = compare_rows(databases['baseline'], databases['optimized'])
            runs.append(measurements)
        medians = {mode: statistics.median(run[mode]['wall_seconds'] for run in runs)
                   for mode in ('baseline', 'optimized')}
        report['scenarios'][scenario] = {
            'exports': manifest, 'runs': runs, 'rows': counts,
            'median_wall_seconds': medians,
            'wall_speedup': medians['baseline'] / medians['optimized'],
        }
    result = json.dumps(report, indent=2)
    (output / 'results.json').write_text(result + '\n')
    print(result)


if __name__ == '__main__':
    main()
