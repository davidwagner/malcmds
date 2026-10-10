"""Benchmark full AutoLabel scenarios through the production ingestion CLI.

Example, from the repository root with ingestion dependencies and psutil:
  tmp/venv/bin/python reports/autolabel-parallel-92/benchmark.py \
    datasets/autolabel tmp/autolabel-parallel-benchmark

The output directory must not exist. Each trial uses a fresh database. The
--cold option requests POSIX advisory input-cache eviction before every trial;
this does not guarantee cold storage or eliminate filesystem/controller caches.
"""

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

import duckdb
import orjson
import psutil
import pyarrow

REPO = Path(__file__).resolve().parents[2]
SCENARIOS = ('CVE-2018-17246', 'python-demo', 'CVE-2024-36401')


def _trial(sample, database, workers):
    sys.path.insert(0, str(REPO / 'datasets'))
    from _ingest import run
    from _ingest_autolabel import records
    sys.argv = ['ingest', '--db', database, '--workers', workers]
    run(Path(sample), records)


def _prepare_cache(archive, cold):
    with archive.open('rb') as stream:
        if cold:
            os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
        else:
            while stream.read(8 * 1024 * 1024):
                pass


def _observe(process, scratch):
    rss = reads = 0
    try:
        processes = [process, *process.children(recursive=True)]
    except psutil.NoSuchProcess:
        processes = []
    for child in processes:
        try:
            rss += child.memory_info().rss
            reads += child.io_counters().read_bytes
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    arrow = 0
    for path in scratch.rglob('*.arrow'):
        try:
            arrow += path.stat().st_size
        except FileNotFoundError:
            pass
    return rss, reads, arrow


def _measure(sample, database, workers, scratch, logfile):
    command = [sys.executable, str(Path(__file__).resolve()), '--trial',
               str(sample), str(database), str(workers)]
    started = time.perf_counter()
    rss = reads = arrow = 0
    with logfile.open('w') as log, \
            subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT) as child:
        process = psutil.Process(child.pid)
        while child.poll() is None:
            current_rss, current_reads, current_arrow = _observe(process, scratch)
            rss = max(rss, current_rss)
            reads = max(reads, current_reads)
            arrow = max(arrow, current_arrow)
            time.sleep(0.02)
        code = child.wait()
    elapsed = time.perf_counter() - started
    if code:
        raise RuntimeError(f'Ingestion exited {code}; see {logfile}')
    return {'seconds': elapsed, 'peak_parent_and_children_rss_bytes': rss,
            'peak_temporary_arrow_bytes': arrow,
            'observed_process_tree_read_bytes_high_water': reads}


def _digest(database, order):
    digest = hashlib.sha256()
    count = 0
    with duckdb.connect(str(database), read_only=True) as con:
        assert con.execute('SELECT dataset, ingested FROM INGESTED').fetchall() == [('autolabel', True)]
        rows = con.execute(f'SELECT * FROM COMMANDS ORDER BY {order}')
        while batch := rows.fetchmany(10000):
            for row in batch:
                digest.update(orjson.dumps(row))
                digest.update(b'\n')
            count += len(batch)
    return {'rows': count, 'sha256': digest.hexdigest()}


def main():
    """Compare serial and parallel ingestion, all stored fields, and row order."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archives', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--scenarios', nargs='+', default=list(SCENARIOS))
    parser.add_argument('--trials', type=int, default=3)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--cold', action='store_true')
    args = parser.parse_args()
    if args.trials < 1 or args.workers < 2:
        parser.error('--trials must be positive and --workers at least two')
    archives = args.archives.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {
        'python': platform.python_version(), 'duckdb': duckdb.__version__,
        'orjson': orjson.__version__, 'pyarrow': pyarrow.__version__,
        'logical_cpus': os.cpu_count(), 'platform': platform.platform(),
        'physical_memory_bytes': psutil.virtual_memory().total,
        'source_sha256': {
            str(path.relative_to(REPO)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (REPO / 'datasets' / '_ingest_autolabel.py', REPO / 'datasets' / '_ingest.py')
        },
        'git_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(),
        'timing': 'Full production ingestion run and CLI parsing; includes process startup, imports, database creation, parsing, insertion, and close. Excludes cache preparation and row comparison.',
        'cache': 'Advisory POSIX_FADV_DONTNEED before each trial; not guaranteed cold.' if args.cold else 'Every archive read sequentially before each trial to warm the input cache.',
        'resources': '20 ms polling; RSS is summed over parent and live descendants (shared pages counted per process). Arrow size sums *.arrow files. Peaks may be missed between samples. Read bytes is the high-water sum of live process I/O counters; short-lived child I/O may be missed and this does not count cache hits.',
        'comparison': 'SHA-256 of every column in every row, encoded as JSON with newline separators; sorted by record_id and separately by DuckDB rowid (insertion order).',
        'results': [],
    }
    for scenario in args.scenarios:
        archive = archives / f'{scenario}.tar'
        if not archive.is_file():
            raise FileNotFoundError(archive)
        scratch = output / scenario
        sample = scratch / 'datasets' / 'autolabel'
        sample.mkdir(parents=True)
        (sample / archive.name).symlink_to(archive)
        result = {'scenario': scenario, 'archive_bytes': archive.stat().st_size,
                  'trials': {'1': [], str(args.workers): []}}
        expected = None
        for trial in range(args.trials):
            # Alternate order to reduce systematic bias from background load.
            variants = [1, args.workers] if trial % 2 == 0 else [args.workers, 1]
            for workers in variants:
                database = scratch / f'workers-{workers}-trial-{trial}.duckdb'
                logfile = scratch / f'workers-{workers}-trial-{trial}.log'
                _prepare_cache(archive, args.cold)
                measurement = _measure(sample, database, workers, scratch, logfile)
                comparison = {'all_columns_sorted': _digest(database, 'record_id'),
                              'all_columns_in_insertion_order': _digest(database, 'rowid')}
                if expected is None:
                    expected = comparison
                if comparison != expected:
                    raise AssertionError(f'Output mismatch: {scenario}, workers={workers}, trial={trial}')
                result['trials'][str(workers)].append(measurement)
                print(json.dumps({'scenario': scenario, 'workers': workers, 'trial': trial, **measurement}), flush=True)
        result['comparison'] = expected
        result['all_columns_and_insertion_order_equal'] = True
        result['median_seconds'] = {
            workers: statistics.median(item['seconds'] for item in trials)
            for workers, trials in result['trials'].items()
        }
        result['speedup'] = result['median_seconds']['1'] / result['median_seconds'][str(args.workers)]
        report['results'].append(result)
        (output / 'measurements.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'scenario': scenario, 'speedup': result['speedup']}), flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--trial':
        _trial(*sys.argv[2:])
    else:
        main()
