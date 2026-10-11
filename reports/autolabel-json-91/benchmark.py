"""Compare complete AutoLabel ingests using fresh databases and two readers.

Usage (with ingestion dependencies installed):
  git show f3a4160:datasets/_ingest_autolabel.py > tmp/original_reader.py
  python reports/autolabel-json-91/benchmark.py tmp/original_reader.py \
      tmp/json-benchmark tmp/sample-one/autolabel tmp/sample-two/autolabel

Each sample directory must contain complete original scenario archives, or
copies containing complete nested runs with the original archive/member names.
The output directory must not exist. Trials run sequentially on warm input.
"""

import argparse
import hashlib
import importlib.util
import json
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

import duckdb
import orjson

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts'))


def _trial(reader, sample, database):
    if database.exists():
        raise FileExistsError(database)
    spec = importlib.util.spec_from_file_location('benchmark_reader', reader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from _ingest import run
    sys.argv = ['ingest', '--db', str(database)]
    started = time.perf_counter()
    run(sample, module.records)
    elapsed = time.perf_counter() - started
    print(json.dumps({'seconds': elapsed}))


def _rows(database):
    with duckdb.connect(str(database), read_only=True) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(True,)]
        return con.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall()


def main():
    """Measure three trials per reader and compare every stored command field."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('samples', type=Path, nargs='+')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for index, sample in enumerate(args.samples):
        # Read the input before timing. These measurements do not model cold I/O.
        for archive in sorted(sample.iterdir()):
            if archive.is_file():
                with archive.open('rb') as stream:
                    while stream.read(1024 * 1024):
                        pass
        expected = None
        timings = {'baseline': [], 'updated': []}
        for trial in range(3):
            for variant, reader in [
                ('baseline', args.baseline),
                ('updated', REPO / 'scripts/_ingest_autolabel.py'),
            ]:
                database = args.output / f'{index}-{variant}-{trial}.duckdb'
                command = [sys.executable, str(Path(__file__).resolve()), '--trial',
                           str(reader.resolve()), str(sample.resolve()), str(database.resolve())]
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                (args.output / f'{index}-{variant}-{trial}.log').write_text(result.stdout + result.stderr)
                timings[variant].append(json.loads(result.stdout.splitlines()[-1])['seconds'])
                rows = _rows(database)
                if expected is None:
                    expected = rows
                assert rows == expected, f'Command fields changed: {sample}, {variant}, trial {trial}'
        medians = {variant: statistics.median(values) for variant, values in timings.items()}
        results.append({
            'sample': sample.parent.name, 'rows': len(expected),
            'all_columns_equal': True,
            'sha256': hashlib.sha256(repr(expected).encode()).hexdigest(),
            'seconds': timings, 'median_seconds': medians,
            'speedup': medians['baseline'] / medians['updated'],
        })
        print(json.dumps(results[-1]), flush=True)
    report = {
        'python': platform.python_version(), 'duckdb': duckdb.__version__,
        'orjson': orjson.__version__,
        'timing': 'Warm input; database setup, parsing, insertion and close; excludes imports and comparison.',
        'results': results,
    }
    (args.output / 'measurements.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--trial':
        _trial(*map(Path, sys.argv[2:]))
    else:
        main()
