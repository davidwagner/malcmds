"""Run the serial benchmark against actual gzip inputs and DuckDB outputs."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_ingest_optc_parallel import event, write_stream
from test_optc_labels import install_labels

BENCHMARK = Path(__file__).with_name('benchmark_optc.py')


def test_serial_benchmark_compares_complete_outputs(tmp_path):
    """Both run orders must compare rows and report actual input counts."""
    root = tmp_path / 'optc'
    install_labels(root, [])
    for partition in ('benign', 'evaluation', 'short'):
        write_stream(root / 'ecar' / partition / 'a.json.gz', [json.dumps(event('one', 'whoami'))])
    driver = (f'import sys; sys.path.insert(0, {str(BENCHMARK.parent)!r}); '
              'from benchmark_optc import main; main()')
    result = subprocess.run(
        [sys.executable, '-c', driver, '--baseline', 'HEAD', '--root', str(root),
         '--lines', '2', '--repeats', '2'], capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    directory = Path(result.stdout.splitlines()[0].removeprefix('Artifacts: '))
    report = json.loads((directory / 'results.json').read_text())
    assert report['workers'] == 1
    assert [entry['partition'] for entry in report['samples']] == ['benign', 'evaluation', 'short']
    for entry in report['samples']:
        assert entry['rows'] == entry['lines'] == 1
        assert entry['speedup'] > 0
        assert len(entry['output_sha256']) == 64
        assert all(len(runs) == 2 for runs in entry['seconds'].values())


@pytest.mark.parametrize('arguments, message', [
    (['--lines', '0'], 'must be positive'),
    (['--repeats', '0'], 'must be positive'),
    ([], 'must contain published labels'),
])
def test_benchmark_rejects_invalid_inputs(tmp_path, arguments, message):
    """Invalid benchmarks must fail before creating misleading timing results."""
    result = subprocess.run(
        [sys.executable, str(BENCHMARK), '--baseline', 'HEAD', '--root', str(tmp_path), *arguments],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    assert message in result.stderr


def test_benchmark_reports_missing_partition(tmp_path):
    """A missing source partition cannot be mistaken for a fast empty ingestion."""
    install_labels(tmp_path, [])
    result = subprocess.run(
        [sys.executable, str(BENCHMARK), '--baseline', 'HEAD', '--root', str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert 'No benign eCAR files' in result.stderr
