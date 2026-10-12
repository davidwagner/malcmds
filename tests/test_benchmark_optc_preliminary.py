"""Run the preliminary-scan benchmark CLI on small, real gzip datasets."""

import gzip
import hashlib
import json
import statistics
import subprocess
import sys
from pathlib import Path

import pytest
from test_ingest_optc_parallel import write_stream
from test_optc_labels import install_labels, synthetic_event


REPO = Path(__file__).resolve().parents[1]
BENCHMARK = REPO / 'tests' / 'benchmark_optc_preliminary.py'


def run_benchmark(root, *arguments):
    """Execute the benchmark in a separate interpreter, including spawned pools."""
    return subprocess.run(
        [sys.executable, str(BENCHMARK), '--baseline', 'HEAD', '--root', str(root), *arguments],
        cwd=REPO, capture_output=True, text=True, check=False, timeout=90)


def test_benchmark_reports_verified_prefixes_and_alternates_modes(tmp_path):
    """Report authentic prefixes, independent evidence hashes, and both run orders."""
    root = tmp_path / 'optc'
    start = '2019-09-23T11:23:55.100-04:00'
    reboot = '2019-09-23T11:24:00-04:00'
    install_labels(root, [], intervals=[('sysclient0201', '5452', start, 'Infinity')])
    lines = [json.dumps(synthetic_event('first', start, 'first-process')),
             json.dumps(dict(object='HOST', action='REBOOT', hostname='SYSCLIENT0201', timestamp=reboot)),
             json.dumps(synthetic_event('excluded', '2019-09-23T11:25:00-04:00', 'later-process'))]
    sources = {}
    for partition in ('evaluation', 'short'):
        for number in range(6):
            path = root / 'ecar' / partition / f'{number}.json.gz'
            write_stream(path, lines)
            sources[str(path.relative_to(root))] = path.read_bytes()
    result = run_benchmark(root, '--lines', '2', '--files', '6', '--repeats', '2', '--seed', '31')
    assert result.returncode == 0, result.stderr
    output_lines = result.stdout.splitlines()
    assert output_lines[0].startswith('Artifacts: ')
    artifacts = Path(output_lines[0].removeprefix('Artifacts: '))
    assert artifacts.is_relative_to(REPO / 'tmp'), 'Benchmark artifacts must stay under repository tmp/'
    report = json.loads((artifacts / 'results.json').read_text())
    assert report['baseline'] == subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    assert report['seed'] == 31
    assert report['line_limit_per_file'] == 2
    assert report['python'] and report['platform']
    assert (artifacts / 'baseline_labels.py').is_file()
    modes = [line.split(':', 1)[0] for line in output_lines
             if line.startswith(('baseline:', 'serial:', 'six_workers:'))]
    assert modes == ['baseline', 'serial', 'six_workers', 'six_workers', 'serial', 'baseline'] * 2
    expected_evidence = {
        'intervals': [[['sysclient0201', '5452'], [
            ['2019-09-23 11:23:55.100000-04:00', None, '2019-09-23 11:24:00-04:00']]]],
        'reboots': [['sysclient0201', ['2019-09-23 11:24:00-04:00']]],
    }
    expected_digest = hashlib.sha256(json.dumps(expected_evidence, sort_keys=True).encode()).hexdigest()
    expected_prefix = ''.join(line + '\n' for line in lines[:2]).encode()
    assert set(report['groups']) == {'primary', 'held_out'}
    for name, partition in (('primary', 'evaluation'), ('held_out', 'short')):
        group = report['groups'][name]
        assert group['evidence_sha256'] == expected_digest, 'Benchmark hash omitted or changed bounded lifetime evidence'
        assert len(group['samples']) == 6
        assert {sample['source'] for sample in group['samples']} == {
            f'ecar/{partition}/{number}.json.gz' for number in range(6)}
        for sample in group['samples']:
            copied = artifacts / name / sample['source']
            assert sample['lines'] == 2
            assert sample['uncompressed_bytes'] == len(expected_prefix)
            assert sample['compressed_bytes'] == copied.stat().st_size
            assert gzip.decompress(copied.read_bytes()) == expected_prefix
        for mode in ('baseline', 'serial', 'six_workers'):
            durations = group['seconds'][mode]
            assert len(durations) == 2 and all(duration > 0 for duration in durations)
            assert group['median_seconds'][mode] == statistics.median(durations)
        median = group['median_seconds']
        assert group['serial_speedup'] == median['baseline'] / median['serial']
        assert group['parallel_speedup'] == median['serial'] / median['six_workers']
        assert group['total_speedup'] == median['baseline'] / median['six_workers']
    assert all((root / source).read_bytes() == contents for source, contents in sources.items()), (
        'Sampling must leave original gzip archives unchanged')


@pytest.mark.parametrize('option', ['--lines', '--files', '--repeats'])
def test_benchmark_rejects_nonpositive_counts(tmp_path, option):
    """Invalid counts fail before sample creation or expensive scans."""
    result = run_benchmark(tmp_path, option, '0')
    assert result.returncode == 2
    assert '--lines, --files, and --repeats must be positive' in result.stderr
    assert 'Artifacts:' not in result.stdout


@pytest.mark.parametrize('missing', ['labels', 'primary', 'held_out'])
def test_benchmark_requires_labels_and_both_partitions(tmp_path, missing):
    """Incomplete inputs cannot produce a misleading successful benchmark."""
    root = tmp_path / 'optc'
    root.mkdir()
    if missing != 'labels':
        install_labels(root, [])
    if missing == 'held_out':
        write_stream(root / 'ecar' / 'benign' / 'one.json.gz', ['{}'])
    result = run_benchmark(root)
    assert result.returncode == 2
    expected = '--root must contain published labels' if missing == 'labels' else f'No {missing} gzip files'
    assert expected in result.stderr
    assert 'Artifacts:' not in result.stdout
