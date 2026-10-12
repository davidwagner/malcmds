"""Exercise six-worker ingestion through real subprocesses and DuckDB writes."""

import copy
import json
import zipfile
from pathlib import Path

import duckdb
import pytest
from test_ingest_batches import invoke
from test_ingest_optc_parallel import event, write_stream


def comiset_dataset(root):
    """Put late annotations and preferred launches across JSON worker batches."""
    root.mkdir()
    fixture = Path(__file__).parent / 'fixtures/comiset/LAB.json'
    original = json.loads(fixture.read_text())['onedrive.exe']['record']
    fallback = copy.deepcopy(original)
    fallback['_id'] = 'fallback'
    fallback['_source']['process_guid'] = 'shared'
    fallback['_source']['event_id'] = '11'
    creation = copy.deepcopy(fallback)
    creation['_id'] = 'creation'
    creation['_source']['event_id'] = '1'
    annotation = copy.deepcopy(fallback)
    annotation['_id'] = 'annotation'
    annotation['_source']['rule_technique_id'] = 'T1055'
    annotation['_source'].pop('CommandLine', None)
    # One archive has enough chunks to refill a six-worker queue. This also
    # checks that a tagged non-launch record survives worker serialization.
    rows = [fallback] * 6100 + [creation, annotation]
    anonymous = copy.deepcopy(creation)
    anonymous['_source'].pop('process_guid')
    anonymous['_id'] = 'anonymous'
    rows.append(anonymous)
    ignored = copy.deepcopy(anonymous)
    ignored['_source']['event_id'] = '11'
    rows.append(ignored)
    rows.append({})
    with zipfile.ZipFile(root / 'a.zip', 'w') as archive:
        archive.writestr('notes.txt', 'not JSON')
        archive.writestr('events.json', ''.join(json.dumps(row) + '\n' for row in rows))
        archive.writestr('later.json', json.dumps(annotation) + '\n')
    with zipfile.ZipFile(root / 'b.zip', 'w') as archive:
        archive.writestr('events.json', json.dumps(original) + '\n')


def optc_dataset(root):
    """Spread observations of one process across seven files in one partition."""
    for index in range(7):
        row = event(f'event-{index}', f'cmd /c command-{index}')
        row['objectID'] = 'shared-process'
        row['action'] = 'OPEN' if index < 6 else 'CREATE'
        write_stream(root / 'ecar' / 'benign' / 'host' / f'{index}.json.gz',
                     [json.dumps(row)])


def stored(database):
    """Read all persisted observations in deterministic order."""
    with duckdb.connect(str(database), read_only=True) as connection:
        return {
            table: connection.execute(f'SELECT * FROM {table} ORDER BY ALL').fetchall()
            for table in ('PROCESS_LAUNCHES', 'SHELL_INPUTS', 'INGESTED')
        }


@pytest.mark.parametrize('dataset', ['comiset', 'optc'])
@pytest.mark.parametrize('workers', [None, '2'])
def test_default_six_workers_preserve_global_selection(tmp_path, dataset, workers):
    """Default ingestion must use six workers without changing persisted rows."""
    root = tmp_path / dataset
    (comiset_dataset if dataset == 'comiset' else optc_dataset)(root)
    source = f'from _ingest_{dataset} import records\n'
    serial = tmp_path / 'serial.duckdb'
    parallel = tmp_path / 'parallel.duckdb'
    result = invoke(root, serial, source, '--workers', '1', '--batch-size', '2')
    assert result.returncode == 0, result.stderr
    options = () if workers is None else ('--workers', workers)
    result = invoke(root, parallel, source, '--batch-size', '2', *options)
    assert result.returncode == 0, result.stderr
    assert f'{workers or 6} parsing workers' in result.stderr
    assert stored(parallel) == stored(serial)
    rows = stored(parallel)['PROCESS_LAUNCHES']
    if dataset == 'comiset':
        assert len(rows) == 3
        assert any('creation' in row[4] and row[5] == 'malicious' for row in rows)
        assert not any('fallback' in row[4] for row in rows)
    else:
        assert len(rows) == 1
        assert rows[0][4] == 'event-6:0'
    assert not list(root.rglob('*-workers-*'))


@pytest.mark.parametrize('dataset', ['comiset', 'optc'])
@pytest.mark.parametrize('options', [('--max-records', '1'), ('--limit', '1'),
                                     ('--sample-files', '1', '--seed', '4')])
def test_parallel_limits_and_sampling(tmp_path, dataset, options):
    """Sampling and both record budgets must match the sequential CLI."""
    root = tmp_path / dataset
    (comiset_dataset if dataset == 'comiset' else optc_dataset)(root)
    outputs = []
    for workers in ('1', '6'):
        database = tmp_path / f'{workers}.duckdb'
        result = invoke(root, database, f'from _ingest_{dataset} import records\n',
                        '--workers', workers, *options)
        assert result.returncode == 0, result.stderr
        outputs.append(stored(database))
    assert outputs[0] == outputs[1]
    assert outputs[0]['PROCESS_LAUNCHES']
    assert not list(root.rglob('*-workers-*'))


@pytest.mark.parametrize('dataset', ['comiset', 'optc'])
def test_worker_failure_leaves_no_partial_selection(tmp_path, dataset):
    """A genuine parse error must reach the parent and remove private spools."""
    root = tmp_path / dataset
    (comiset_dataset if dataset == 'comiset' else optc_dataset)(root)
    if dataset == 'comiset':
        with zipfile.ZipFile(root / 'z.zip', 'w') as archive:
            archive.writestr('bad.json', '{bad json\n')
    else:
        write_stream(root / 'ecar/benign/host/z.json.gz', ['{"object":"PROCESS", bad'])
    database = tmp_path / 'failed.duckdb'
    result = invoke(root, database, f'from _ingest_{dataset} import records\n')
    assert result.returncode != 0
    assert 'JSONDecodeError' in result.stderr
    assert stored(database)['PROCESS_LAUNCHES'] == []
    assert not list(root.rglob('*-workers-*'))


@pytest.mark.parametrize('workers', ['1', '6'])
def test_empty_comiset(tmp_path, workers):
    """Empty selections must not create a pool or leave temporary files."""
    root = tmp_path / 'comiset'
    root.mkdir()
    result = invoke(root, tmp_path / 'empty.duckdb', 'from _ingest_comiset import records\n',
                    '--workers', workers)
    assert result.returncode == 0, result.stderr
    assert not list(root.rglob('*-workers-*'))


def test_comiset_exact_record_budget_skips_later_corrupt_archive(tmp_path):
    """A global raw-record budget must stop at the end of the first archive."""
    root = tmp_path / 'comiset'
    root.mkdir()
    with zipfile.ZipFile(root / 'a.zip', 'w') as archive:
        archive.writestr('empty.json', '{}\n')
    (root / 'z.zip').write_bytes(b'not a zip')
    result = invoke(root, tmp_path / 'bounded.duckdb', 'from _ingest_comiset import records\n',
                    '--max-records', '1')
    assert result.returncode == 0, result.stderr


def test_parent_input_failure_stops_workers(tmp_path):
    """Failure while feeding ZIP batches must join workers and remove spools."""
    root = tmp_path / 'comiset'
    comiset_dataset(root)
    (root / 'z.zip').write_bytes(b'not a zip')
    result = invoke(root, tmp_path / 'failed.duckdb', 'from _ingest_comiset import records\n')
    assert result.returncode != 0
    assert 'BadZipFile' in result.stderr
    assert not list(root.rglob('*-workers-*'))


def test_early_consumer_close_joins_workers(tmp_path):
    """Closing the real parser after its first observation must stop prefetch."""
    root = tmp_path / 'comiset'
    comiset_dataset(root)
    source = '''
from contextlib import closing
from multiprocessing import active_children
from _ingest_comiset import _lines, _batches, _observations
from _ingest_parallel import ordered_records

def records(root, options):
    with closing(_lines(sorted(root.glob('*.zip')), None)) as lines:
        with closing(ordered_records(_observations, _batches(lines), 6, root / 'tmp', 'comiset')) as parsed:
            first = next(parsed)
            assert first[2], 'Worker serialization lost the parsed Command'
            yield first[2][0]
    assert not active_children(), 'Closing the parser left worker processes alive'
'''
    result = invoke(root, tmp_path / 'closed.duckdb', source)
    assert result.returncode == 0, result.stderr
    assert not list(root.rglob('*-workers-*'))


def test_optc_limited_reader_can_be_exhausted(tmp_path):
    """A consumer that exhausts a bounded reader must receive its selected prefix."""
    root = tmp_path / 'optc'
    optc_dataset(root)
    source = '''
from _ingest_optc import records as read_records

def records(root, options):
    commands = list(read_records(root, options))
    assert len(commands) == 1
    yield from commands
'''
    database = tmp_path / 'bounded.duckdb'
    result = invoke(root, database, source, '--limit', '1')
    assert result.returncode == 0, result.stderr
    assert stored(database)['PROCESS_LAUNCHES'][0][4] == 'event-0:0'


def test_missing_optc_input_reports_fetch_error(tmp_path):
    """An empty input must fail clearly before starting workers."""
    root = tmp_path / 'optc'
    root.mkdir()
    result = invoke(root, tmp_path / 'empty.duckdb', 'from _ingest_optc import records\n')
    assert result.returncode != 0
    assert 'No completed OpTC eCAR gzip files' in result.stderr
    assert not list(root.rglob('*-workers-*'))
