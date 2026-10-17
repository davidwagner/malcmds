"""Exercise independent ingestion sessions and the optional attempt mapping tools.

The loader also rejects unknown published sources, non-string upstream IDs,
and duplicate published keys.
Those defensive branches cannot be reached from these pinned Parquet files:
changing these values first fails the required whole-file digest check. Reaching
those branches would require a test double or overriding the production pins.

The builder has additional defensive paths unavailable in its pinned CLI run:
restoring an already imported _common module (the CLI starts a fresh process),
empty SWE Bash fences, malformed Terminal-Bench JSON, disabling the SWE shape
cap (pinned at five), duplicate published keys, and missing or mismatching
replayed commands. The pinned data has none of those cases. Changing the data
first fails its digest check, so those paths would also require doubles or pin
overrides. The corrupted-cache tests exercise the actual early rejection.
"""

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
import pytest


def command_id(command):
    """Return the publisher's command digest without changing its text."""
    return 'sha256:' + hashlib.sha256(command.encode()).hexdigest()


def write_manifest(root, entries):
    """Rewrite hashes for deliberately altered copies to test pin validation."""
    from _shellrisk_sessions import (
        ADAPTER_REVISION, CONFIG, EXTRACTION_SETTINGS, PUBLISHED_FILES, PUBLISHED_REVISION, SOURCES,
    )
    mapping = root / 'sessions.jsonl'
    mapping.write_text(''.join(json.dumps(entry) + '\n' for entry in entries))
    files = []
    for name in PUBLISHED_FILES:
        path = root / name
        files.append({'path': name, 'size': path.stat().st_size,
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest = {'format_version': 1, 'published_revision': PUBLISHED_REVISION,
                'published_files': files, 'upstream_sources': SOURCES,
                'adapter_revision': ADAPTER_REVISION, 'adapter_files': CONFIG['adapter_files'],
                'extraction_settings': EXTRACTION_SETTINGS,
                'mapping_sha256': hashlib.sha256(mapping.read_bytes()).hexdigest(),
                'coverage': {source: sum(entry['source'] == source for entry in entries)
                             for source in SOURCES}}
    (root / 'sessions.manifest.json').write_text(json.dumps(manifest))


def fixture(root):
    """Extract the complete pinned release and its replayed attempt mapping."""
    root.mkdir()
    archive = Path(__file__).parent / 'fixtures/shellrisk-sessions.zip'
    with zipfile.ZipFile(archive) as source:
        source.extractall(root)
    rows = []
    for split in ['train', 'test']:
        name = f'data/{split}-00000-of-00001.parquet'
        for index, row in enumerate(pq.read_table(root / name).to_pylist()):
            rows.append(dict(row, record_id=f'{name}:{index}:command'))
    entries = [json.loads(line) for line in (root / 'sessions.jsonl').read_text().splitlines()]
    return rows, entries


def test_attempts_strings_labels_and_processes(tmp_path):
    from test_ingest_tabular import ingest, reference
    from _ingest_quasarnix import reference_commands
    root = tmp_path / 'shellrisk-bench'
    rows, entries = fixture(root)
    refs = reference_commands(reference(tmp_path))
    expected_rows = [row for row in rows if row['command'] not in refs]
    indexed = {(entry['source'], entry['upstream_id']): entry for entry in entries}
    assert len(entries) == 18643
    assert len({entry['session_id'] for entry in entries}) == 12081
    db = tmp_path / 'commands.duckdb'
    limited = ingest(root, db, '--limit', '1')
    assert limited.returncode == 0, limited.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
    result = ingest(root, db)
    assert result.returncode == 0, result.stderr
    report = next(json.loads(line) for line in result.stderr.splitlines() if line.startswith('{'))
    assert report['quasarnix_overlap_removed'] == len(rows) - len(expected_rows)
    with duckdb.connect(str(db)) as con:
        actual = {record: (text, label, session) for text, record, label, session in con.execute(
            'SELECT shell_input,record_id,dataset_label,session_id FROM SHELL_INPUTS').fetchall()}
        assert len(actual) == len(expected_rows)
        for row in expected_rows:
            text, label, session = actual[row['record_id']]
            assert text == row['command']
            assert label == ('unknown' if row['label'] == 'risky' else 'benign')
            assert session == f"shellrisk-bench:record:{row['record_id']}"
        first = indexed['swesmith', 'swesmith-000291']
        second = indexed['swesmith', 'swesmith-000305']
        assert first['session_id'] == second['session_id']
        assert (first['raw_row'], first['message_index'], second['message_index']) == (25, 46, 84)
        tasks = defaultdict(set)
        blank_trials = defaultdict(set)
        attempts = defaultdict(set)
        for entry in entries:
            attempts[entry['source'], entry['raw_file'], entry['raw_row']].add(entry['session_id'])
            if entry['source'] == 'swesmith':
                tasks[entry['task_id']].add(entry['session_id'])
            elif not entry['trial_id']:
                blank_trials[entry['task_id'], entry['agent']].add(entry['session_id'])
        assert all(len(sessions) == 1 for sessions in attempts.values())
        assert sum(len(sessions) > 1 for sessions in tasks.values()) == 2405
        assert any(len(sessions) > 1 for sessions in blank_trials.values())
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone()[0] > len(expected_rows)
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES p JOIN SHELL_INPUTS s '
                           "ON p.record_id LIKE s.record_id || ':%' "
                           'WHERE p.session_id != s.session_id OR p.dataset_label != s.dataset_label').fetchone() == (0,)
        before = con.execute('SELECT * FROM SHELL_INPUTS ORDER BY record_id').fetchall()
        con.execute('UPDATE INGESTED SET ingested=false')
    assert ingest(root, db).returncode == 0
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT * FROM SHELL_INPUTS ORDER BY record_id').fetchall() == before
    skipped = ingest(root, db)
    assert json.loads(skipped.stdout)['skipped']


@pytest.mark.parametrize('damage', ['missing', 'invalid', 'wrong_type'])
def test_shellrisk_reference_required_when_limited(tmp_path, damage):
    from _ingest_quasarnix import FILES
    from test_ingest_tabular import ingest, reference
    root = tmp_path / 'shellrisk-bench'
    fixture(root)
    path = reference(tmp_path) / FILES[0]
    if damage == 'missing':
        path.unlink()
    else:
        path.write_text('not json' if damage == 'invalid' else '[123]')
    db = tmp_path / 'commands.duckdb'
    result = ingest(root, db, '--max-records', '1', '--sample-files', '1')
    assert result.returncode != 0
    assert str(path) in result.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone() == (0,)


@pytest.mark.parametrize('damage', [
    'missing_mapping', 'missing_manifest', 'mapping_hash', 'published_hash', 'partial', 'duplicate',
    'wrong_command', 'wrong_command_hash', 'wrong_session', 'unknown_source', 'unknown_file',
    'negative_row', 'boolean_row', 'negative_position', 'missing_position', 'missing_task',
    'invalid_json', 'extra_entry', 'wrong_revision', 'wrong_adapter', 'wrong_settings',
    'wrong_upstream', 'wrong_version', 'wrong_coverage', 'missing_published_file',
    'invalid_inventory', 'reordered_inventory', 'published_digest', 'published_duplicate',
    'published_unknown_source', 'published_wrong_hash', 'published_wrong_text',
    'null_command', 'invalid_upstream_id', 'null_upstream_id', 'invalid_task',
    'row_out_of_range', 'wrong_adapter_files', 'shortened_release',
])
def test_optional_mapping_loader_rejects_invalid_mapping(tmp_path, damage):
    from test_ingest_tabular import reference
    root = tmp_path / 'shellrisk-bench'
    _, entries = fixture(root)
    reference(tmp_path)
    mapping = root / 'sessions.jsonl'
    manifest_path = root / 'sessions.manifest.json'
    manifest = json.loads(manifest_path.read_text())
    if damage == 'missing_mapping':
        mapping.unlink()
    elif damage == 'missing_manifest':
        manifest_path.unlink()
    elif damage == 'mapping_hash':
        mapping.write_text(mapping.read_text() + '\n')
    elif damage == 'published_hash':
        with (root / manifest['published_files'][1]['path']).open('ab') as stream:
            stream.write(b'damaged')
    elif damage == 'missing_published_file':
        (root / manifest['published_files'][1]['path']).unlink()
    elif damage in {'invalid_inventory', 'reordered_inventory', 'published_digest'}:
        if damage == 'invalid_inventory':
            manifest['published_files'] = None
        elif damage == 'reordered_inventory':
            manifest['published_files'].reverse()
        else:
            manifest['published_files'][1]['sha256'] = '0' * 64
        manifest_path.write_text(json.dumps(manifest))
    elif damage in {'published_duplicate', 'published_unknown_source',
                    'published_wrong_hash', 'published_wrong_text', 'shortened_release'}:
        path = root / 'data/test-00000-of-00001.parquet'
        rows = pq.read_table(path).to_pylist()
        if damage == 'shortened_release':
            rows = rows[:1]
        elif damage == 'published_duplicate':
            rows.append(dict(rows[0]))
        elif damage == 'published_unknown_source':
            rows[-1]['source'] = 'unknown'
        elif damage == 'published_wrong_hash':
            rows[0]['id'] = command_id('changed')
        else:
            rows[0]['command'] = 'changed'
        pq.write_table(pa.Table.from_pylist(rows), path)
        write_manifest(root, entries)
    elif damage.startswith('wrong_') and damage in {
            'wrong_revision', 'wrong_adapter', 'wrong_settings', 'wrong_upstream',
            'wrong_version', 'wrong_coverage', 'wrong_adapter_files'}:
        field = {'wrong_revision': 'published_revision', 'wrong_adapter': 'adapter_revision',
                 'wrong_settings': 'extraction_settings', 'wrong_upstream': 'upstream_sources',
                 'wrong_version': 'format_version', 'wrong_coverage': 'coverage',
                 'wrong_adapter_files': 'adapter_files'}[damage]
        manifest[field] = None
        manifest_path.write_text(json.dumps(manifest))
    else:
        entry = next(entry for entry in reversed(entries) if entry['source'] == 'terminalbench')
        if damage == 'partial':
            entries.pop()
        elif damage == 'duplicate':
            entries.append(dict(entry))
        elif damage == 'extra_entry':
            entries.append(dict(entry, upstream_id='terminalbench-999999'))
        elif damage == 'wrong_command':
            entry['command'] = 'echo changed'
        elif damage == 'wrong_command_hash':
            entry['command_id'] = command_id('echo changed')
        elif damage == 'wrong_session':
            entry['session_id'] = 'arbitrary-session'
        elif damage == 'unknown_source':
            entry['source'] = 'unrecognized'
        elif damage == 'unknown_file':
            entry['raw_file'] = 'data/unpinned.parquet'
        elif damage == 'row_out_of_range':
            from _shellrisk_sessions import SOURCES, session_identity
            pin = next(pin for pin in SOURCES[entry['source']]['files']
                       if pin['path'] == entry['raw_file'])
            entry['raw_row'] = pin['num_rows']
            entry['session_id'] = session_identity(entry['source'], entry['raw_file'], entry['raw_row'])
        elif damage == 'negative_row':
            entry['raw_row'] = -1
        elif damage == 'boolean_row':
            entry['raw_row'] = True
        elif damage == 'negative_position':
            entry['step_index'] = -1
        elif damage == 'missing_position':
            del entry['tool_index']
        elif damage == 'null_command':
            entry['command'] = None
        elif damage == 'invalid_upstream_id':
            entry['upstream_id'] = 'swesmith-not-numeric'
        elif damage == 'null_upstream_id':
            entry['upstream_id'] = None
        elif damage == 'invalid_task':
            entry['task_id'] = 1
        elif damage == 'missing_task':
            del entry['task_id']
        write_manifest(root, entries)
        if damage == 'invalid_json':
            mapping.write_text(mapping.read_text() + 'not json\n')
            manifest = json.loads(manifest_path.read_text())
            manifest['mapping_sha256'] = hashlib.sha256(mapping.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
    result = subprocess.run([sys.executable, '-c',
        'import sys; from pathlib import Path; from _shellrisk_sessions import load_session_map; '
        'load_session_map(Path(sys.argv[1]))', str(root)],
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'scripts')),
        capture_output=True, text=True, check=False)
    assert result.returncode != 0, result.stdout


@pytest.mark.skipif(not (os.environ.get('SHELLRISK_PUBLISHED_ROOT') and
                        os.environ.get('SHELLRISK_UPSTREAM_ROOT')),
                    reason='Full replay needs the 49 pinned upstream files (about 3 GB).')
def test_full_pinned_builder_is_reproducible(tmp_path):
    """Replay the actual release twice and retain every published agent command."""
    executable = Path(__file__).resolve().parents[1] / 'datasets/shellrisk-bench/build_sessions'
    outputs = [tmp_path / 'first', tmp_path / 'second']
    for output in outputs:
        result = subprocess.run(
            [sys.executable, str(executable), '--published-root',
             os.environ['SHELLRISK_PUBLISHED_ROOT'], '--upstream-root',
             os.environ['SHELLRISK_UPSTREAM_ROOT'], '--output-dir', str(output)],
            capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr
    for name in ['sessions.jsonl', 'sessions.manifest.json']:
        assert (outputs[0] / name).read_bytes() == (outputs[1] / name).read_bytes()
    manifest = json.loads((outputs[0] / 'sessions.manifest.json').read_text())
    assert manifest['coverage'] == {'swesmith': 12064, 'terminalbench': 6579}
    entries = [json.loads(line) for line in (outputs[0] / 'sessions.jsonl').read_text().splitlines()]
    assert len(entries) == 18643
    assert len({entry['session_id'] for entry in entries}) == 12081
    indexed = {(entry['source'], entry['upstream_id']): entry for entry in entries}
    first = indexed['swesmith', 'swesmith-000291']
    second = indexed['swesmith', 'swesmith-000305']
    assert first['session_id'] == second['session_id']
    assert (first['raw_row'], first['message_index'], second['message_index']) == (25, 46, 84)


@pytest.mark.skipif(not (os.environ.get('SHELLRISK_PUBLISHED_ROOT') and
                        os.environ.get('SHELLRISK_UPSTREAM_ROOT')),
                    reason='Cache checks need the pinned upstream files.')
@pytest.mark.parametrize('damage', ['published', 'adapter', 'raw'])
def test_builder_rejects_modified_pinned_files(tmp_path, damage):
    """Reject changed cached bytes before publishing a mapping."""
    from _shellrisk_sessions import CONFIG
    published = tmp_path / 'published'
    upstream = tmp_path / 'upstream'
    published.mkdir()
    upstream.mkdir()
    original_published = Path(os.environ['SHELLRISK_PUBLISHED_ROOT'])
    original_upstream = Path(os.environ['SHELLRISK_UPSTREAM_ROOT'])
    paths = {}
    for pin in CONFIG['published_files']:
        target = published / pin['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(original_published / pin['path'])
        paths['published'] = target
    for pin in CONFIG['adapter_files']:
        target = upstream / 'upstream' / pin['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(original_upstream / 'upstream' / pin['path'])
        paths['adapter'] = target
    for source, spec in CONFIG['upstream_sources'].items():
        for pin in spec['files']:
            original = original_upstream / source / Path(pin['path']).name
            if not original.exists():
                original = original_upstream / source / pin['path']
            target = upstream / source / pin['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(original)
            paths.setdefault('raw', target)
    target = paths[damage]
    target.unlink()
    target.write_bytes(b'changed pinned file')
    output = tmp_path / 'output'
    executable = Path(__file__).resolve().parents[1] / 'datasets/shellrisk-bench/build_sessions'
    result = subprocess.run([sys.executable, str(executable), '--published-root', str(published),
                             '--upstream-root', str(upstream), '--output-dir', str(output)],
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert 'pinned file size/hash mismatch' in result.stderr
    assert not (output / 'sessions.jsonl').exists()
    assert not (output / 'sessions.manifest.json').exists()


@pytest.mark.parametrize('mapping', ['missing', 'corrupt'])
def test_ingestion_needs_no_attempt_mapping(tmp_path, mapping):
    """Published inputs ingest independently even without usable trajectory files."""
    from test_ingest_tabular import ingest, reference
    root = tmp_path / 'shellrisk-bench'
    fixture(root)
    reference(tmp_path)
    for name in ['sessions.jsonl', 'sessions.manifest.json']:
        path = root / name
        if mapping == 'missing':
            path.unlink()
        else:
            path.write_text('invalid JSON')
    db = tmp_path / 'commands.duckdb'
    result = ingest(root, db, '--max-records', '2')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute("SELECT count(*) FROM SHELL_INPUTS WHERE session_id != dataset || ':record:' || record_id").fetchone() == (0,)
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone()[0] > 0
