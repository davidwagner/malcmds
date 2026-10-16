"""Validate recovered ShellRisk task attempts before importing published commands."""

import hashlib
import json
from collections import Counter
from pathlib import Path

import pyarrow.parquet as pq

CONFIG = json.loads(Path(__file__).with_name('shellrisk-sources.json').read_text())
SOURCES = CONFIG['upstream_sources']
PUBLISHED_REVISION = CONFIG['published_revision']
ADAPTER_REVISION = CONFIG['adapter_revision']
EXTRACTION_SETTINGS = CONFIG['extraction_settings']
PUBLISHED_FILES = ('data/train-00000-of-00001.parquet', 'data/test-00000-of-00001.parquet')
OTHER_SOURCES = {'nl2bash', 'atomicredteam', 'gtfobins', 'payloads'}


def file_digest(path: Path) -> str:
    """Return a file's SHA-256 digest using bounded memory."""
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def session_identity(source: str, raw_file: str, raw_row: int) -> str:
    """Identify one recorded attempt within an immutable upstream release."""
    spec = SOURCES[source]
    identity = json.dumps([spec['dataset'], spec['revision'], raw_file, raw_row],
                          separators=(',', ':'), ensure_ascii=False)
    return 'shellrisk-bench:attempt:' + hashlib.sha256(identity.encode('utf-8')).hexdigest()


def published_rows(root: Path):
    """Read both complete published splits in their original row order."""
    for name in PUBLISHED_FILES:
        with pq.ParquetFile(root / name) as source:
            for batch in source.iter_batches(columns=['command', 'id', 'source', 'upstream_id']):
                yield from batch.to_pylist()


def session_id_for(row: dict, mapping: dict[tuple[str, str], dict]) -> str:
    """Return the matching attempt ID, or the fallback marker for non-agent sources."""
    source = row.get('source')
    if isinstance(source, str) and source in OTHER_SOURCES:
        return ''
    if not isinstance(source, str) or source not in SOURCES:
        raise ValueError(f'Unexpected ShellRisk source {source!r}')
    upstream_id = row.get('upstream_id')
    if not isinstance(upstream_id, str):
        raise ValueError(f'{source}: invalid upstream ID {upstream_id!r}')
    key = (source, upstream_id)
    entry = mapping.get(key)
    if entry is None:
        raise ValueError(f'Missing ShellRisk session mapping for {key}')
    text = row.get('command')
    if not isinstance(text, str):
        raise ValueError(f'{key}: expected command text')
    command_id = 'sha256:' + hashlib.sha256(text.encode('utf-8')).hexdigest()
    if (text != entry['command'] or row.get('id') != command_id
            or entry['command_id'] != command_id):
        raise ValueError(f'{key}: ShellRisk command text/hash mismatch')
    return entry['session_id']


def _validate_entry(entry: dict) -> tuple[str, str]:
    source = entry.get('source')
    upstream_id = entry.get('upstream_id')
    key = (source, upstream_id)
    if not isinstance(source, str) or source not in SOURCES or not isinstance(upstream_id, str):
        raise ValueError(f'Invalid ShellRisk mapping key {key}')
    key = (source, upstream_id)
    suffix = upstream_id.removeprefix(source + '-')
    if not upstream_id.startswith(source + '-') or not suffix.isascii() or not suffix.isdecimal():
        raise ValueError(f'Invalid ShellRisk mapping key {key}')
    raw_file = entry.get('raw_file')
    files = {item['path']: item for item in SOURCES[source]['files']}
    if not isinstance(raw_file, str) or raw_file not in files:
        raise ValueError(f'{key}: invalid source file {raw_file!r}')
    positions = ['raw_row'] + (['message_index', 'bash_block_index'] if source == 'swesmith'
                              else ['step_index', 'tool_index'])
    for field in positions:
        value = entry.get(field)
        if type(value) is not int or value < 0:
            raise ValueError(f'{key}: invalid source position {field}={value!r}')
    if entry['raw_row'] >= files[raw_file]['num_rows']:
        raise ValueError(f'{key}: source row exceeds file row count')
    for field in ('task_id', 'agent', 'trial_id'):
        if field not in entry or (entry[field] is not None and not isinstance(entry[field], str)):
            raise ValueError(f'{key}: invalid metadata {field}')
    if entry.get('session_id') != session_identity(source, raw_file, entry['raw_row']):
        raise ValueError(f'{key}: session identity mismatch')
    session_id_for({'source': source, 'upstream_id': upstream_id,
                    'command': entry.get('command'), 'id': entry.get('command_id')}, {key: entry})
    return key


def load_session_map(root: Path) -> dict[tuple[str, str], dict]:
    """Validate the manifest, mapping and full published coverage before ingestion."""
    manifest_path = root / 'sessions.manifest.json'
    mapping_path = root / 'sessions.jsonl'
    if not manifest_path.is_file() or not mapping_path.is_file():
        raise FileNotFoundError(f'Missing ShellRisk sessions in {root}; run ./build_sessions '
                                '--upstream-root ../../tmp/shellrisk-upstream after ./fetch')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    expected = {'format_version': 1, 'published_revision': PUBLISHED_REVISION,
                'adapter_revision': ADAPTER_REVISION, 'adapter_files': CONFIG['adapter_files'],
                'upstream_sources': SOURCES,
                'extraction_settings': EXTRACTION_SETTINGS}
    for field, value in expected.items():
        if manifest.get(field) != value:
            raise ValueError(f'{manifest_path}: incompatible {field}')
    files = manifest.get('published_files')
    if files != CONFIG['published_files']:
        raise ValueError(f'{manifest_path}: invalid published file inventory')
    for item in files:
        path = root / item['path']
        if path.stat().st_size != item.get('size') or file_digest(path) != item.get('sha256'):
            raise ValueError(f'{path}: published file hash/size mismatch')
    if file_digest(mapping_path) != manifest.get('mapping_sha256'):
        raise ValueError(f'{mapping_path}: mapping hash mismatch')
    mapping = {}
    with mapping_path.open(encoding='utf-8') as stream:
        for line in stream:
            entry = json.loads(line)
            key = _validate_entry(entry)
            if key in mapping:
                raise ValueError(f'{mapping_path}: duplicate mapping key {key}')
            mapping[key] = entry
    coverage = Counter({source: 0 for source in SOURCES})
    seen = set()
    for row in published_rows(root):
        session_id_for(row, mapping)
        if row['source'] in SOURCES:
            key = (row['source'], row['upstream_id'])
            if key in seen:
                raise ValueError(f'Duplicate published ShellRisk key {key}')
            seen.add(key)
            coverage[row['source']] += 1
    if seen != mapping.keys():
        raise ValueError('ShellRisk mapping contains unpublished entries')
    if dict(coverage) != manifest.get('coverage'):
        raise ValueError(f'{manifest_path}: coverage mismatch')
    return mapping
