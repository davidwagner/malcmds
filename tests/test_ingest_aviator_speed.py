"""Exercise accelerated AVIATOR reads through real ZIPs and persisted DuckDB rows."""

import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import zipfile

import pytest
from test_ingest_aviator_parallel import (
    ARCHIVE,
    SCRIPTS,
    archive_root,
    event,
    ingest,
    rows,
)


@pytest.mark.parametrize('encoding', ['utf-8', 'cp1252', 'utf-16'])
def test_sparse_events_keep_ordinals_entities_and_large_commands(tmp_path, encoding):
    """Filtering must retain source positions, XML decoding and split delimiters."""
    ordinary = event(0) * 9000
    commands = [
        event(11, 'tool.exe café &amp; tea'),
        event(12, 'tool.exe escaped').replace('CommandLine', '&#67;ommandLine'),
        event(13, 'tool.exe ' + 'x' * (2 * 1024 * 1024)),
        event(14, 'tool.exe bad & unescaped'),
        event(15, 'tool.exe nul\x00value'),
        event(16, 'tool.exe unicode-space').replace('<Event>', '<Event\u00a0>'),
    ]
    content = ordinary + ''.join(commands) + ordinary
    root = archive_root(tmp_path, [('ex_sample.zip', [
        ('sysmon_normal_operation.xml', content.encode(encoding)),
    ])])
    fast, reference = tmp_path / 'fast.db', tmp_path / 'reference.db'
    ingest(root, fast, 1)
    # A raw-record bound intentionally retains the established serial parser.
    ingest(root, reference, 1, '--max-records', '1000000')
    assert rows(fast) == rows(reference), (
        'AVIATOR byte filtering changed command text, labels, sessions, or source ordinals'
    )
    assert len(rows(fast)) == 6
    assert rows(fast)[0][2] == ['café', '&', 'tea']


def test_limit_stops_before_unread_truncated_event(tmp_path):
    """A limit may finish before a later broken frame; complete ingestion must fail."""
    root = archive_root(tmp_path, [('ex_sample.zip', [
        ('sysmon.xml', event(1, 'tool.exe good') + event(2) * 20000 + '<Event>broken'),
    ])])
    limited = tmp_path / 'limited.db'
    ingest(root, limited, 1, '--limit', '1')
    assert rows(limited)[0][2] == ['good']
    result = ingest(root, tmp_path / 'broken.db', 1, check=False)
    assert result.returncode != 0
    assert 'Truncated XML Event' in result.stderr


@pytest.mark.parametrize('payload', [
    event(1, 'tool.exe good').encode() + event(2).replace('host', '\x81').encode('latin1'),
    b'<?xml version="1.0" encoding="utf-8"?>' + event(1).encode() + b'\xff',
])
def test_skipped_records_still_validate_encoding(tmp_path, payload):
    """Ignoring command-free XML must not hide errors in the declared text codec."""
    root = archive_root(tmp_path, [('ex_sample.zip', [('sysmon.xml', payload)])])
    result = ingest(root, tmp_path / 'invalid.db', 1, check=False)
    assert result.returncode != 0
    assert 'UnicodeDecodeError' in result.stderr


def test_limit_keeps_earlier_command_before_later_invalid_utf8(tmp_path):
    """Output limits must retain the reference reader's decoding read-ahead."""
    payload = (b'<?xml version="1.0" encoding="utf-8"?>'
               + event(1, 'tool.exe first').encode()
               + event(2).encode() * 1000 + b'\xff')
    root = archive_root(tmp_path, [('ex_sample.zip', [('sysmon.xml', payload)])])
    database = tmp_path / 'limited.db'
    ingest(root, database, 1, '--limit', '1')
    assert rows(database)[0][2] == ['first']


def test_dense_blocks_and_false_unicode_starts_keep_positions(tmp_path):
    """Filling the native output array must resume at the right byte and ordinal."""
    content = '<Event>Command</Event>' * 6000
    content += ('<Eventé>ignored</Event>' + event(1, 'tool.exe dense')) * 5000
    root = archive_root(tmp_path, [('ex_sample.zip', [('sysmon.xml', content)])])
    fast, reference = tmp_path / 'fast.db', tmp_path / 'reference.db'
    ingest(root, fast, 1, '--batch-size', '100000')
    ingest(root, reference, 1, '--batch-size', '100000', '--max-records', '1000000')
    assert rows(fast) == rows(reference)
    assert len(rows(fast)) == 5000


@pytest.mark.parametrize('compression', [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
                                         zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
@pytest.mark.parametrize('damaged', [False, True])
def test_zip64_decoders_and_crc_are_preserved(tmp_path, compression, damaged):
    """ZipExtFile/ISA-L changes must preserve codecs, rewinds, ZIP64 and CRC errors.

    The _expected_crc=None branch is unreachable through ZipFile.open(): it
    always supplies a central-directory CRC. No fabricated reader bypasses it.
    """
    root = tmp_path / 'aviator'
    root.mkdir()
    data = io.BytesIO()
    content = event(1, 'tool.exe café').encode() + event(2).encode() * 20000
    with (zipfile.ZipFile(data, 'w', compression=compression) as zipped,
          zipped.open('sysmon.xml', 'w', force_zip64=True) as output):
        output.write(content)
    payload = bytearray(data.getvalue())
    if damaged:
        offset = payload.index(b'PK\x01\x02') + 16
        crc = struct.unpack_from('<I', payload, offset)[0]
        struct.pack_into('<I', payload, offset, crc ^ 1)
    with tarfile.open(root / ARCHIVE, 'w') as archive:
        member = tarfile.TarInfo('ex_sample.zip')
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    database = tmp_path / 'commands.db'
    result = ingest(root, database, 1, check=False)
    if damaged:
        assert result.returncode != 0 and 'Bad CRC-32' in result.stderr, (
            'ZIP decoder changes must not silently accept a corrupt central-directory CRC'
        )
    else:
        assert result.returncode == 0, result.stderr
        assert rows(database)[0][2] == ['café'], (
            'Buffered seeks must retain the decoder state or start a fresh decoder at byte zero'
        )


@pytest.mark.parametrize("compiler", [False, True])
def test_compiler_free_fallback_and_non_xml_prefix(tmp_path, compiler):
    """Hosts without cc can still ingest, including the reference format fallback."""
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    for path in SCRIPTS.iterdir():
        if path.is_file():
            (scripts / path.name).symlink_to(path)
    root = archive_root(tmp_path, [('ex_sample.zip', [
        ('sysmon.xml', event(1, 'tool.exe fallback')),
        ('other.xml', 'irrelevant text'),
    ])])
    database = tmp_path / 'commands.db'
    driver = (f'import sys; sys.path.insert(0, {str(scripts)!r}); '
              'from pathlib import Path; from _ingest import run; '
              'from _ingest_aviator import records; '
              f'run(Path({str(root)!r}), records)')
    result = subprocess.run([sys.executable, '-c', driver, '--db', str(database),
                             '--workers', '1'], env={**os.environ, 'PATH': os.environ['PATH'] if compiler else ''},
                            check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert rows(database)[0][2] == ['fallback']


@pytest.mark.parametrize('late_bytes', [b'', b'\xe4', b'\xc3'])
def test_late_encoding_decision_preserves_earlier_ambiguous_commands(tmp_path, late_bytes):
    """A late CP1252 byte must reinterpret UTF-8-looking bytes throughout the file."""
    raw = (event(1, 'tool.exe café').encode()
           + event(2, 'tool.exe following').encode()
           + event(3).encode() * 20000 + late_bytes)
    root = archive_root(tmp_path, [('ex_sample.zip', [('sysmon.xml', raw)])])
    fast, reference = tmp_path / 'fast.db', tmp_path / 'reference.db'
    ingest(root, fast, 1)
    ingest(root, reference, 1, '--max-records', '1000000')
    assert rows(fast) == rows(reference), (
        'Codec selection must consider the whole export, including a trailing incomplete UTF-8 sequence'
    )
    assert rows(fast)[0][2] == ['cafÃ©' if late_bytes else 'café']


def test_ambiguous_candidates_spill_and_keep_order(tmp_path):
    """More than 8 MiB of deferred XML must spill without changing command order."""
    content = event(1, 'tool.exe café ' + 'x' * (9 * 1024 * 1024)) + event(2, 'tool.exe after')
    root = archive_root(tmp_path, [('ex_sample.zip', [('sysmon.xml', content)])])
    fast, reference = tmp_path / 'fast.db', tmp_path / 'reference.db'
    ingest(root, fast, 1)
    ingest(root, reference, 1, '--max-records', '1000000')
    assert rows(fast) == rows(reference)
    assert rows(fast)[1][2] == ['after']


def test_late_cp1252_rejects_undefined_byte_in_earlier_utf8(tmp_path):
    """A UTF-8 continuation byte can become undefined after CP1252 is selected."""
    raw = event(1, 'tool.exe \u0101').encode() + event(2).encode() * 20000 + b'\xff'
    root = archive_root(tmp_path, [('ex_sample.zip', [('sysmon.xml', raw)])])
    result = ingest(root, tmp_path / 'invalid.db', 1, check=False)
    assert result.returncode != 0 and 'UnicodeDecodeError' in result.stderr


def test_benchmark_cli_prepares_samples_and_checks_fresh_databases(tmp_path):
    """The reproducible benchmark must ingest both revisions and verify persisted rows."""
    root = archive_root(tmp_path, [('ex_sample.zip', [
        ('sysmon.xml', event(1, 'tool.exe benchmark') + event(2) * 20000),
    ])])
    with tarfile.open(root / 'aviator-ground-truth-and-tools.tar.gz', 'w:gz'):
        pass
    output = tmp_path / 'benchmark'
    result = subprocess.run([
        sys.executable, str(SCRIPTS.parent / 'tests' / 'benchmark_aviator_ingest.py'),
        '--source', str(root), '--scenario', 'sample', '--sample-mib', '1',
        '--repeat', '2', '--baseline-ref', 'HEAD', '--output', str(output),
    ], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    report = json.loads((output / 'results.json').read_text())
    sample = report['scenarios']['sample']
    assert report['workers'] == 1
    assert sample['rows'] == {'PROCESS_LAUNCHES': 1, 'SHELL_INPUTS': 0, 'INGESTED': 1}
    assert len(sample['runs']) == 2
    assert 0 < sample['exports'][0]['bytes'] <= 1024 * 1024
    assert all(run[mode]['wall_seconds'] > 0 for run in sample['runs']
               for mode in ('baseline', 'optimized'))


@pytest.mark.parametrize('argument', ['--sample-mib', '--repeat'])
def test_benchmark_rejects_nonpositive_sizes(tmp_path, argument):
    """Invalid benchmark sizes must fail before creating sample or database files."""
    output = tmp_path / 'benchmark'
    result = subprocess.run([
        sys.executable, str(SCRIPTS.parent / 'tests' / 'benchmark_aviator_ingest.py'),
        '--source', str(tmp_path), '--output', str(output), argument, '0',
    ], check=False, capture_output=True, text=True)
    assert result.returncode == 2
    assert 'must be positive' in result.stderr
    assert not output.exists()


@pytest.mark.parametrize('encoding', ['utf-8-sig', 'iso8859-1', 'ascii', 'utf-32'])
def test_bom_and_declared_codecs(tmp_path, encoding):
    """Preserve BOM handling, declared fallback codecs and unsupported-codec errors."""
    content = event(1, 'tool.exe declared')
    payload = content.encode('utf-8-sig') if encoding == 'utf-8-sig' else (
        f'<?xml version="1.0" encoding="{encoding}"?>' + content).encode()
    root = archive_root(tmp_path, [('ex_sample.zip', [('sysmon.xml', payload)])])
    database = tmp_path / 'commands.db'
    result = ingest(root, database, 1, check=False)
    if encoding == 'utf-32':
        assert result.returncode != 0 and 'Unsupported AVIATOR XML encoding' in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert rows(database)[0][2] == ['declared']


def test_split_openers_whitespace_and_progress(tmp_path):
    """Chunk splits and Python's ASCII whitespace rules must preserve framing."""
    first = event(1, 'tool.exe first')
    content = first + ' ' * (128 * 1024 - len(first) - 6)
    content += event(2, 'tool.exe split')
    content += '<EventX>ignored</Event><Event\x01>ignored</Event>'
    for character in ('\t', '\n', '\r', '\x1c', '\x1f', ' '):
        content += event(3, 'tool.exe whitespace').replace('<Event>', f'<Event{character}>')
    content += '<Event></Event>' * 100001 + ' trailing &amp;'
    root = archive_root(tmp_path, [('ex_sample.zip', [('sysmon.xml', content)])])
    fast, reference = tmp_path / 'fast.db', tmp_path / 'reference.db'
    result = ingest(root, fast, 1)
    ingest(root, reference, 1, '--max-records', '1000000')
    assert rows(fast) == rows(reference)
    assert 'XML events scanned' in result.stderr


def test_candidate_exactly_fills_block_and_leading_entity(tmp_path):
    """Complete and partial blocks may start with escaped text outside XML tags."""
    first = event(1, 'tool.exe first')
    dense = '<Event>Command</Event>' * 4095
    last = '<Event>Command' + ' ' * (128 * 1024 - len(dense) - 22) + '</Event>'
    content = dense + last + first
    content += ' ' * (128 * 1024 - len(first))
    content += '&amp;' + event(2, 'tool.exe next') + ' trailing &amp;'
    root = archive_root(tmp_path, [('ex_sample.zip', [('sysmon.xml', content)])])
    fast, reference = tmp_path / 'fast.db', tmp_path / 'reference.db'
    ingest(root, fast, 1)
    ingest(root, reference, 1, '--max-records', '1000000')
    assert rows(fast) == rows(reference)


@pytest.mark.parametrize('workers', [1, 2])
@pytest.mark.parametrize('encoded_name', ['&#67;ommandLine', '&#x43;ommandLine'])
def test_encoded_field_after_greater_than_in_attribute(tmp_path, workers, encoded_name):
    """A legal > in an XML attribute must not hide an encoded command field."""
    content = event(1, 'tool.exe retained').replace(
        'Name="CommandLine"', f'note=">" Name="{encoded_name}"'
    )
    root = archive_root(tmp_path, [('ex_sample.zip', [('sysmon.xml', content)])])
    fast, reference = tmp_path / 'fast.db', tmp_path / 'reference.db'
    ingest(root, fast, workers)
    ingest(root, reference, 1, '--max-records', '1000000')
    assert rows(reference)[0][2] == ['retained']
    assert rows(fast) == rows(reference), (
        'The native filter must retain encoded command names after quoted > characters'
    )
