"""Check JSON compatibility through real archives and the database CLI.

These checks protect the assumptions used to skip a second decode of ignored
Sysdig events. Dependency updates must preserve identities, ancestry and errors.
"""

import io
import json
import tarfile

import duckdb
import pytest
from test_ingest_batches import invoke

READER = 'from _ingest_autolabel import records\n'
BIG = 2**80 + 1


def _event(kind='execve', **changes):
    return {
        'evt.type': kind, 'evt.num': BIG, 'proc.vpid': BIG,
        'container.id': 'container', 'evt.rawres': 0,
        'proc.cmdline': 'id', 'proc.exepath': '/usr/bin/id',
        'malicious': True,
    } | changes


def _archive(root, lines):
    payload = b'\n'.join(lines)
    with tarfile.open(root / 'events.tar', 'w') as archive:
        member = tarfile.TarInfo('sysdig/events.log')
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))


def _encode(event):
    return json.dumps(event).encode()


@pytest.mark.parametrize('clone', ['clone', 'clone3', 'fork', 'vfork'])
@pytest.mark.parametrize('exit_kind', ['procexit', 'exit', 'exit_group'])
def test_large_ids_and_lifecycle(tmp_path, clone, exit_kind):
    """Integer rounding must never merge attempts or lose process ancestry."""
    root = tmp_path / 'autolabel'
    root.mkdir()
    events = [
        _event('read'),
        _event(),
        _event(clone, **{'evt.num': BIG + 1, 'evt.rawres': BIG + 2}),
        _event('execveat', **{'evt.num': BIG + 2, 'proc.vpid': BIG + 2}),
        _event(exit_kind, **{'evt.num': BIG + 3, 'proc.vpid': BIG + 2}),
        _event(**{'evt.num': BIG + 4, 'proc.vpid': BIG + 2}),
    ]
    _archive(root, [_encode(event) for event in events + events])
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute('SELECT record_id,session_id FROM COMMANDS ORDER BY record_id').fetchall()
        prefix = 'events.tar:container:'
        parent = f'{prefix}process:{BIG}:{BIG}'
        assert rows == [
            (f'{prefix}{BIG}', parent),
            (f'{prefix}{BIG + 2}', parent),
            (f'{prefix}{BIG + 4}', f'{prefix}process:{BIG + 2}:{BIG + 4}'),
        ], 'JSON decoding must preserve large integer identities, clone ancestry and PID reuse'


@pytest.mark.parametrize('case', [
    'escaped-key', 'duplicate-exec', 'duplicate-read', 'text', 'nan',
    'infinity', 'negative-infinity', 'huge-number', 'surrogate', 'utf16',
    'utf32', 'bom', 'signed64', 'unsigned64',
])
def test_json_encodings_match_standard_fields(tmp_path, case):
    """Compare every stored column with a normally encoded equivalent event."""
    event = _event(**{'evt.num': 1, 'proc.vpid': 1})
    line = _encode(event)
    if case == 'escaped-key':
        line = line.replace(b'evt.type', b'evt.\\u0074ype')
    elif case == 'duplicate-exec':
        line = line.replace(b'"evt.type":', b'"evt.type": "read", "evt.type":')
    elif case == 'duplicate-read':
        event['evt.type'] = 'read'
        line = _encode(event).replace(b'"evt.type":', b'"evt.type": "execve", "evt.type":')
    elif case == 'text':
        event['proc.cmdline'] = 'id \'{"evt.type":"read"}\''
        line = _encode(event)
    elif case in {'nan', 'infinity', 'negative-infinity', 'huge-number'}:
        number = {'nan': 'NaN', 'infinity': 'Infinity', 'negative-infinity': '-Infinity', 'huge-number': '1e400'}[case]
        line = line.replace(b'"evt.num": 1,', f'"evt.num": {number},'.encode())
        # The old reader stringifies event IDs using standard-library semantics.
        event['evt.num'] = str(json.loads(number))
    elif case == 'surrogate':
        line = line[:-1] + b', "unused": "\\ud800"}'
    elif case in {'utf16', 'utf32', 'bom'}:
        line = line.decode().encode({'utf16': 'utf-16', 'utf32': 'utf-32', 'bom': 'utf-8-sig'}[case])
    elif case in {'signed64', 'unsigned64'}:
        number = 2**63 + 1 if case == 'signed64' else 2**64 + 1
        event['evt.num'] = str(number)
        event['proc.vpid'] = str(number)
        line = _encode(event).replace(f'"{number}"'.encode(), str(number).encode())
    outputs = []
    for variant, payload in [('standard', _encode(event)), ('variant', line)]:
        root = tmp_path / variant / 'autolabel'
        root.mkdir(parents=True)
        _archive(root, [payload])
        database = root.parent / 'commands.duckdb'
        result = invoke(root, database, READER)
        assert result.returncode == 0, result.stderr
        with duckdb.connect(str(database)) as con:
            outputs.append(con.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall())
            assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(True,)]
    assert outputs[0] == outputs[1], f'{case}: decoder changed stored command fields'
    assert len(outputs[1]) == (0 if case == 'duplicate-read' else 1)


@pytest.mark.parametrize('bad,error', [
    (b'{broken}', 'JSONDecodeError'),
    (b'{"evt.type":"read", "unused":"\xff"}', 'UnicodeDecodeError'),
    (b'{"evt.type":"read", "unused":}', 'JSONDecodeError'),
    (b'{"evt.type":"execve"} trailing', 'JSONDecodeError'),
    (b'[]', 'AttributeError'),
    (b'{"evt.type":[]}', 'TypeError'),
])
def test_bad_json_keeps_ingestion_retryable(tmp_path, bad, error):
    """Even ignored events must be valid; a failed ingest must allow a retry."""
    root = tmp_path / 'autolabel'
    root.mkdir()
    valid = _encode(_event())
    _archive(root, [valid, bad])
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, READER, '--batch-size', '1')
    assert result.returncode != 0 and error in result.stderr, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(False,)]
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (1,)
    _archive(root, [valid])
    result = invoke(root, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(True,)]
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone() == (1,)
