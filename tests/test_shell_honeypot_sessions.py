"""Real miniature releases exercise connection reconstruction and source decoding."""

import json

import duckdb
from test_ingest_batches import invoke
from test_ingest_quasarnix_honeypot import _archive


def event(kind, text, time, **changes):
    """Build a transformed event with complete endpoints on a nonstandard port."""
    result = {'info': kind, 'tshark': text, 'timestamp': time, 'protocol': 'telnet',
                  'src_host': '192.0.2.1', 'src_port': '40001',
                  'dst_host': '198.51.100.1', 'dst_port': 443}
    result.update(changes)
    return result


def ingest(tmp_path, files):
    """Import a real tar archive through the production writer and database."""
    root = tmp_path / 'shell-honeypot'
    root.mkdir()
    _archive(root, files)
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_shell_honeypot import records\n')
    assert result.returncode == 0, result.stderr
    return root, database


def test_telnet_normalizes_ports_crosses_midnight_and_splits_login_idle(tmp_path):
    """Only relevant activity advances the 60-minute estimated-session clock."""
    root, database = ingest(tmp_path, {
        '2024/cowrie/telnet_01.json': [
            event('command.input', 'echo first', '2024-03-01T23:50:00'),
            event('command.input', 'echo concurrent', '2024-03-01T23:51:00', src_port=40002),
        ],
        '2024/cowrie/telnet_02.json': [
            event('command.input', 'echo midnight', '2024-03-02T00:10:00Z', src_port=40001, dst_port='443'),
            event('command.input', 'echo hour', '2024-03-02T01:10:00'),
            event('command.process', 'echo debug', '2024-03-02T02:00:00'),
            event('command.input', 'echo idle', '2024-03-02T02:10:01'),
            event('userlogin', 'login attempt [root/password] succeeded', '2024-03-02T02:11:00'),
            event('userlogin', 'login attempt [root/password] succeeded', '2024-03-02T02:11:01'),
            event('command.input', 'echo login', '2024-03-02T02:12:00'),
        ],
    })
    with duckdb.connect(str(database)) as con:
        sessions = dict(con.execute('SELECT shell_input,session_id FROM SHELL_INPUTS').fetchall())
        assert len(sessions) == 6
        assert sessions['echo first'] == sessions['echo midnight'] == sessions['echo hour']
        assert len({sessions[text] for text in ['echo first', 'echo concurrent', 'echo idle', 'echo login']}) == 4
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES WHERE group_id IS NOT NULL').fetchone() == (0,)
    assert json.loads((root / 'import-summary.json').read_text())


def test_ssh_connect_close_reuse_and_long_explicit_interval(tmp_path):
    """An explicit connection lasts until close and reused native IDs stay separate."""
    rows = [
        event('session.connect', 'New connection [session: reused]', '2024-03-01T23:00:00', protocol='ssh'),
        event('command.input', 'echo first', '2024-03-01T23:01:00', protocol='ssh'),
        event('command.input', 'echo late', '2024-03-02T02:00:00', protocol='ssh'),
        event('session.loseConnection', '', '2024-03-02T02:01:00', protocol='ssh'),
        event('session.closed', '', '2024-03-02T02:01:01', protocol='ssh'),
        event('command.input', 'echo orphan', '2024-03-02T02:02:00', protocol='ssh'),
        event('session.connect', 'New connection [session: reused]', '2024-03-02T02:03:00', protocol='ssh'),
        event('command.input', 'echo reconnect', '2024-03-02T02:04:00', protocol='ssh'),
    ]
    _, database = ingest(tmp_path, {'2024/cowrie/ssh_a.json': rows[:2], '2024/cowrie/ssh_b.json': rows[2:]})
    with duckdb.connect(str(database)) as con:
        sessions = dict(con.execute('SELECT shell_input,session_id FROM SHELL_INPUTS').fetchall())
        assert sessions['echo first'] == sessions['echo late']
        assert len(set(sessions.values())) == 3
        assert 'reused' in sessions['echo first'] and 'reused' in sessions['echo reconnect']


def test_missing_endpoints_times_and_early_occurrences_get_fallbacks(tmp_path):
    """An IP address and list order cannot recover missing login times."""
    _, database = ingest(tmp_path, {
        '2024/cowrie/telnet.json': [
            event('command.input', 'id', '2024-03-01T00:00:00', src_port=None),
            event('command.input', 'id', '2024-03-01T00:00:00', src_port=None),
            event('command.input', 'whoami', 'bad-time'),
        ],
        'dataset/sessions/2021_2022.jsonl': [
            {'session_id': 'ip-group', 'src_ip': '192.0.2.1', 'commands': ['id', 'id', '', 'VALUE=one']},
        ],
    })
    with duckdb.connect(str(database)) as con:
        rows = con.execute('SELECT record_id,session_id,group_id FROM SHELL_INPUTS').fetchall()
        assert len(rows) == 7
        assert len({row[1] for row in rows}) == 7
        assert all(session == 'shell-honeypot:record:' + record and group is None for record, session, group in rows)
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (5,)
        assert con.execute("SELECT count(*) FROM SHELL_INPUTS WHERE ends_with(record_id, ':line:1:command:0')").fetchone() == (1,)


def test_fragment_only_reconstruction_and_failed_attempts(tmp_path):
    """Recognized wrappers become best-effort shell inputs, with original spelling retained."""
    root, database = ingest(tmp_path, {'2024/cowrie/ssh.json': [
        event('command.input', "command  found [ b'uname -a ']", '2024-03-01T00:00:00', protocol='ssh'),
        event('command.failed', "command not found [ b'systemctl stop shellinabox ']", '2024-03-01T00:00:01', protocol='ssh'),
        event('command.input', "command  found [ b'uname -a ']", '2024-03-01T00:00:02', protocol='ssh'),
        event('command.input', "command  found [ b'\\xff' ]", '2024-03-01T00:00:03', protocol='ssh'),
    ]})
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT shell_input FROM SHELL_INPUTS ORDER BY record_id').fetchall() == [
            ('uname -a ',), ('systemctl stop shellinabox ',), ('uname -a ',),
        ]
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (3,)
    audit = [json.loads(line) for line in (root / 'import-audit.jsonl').read_text().splitlines()]
    assert any(row['record_id'].endswith(':line:4') for row in audit)


def test_native_ids_preserve_literals_and_bounded_assignment(tmp_path):
    """Native IDs work without endpoints, and output limits preserve session IDs."""
    literal = "  printf '%s\\n' 'command  found [ b\"id\" ]'  "
    root, database = ingest(tmp_path, {'2024/cowrie/ssh.jsonl': [
        {'eventid': 'cowrie.command.input', 'input': literal, 'session': 'abc', 'protocol': 'ssh'},
        {'eventid': 'cowrie.command.input', 'input': 'VALUE=one', 'session': 'abc', 'protocol': 'ssh'},
        {'eventid': 'cowrie.command.input', 'input': 'id', 'session': 'other', 'protocol': 'ssh'},
    ]})
    with duckdb.connect(str(database)) as con:
        rows = con.execute('SELECT record_id,shell_input,session_id FROM SHELL_INPUTS ORDER BY record_id').fetchall()
        assert rows[0][1] == literal
        assert rows[0][2] == rows[1][2] == 'shell-honeypot:2024:deployment:native:abc'
        assert rows[2][2] != rows[0][2]
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (2,)
    bounded = tmp_path / 'bounded.duckdb'
    result = invoke(root, bounded, 'from _ingest_shell_honeypot import records\n', '--max-records', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(bounded)) as con:
        assert con.execute('SELECT record_id,shell_input,session_id FROM SHELL_INPUTS').fetchall() == rows[:1]
        assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(False,)]


def test_rejected_records_are_accounted_without_losing_valid_inputs(tmp_path):
    """Malformed source rows remain traceable, and wrapper parsing never executes code."""
    files = {'2024/cowrie/ssh.json': [
        event('command.input', 'command  found [ 42 ]', '2024-03-01T00:00:00', protocol='ssh'),
        event('command.input', 'command  found [ broken syntax ]', '2024-03-01T00:00:01', protocol='ssh'),
        event('command.input', "command  found [ __import__('os').getcwd() ]", '2024-03-01T00:00:02', protocol='ssh'),
        event('command.failed', "command not found [ b'only_failed' ]", '2024-03-01T00:00:03', protocol='ssh', src_port=40002),
        event('command.failed', 'unrecognized failed format', '2024-03-01T00:00:04', protocol='ssh', src_port=40003),
        event('command.input', 'id', '2024-03-01T00:00:05', protocol='ftp'),
        event('command.input', None, '2024-03-01T00:00:06', protocol='ssh'),
        event('command.input', 'id', '2024-03-01T00:00:07', protocol='ssh', src_port=0),
        event('command.input', 'whoami', '2024-03-01T00:00:08', protocol='ssh', dst_host=''),
        event('command.input', 'id', '2024-03-01T00:00:08', protocol='ssh', src_port='1' * 5000),
        event('login.success', '', '2024-03-01T00:00:09', protocol='ssh', src_port=40004),
        event('session.closed', '', '2024-03-01T00:00:10', protocol='ssh', src_port=40004),
    ], 'dataset/sessions/2021_2022.jsonl': [
        {'commands': 'id'}, {'commands': [False, 'id']},
    ]}
    root, database = ingest(tmp_path, files)
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT shell_input FROM SHELL_INPUTS ORDER BY record_id').fetchall() == [('id',), ('id',), ('whoami',), ('id',)]
        assert con.execute("SELECT count(*) FROM SHELL_INPUTS WHERE starts_with(session_id, 'shell-honeypot:record:')").fetchone() == (4,)
    counts = json.loads((root / 'import-summary.json').read_text())['counts']
    for reason, expected in {'malformed-wrapper': 3, 'isolated-failed-fragment': 1,
                             'unassociated-failed-message': 1, 'unsupported-protocol': 1,
                             'non-string-input': 2, 'invalid-command-list': 1,
                             'orphan-ssh-login': 1, 'orphan-close': 1}.items():
        assert counts[reason] == expected


def test_replay_disagreements_do_not_change_behavior_labels(tmp_path):
    """Contradictory scores and changed replay text stay visible in the audit."""
    root, database = ingest(tmp_path, {
        'dataset/sessions/2021_2022.jsonl': [{'commands': ['uname -a', 'unreviewed_program']}],
        'dataset/request_response/curated.jsonl': [
            {'command': 'uname -a', 'severity_vi': 0, 'session_id': 'a', 'turn_index': 1},
            {'command': 'uname -a', 'severity_vi': 2, 'session_id': 'a', 'turn_index': 2},
            {'command': 42},
        ],
        'dataset/request_response/vm_replay_2021_2022.jsonl': [
            {'command': 'changed text', 'session_id': 'a', 'turn_index': 1},
            {'command': 'uname -a', 'session_id': 'a', 'turn_index': 2},
        ],
    })
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT shell_input,dataset_label FROM SHELL_INPUTS ORDER BY record_id').fetchall() == [
            ('uname -a', 'benign'), ('unreviewed_program', 'unknown'),
        ]
    summary = json.loads((root / 'import-summary.json').read_text())
    assert summary['counts']['changed-replay-text'] == 1
    assert summary['counts']['conflicting-replay-scores'] == 1
    assert summary['counts']['non-string-replay'] == 1
    assert summary['groups']['2021_2022/unknown']['shell_unknown_rate'] == 0.5
    audit = [json.loads(line) for line in (root / 'import-audit.jsonl').read_text().splitlines()]
    emitted = next(row for row in audit if row['action'] == 'emit')
    assert [reference['severity'] for reference in emitted['replay_references']] == [0, 2]


def test_invalid_json_and_non_objects_are_audited(tmp_path):
    """The importer continues after invalid UTF-8, invalid JSON, and non-object rows."""
    import io
    import tarfile

    root = tmp_path / 'shell-honeypot'
    root.mkdir()
    content = b'{broken\n[]\n\xff\n' + json.dumps({'commands': ['id']}).encode() + b'\n'
    with tarfile.open(root / 'release.tar.gz', 'w:gz') as archive:
        member = tarfile.TarInfo('release/dataset/sessions/2021_2022.jsonl')
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_shell_honeypot import records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT shell_input FROM SHELL_INPUTS').fetchall() == [('id',)]
    summary = json.loads((root / 'import-summary.json').read_text())
    assert summary['counts']['malformed-json'] == 3
    audit = [json.loads(line) for line in (root / 'import-audit.jsonl').read_text().splitlines()]
    assert [row['record_id'].rsplit(':line:', 1)[1] for row in audit if row['action'] == 'skip'] == ['1', '2', '3']


def test_early_output_limit_leaves_import_incomplete(tmp_path):
    """A limit preserves early occurrence IDs and records incomplete output."""
    root = tmp_path / 'shell-honeypot'
    root.mkdir()
    _archive(root, {'dataset/sessions/2021_2022.jsonl': [{'commands': ['id', 'whoami']}]})
    database = tmp_path / 'commands.duckdb'
    result = invoke(root, database, 'from _ingest_shell_honeypot import records\n', '--max-records', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT shell_input FROM SHELL_INPUTS').fetchall() == [('id',)]
        assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(False,)]
    assert json.loads((root / 'import-summary.json').read_text())['output_complete'] is False

    retry = invoke(root, database, 'from _ingest_shell_honeypot import records\n')
    assert retry.returncode == 0, retry.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT shell_input FROM SHELL_INPUTS ORDER BY record_id').fetchall() == [('id',), ('whoami',)]
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (2,)
        assert con.execute('SELECT ingested FROM INGESTED').fetchall() == [(True,)]
