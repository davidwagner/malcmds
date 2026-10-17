"""Import real CyberLab command strings and hostile near-matches into DuckDB."""

import gzip
import json
from pathlib import Path

import duckdb
import pytest
from test_ingest_batches import invoke

CASES = json.loads((Path(__file__).parent / 'fixtures/cyberlab-labels.json').read_text())


@pytest.mark.parametrize('mode', ['input', 'message', 'success', 'failed'])
def test_cyberlab_labels(tmp_path, mode):
    """Label complete inputs without transferring a sequence label to processes."""
    records = []
    expected = []
    for i, case in enumerate(CASES):
        text = case['input']
        if not text:
            continue
        event = {'eventid': 'cowrie.command.input', 'input': text}
        if mode == 'message':
            event = {'eventid': 'cowrie.command.input', 'message': 'CMD: ' + text}
        elif mode in ('success', 'failed'):
            prefix = 'Command found: ' if mode == 'success' else 'Command not found: '
            event = {'eventid': 'cowrie.command.' + mode, 'message': prefix + text}
        records.append({str(i): [event]})
        expected.append((text, case['label']))
    (tmp_path / 'sample.json.gz').write_bytes(gzip.compress(json.dumps(records).encode()))
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_misc import cyberlab as records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        actual = con.execute('SELECT shell_input,dataset_label FROM SHELL_INPUTS').fetchall()
        assert sorted(actual) == (sorted(expected) if mode in ('input', 'message') else [])
        assert con.execute("SELECT count(*) FROM PROCESS_LAUNCHES WHERE dataset_label != 'unknown'").fetchone() == (0,)
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone()[0] > 0


def test_near_matches_remain_unknown(tmp_path):
    """Reject extra commands, substitutions, redirects, and altered payloads."""
    commands = [
        'uname -a; id', 'uname -a\nid', 'uname -a > /etc/passwd',
        'uname $(id)', 'X=1 uname -a', 'cat /etc/shadow', 'crontab -r',
        'top -p $(id)', "ps | grep '[Mm]iner' > /tmp/result",
        "cat /proc/cpuinfo | grep name | head -n 1 | awk '{system(\"id\")}'",
        'sleep 15s && cd /var/tmp; echo "ZWNobyBoZWxsbw==" | base64 --decode | bash',
    ]
    for case in CASES:
        if case['label'] == 'benign':
            commands.extend([case['input'] + '; id', case['input'] + '\nid'])
        elif case['label'] == 'malicious':
            commands.append('echo ' + repr(case['input']))
            if 'base64 --decode' in case['input']:
                commands.append(case['input'].replace('IyEv', 'IyAw', 1))
    records = [{str(i): [{'eventid': 'cowrie.command.input', 'input': command}]}
               for i, command in enumerate(commands)]
    (tmp_path / 'sample.json.gz').write_bytes(gzip.compress(json.dumps(records).encode()))
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, 'from _ingest_misc import cyberlab as records\n')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute('SELECT shell_input,dataset_label FROM SHELL_INPUTS').fetchall()
        assert sorted(rows) == sorted((text, 'unknown') for text in commands)
