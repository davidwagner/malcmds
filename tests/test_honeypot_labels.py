"""Remote honeypot inputs retain unknown labels and shell syntax in storage."""
import gzip
import json
import zipfile
from pathlib import Path

import duckdb
import pytest
from test_ingest_batches import invoke


@pytest.mark.parametrize('dataset', ['microsoft', 'cyberlab'])
def test_published_honeypot_commands(tmp_path, dataset):
    """Archive and Bash parser upgrades must preserve remote input and suppress echoes."""
    data = json.loads((Path(__file__).parent/f'fixtures/honeypot/{dataset}.json').read_text())
    if dataset == 'microsoft':
        with zipfile.ZipFile(tmp_path/'Microsoft.IoT-Dump-pwd-infected.zip', 'w') as archive:
            archive.writestr('Microsoft.IoT-Dump1.json', json.dumps(data))
        source = 'from _ingest_misc import microsoft_iot as records\n'
        inputs = data[0]['Commands']
    else:
        # Also retain a useful handler-only observation without claiming complete input.
        data.append({'fallback': [{'eventid': 'cowrie.command.failed', 'message': 'Command not found: missing'}]})
        (tmp_path/'sample.json.gz').write_bytes(gzip.compress(json.dumps(data).encode()))
        source = 'from _ingest_misc import cyberlab as records\n'
        inputs = [e.get('input') or e['message'].removeprefix('CMD: ') for e in next(iter(data[0].values())) if e['eventid']=='cowrie.command.input']
    database = tmp_path/'commands.duckdb'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        shells = con.execute('SELECT pgms,dataset_label,group_id,session_id,shell_input,tokens FROM SHELL_INPUTS ORDER BY record_id').fetchall()
        processes = con.execute('SELECT pgm,dataset_label,group_id,session_id FROM PROCESS_LAUNCHES ORDER BY record_id').fetchall()
    assert shells and all(r[1] == 'unknown' and r[2] is None and r[3] for r in shells)
    assert processes and all(r[1] == 'unknown' and r[2] is None and r[3] for r in processes)
    assert {r[4] for r in shells} == set(inputs)
    assert any(';' in r[5] for r in shells), 'Bash parser lost multi-command input syntax'
    if dataset == 'cyberlab':
        assert sum(r[0].count('system') for r in shells) == 1, 'A failed handler echo must not duplicate original input'
        assert [(r[0], r[1], r[2]) for r in processes if r[0] == 'missing'] == [('missing', 'unknown', None)]
    else:
        assert all(r[1] == 'unknown' for r in processes)
    assert len({r[3] for r in shells}) == 1
    again = invoke(tmp_path, database, source)
    assert again.returncode == 0, again.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone()[0] == len(shells)
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone()[0] == len(processes)


@pytest.mark.parametrize('source', ['microsoft', 'input', 'success', 'failed'])
def test_attacker_commands_keep_connection_or_sequence_without_label_group(tmp_path, source):
    """Commands retain unknown labels and independent source sessions."""
    if source == 'microsoft':
        records = [{'ID': sid, 'TimesSeen': 1000, 'Commands': ['uname -a; id']}
                   for sid in ['first', 'second']]
        with zipfile.ZipFile(tmp_path / 'Microsoft.IoT-Dump-pwd-infected.zip', 'w') as archive:
            archive.writestr('Microsoft.IoT-Dump1.json', json.dumps(records))
        reader = 'from _ingest_misc import microsoft_iot as records\n'
        expected_sessions = {'microsoft-iot:first', 'microsoft-iot:second'}
    else:
        records = []
        prefixes = {'input': 'CMD: ', 'success': 'Command found: ', 'failed': 'Command not found: '}
        for sid in ['first', 'second']:
            commands = ['uname -a; id'] if source == 'input' else ['uname -a', 'id']
            events = [{'eventid': 'cowrie.command.' + source,
                       'message': prefixes[source] + command,
                       'dst_host_identifier': 'host-a'} for command in commands]
            if source == 'input':
                events.append({'eventid': 'cowrie.command.failed',
                               'message': 'Command not found: uname -a',
                               'dst_host_identifier': 'host-a'})
            records.append({sid: events})
        (tmp_path / 'sample.json.gz').write_bytes(gzip.compress(json.dumps(records).encode()))
        reader = 'from _ingest_misc import cyberlab as records\n'
        expected_sessions = {'cyberlab:sample.json.gz:host-a:first',
                             'cyberlab:sample.json.gz:host-a:second'}
    database = tmp_path / 'commands.duckdb'
    result = invoke(tmp_path, database, reader)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        if source in ('microsoft', 'input'):
            rows = con.execute('SELECT pgms,dataset_label,group_id,session_id FROM SHELL_INPUTS').fetchall()
            assert len(rows) == 2, 'Each observed submission must remain one row'
            assert {row[3] for row in rows} == expected_sessions
            assert all(row[:3] == (['uname', 'id'], 'unknown', None) for row in rows)
            assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES').fetchone() == (4,)
        rows = con.execute('SELECT pgm,args,dataset_label,group_id,session_id FROM PROCESS_LAUNCHES').fetchall()
        assert len(rows) == 4, 'Sequence repetition counts and Cowrie handler echoes must not multiply commands'
        assert {row[4] for row in rows} == expected_sessions
        for session in expected_sessions:
            assert sorted((pgm, args, label, group) for pgm, args, label, group, sid in rows if sid == session) == [
                ('id', [], 'unknown', None), ('uname', ['-a'], 'unknown', None),
            ], 'Command labels must not depend on command syntax or Cowrie success/failure'
