"""Exercise damaged TC command observations through Avro and the ingest CLI."""

import json
import subprocess
import sys
from pathlib import Path

import duckdb
import fastavro
import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SCHEMA = {
    'type': 'record',
    'name': 'Observation',
    'fields': [{
        'name': 'datum',
        'type': [{
            'type': 'record',
            'name': 'Subject',
            'fields': [
                {'name': 'uuid', 'type': 'string'},
                {'name': 'type', 'type': 'string'},
                {'name': 'cmdLine', 'type': 'string'},
            ],
        }],
    }],
}


@pytest.mark.parametrize('collector', ['fivedirections', 'marple', 'cadets', 'theia', 'trace'])
@pytest.mark.parametrize('case', ['empty', 'replacement'])
def test_malformed_command_observations(collector, case, tmp_path):
    """Skip empty/broken executables and retain intact argv after bad records."""
    root = tmp_path / 'datasets' / f'tc-e3-{collector}'
    data = root / 'data'
    data.mkdir(parents=True)
    if case == 'empty':
        texts = ['', ' ', '\t\r\n', '\u2003', '\0', ' \0', '\0\0',
                 'N/A', '(null)', 'null', '<unknown>']
        expected = [('echo', ['ok'])]
    else:
        texts = ['\ufffd --broken', '"bad \ufffd" --broken']
        if collector in {'cadets', 'theia', 'trace'}:
            texts += ['printf\0%s\0\ufffd\0', 'printf\0%s\0\0']
        else:
            texts += ['printf "%s" "\ufffd"', 'printf "%s" ""']
        expected = [('echo', ['ok']), ('printf', ['%s', '']), ('printf', ['%s', '\ufffd'])]
    texts.append('echo ok')
    with (data / 'observations.bin').open('wb') as stream:
        fastavro.writer(stream, SCHEMA, [
            {'datum': {'uuid': str(index), 'type': 'SUBJECT_PROCESS', 'cmdLine': text}}
            for index, text in enumerate(texts)
        ])
    driver = root / 'ingest'
    driver.write_text(
        'import sys\nfrom pathlib import Path\n'
        f'sys.path.insert(0, {str(SCRIPTS)!r})\n'
        'from _ingest import run\nfrom _ingest_tc import records\n'
        'run(Path(__file__).resolve().parent, records)\n'
    )
    database = tmp_path / 'commands.duckdb'
    result = subprocess.run(
        [sys.executable, str(driver), '--db', str(database)],
        capture_output=True, text=True, check=True,
    )
    assert json.loads(result.stdout)['stored'] == len(expected)
    with duckdb.connect(str(database), read_only=True) as connection:
        assert connection.execute('SELECT pgm,args FROM COMMANDS ORDER BY pgm,args').fetchall() == expected
