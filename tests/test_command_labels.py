"""Exercise labeling CLIs with real DuckDB, CSV, and downloaded-result files.

No service is replaced by a test double. Offline preparation and importing
provider-format result files are supported CLI operations. Live submission,
provider status transitions, and network/disk failures require external
conditions and are not covered by these tests.
"""

import csv
import json
import os
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[1]


def run(name, *args):
    """Invoke a CLI without inheriting credentials or calling a paid service."""
    env = dict(os.environ)
    env.pop('OPENAI_API_KEY', None)
    return subprocess.run([sys.executable, str(ROOT / 'scripts' / name), *map(str, args)],
                          capture_output=True, text=True, env=env, check=False)


def database(path):
    """Create observation tables with the project's materialized label columns."""
    with duckdb.connect(str(path)) as con:
        con.execute("CREATE TYPE final_label AS ENUM ('malicious', 'benign', 'unknown')")
        con.execute("CREATE TYPE command_label AS ENUM ('malicious', 'benign', 'unknown', 'malicious-group')")
        for table, columns in [('SHELL_INPUTS', 'shell_input VARCHAR'),
                               ('PROCESS_LAUNCHES', 'pgm VARCHAR, args VARCHAR[]')]:
            con.execute(f'''CREATE TABLE {table} ({columns}, dataset VARCHAR,
                ai_label final_label, override_label final_label, dataset_label command_label,
                label final_label)''')
        con.executemany('INSERT INTO SHELL_INPUTS VALUES (?, ?, ?, ?, ?, ?)', [
            ('echo "a,b"\nnext', 'first', None, None, 'benign', 'benign'),
            ('echo "a,b"\nnext', 'first', 'unknown', 'benign', 'unknown', 'benign'),
            ('echo "a,b"\nnext', 'second', None, None, 'unknown', 'unknown'),
            ('known', 'first', 'benign', None, 'unknown', 'benign'),
            ('', 'second', None, None, 'malicious-group', 'unknown'),
            ('unselected', 'other', None, None, 'unknown', 'unknown')])
        con.executemany('INSERT INTO PROCESS_LAUNCHES VALUES (?, ?, ?, ?, ?, ?, ?)', [
            ('/bin/echo', ['a b', ''], 'first', None, None, 'unknown', 'unknown'),
            ('/bin/echo', ['a b', ''], 'second', 'benign', None, 'unknown', 'benign'),
            ('/bin/echo', ['a', 'b'], 'first', None, None, 'unknown', 'unknown'),
            ('/bin/echo', [], 'first', None, None, 'benign', 'benign'),
            ('echo', [], 'first', None, None, 'unknown', 'unknown')])


def write_csv(path, rows):
    """Write exact command fields using standard CSV quoting."""
    with path.open('w', newline='') as stream:
        csv.writer(stream).writerows(rows)


def prepare(tmp_path, table='SHELL_INPUTS', model='luna'):
    """Prepare a job using the same CLI options as a paid submission."""
    db, output, state = (tmp_path / name for name in ('cmds.duckdb', 'labels.csv', 'job.json'))
    database(db)
    result = run('label_commands', '--db', db, '--table', table, '--output', output,
                 '--model', model, '--datasets', 'first', 'second', '--state', state,
                 '--prepare-only')
    assert result.returncode == 0, result.stderr
    return db, output, state


@pytest.mark.parametrize('table,model,count', [('SHELL_INPUTS', 'luna', 3),
                                              ('PROCESS_LAUNCHES', 'sol', 4)])
def test_prepare_selects_unique_unknown_commands(tmp_path, table, model, count):
    """Deduplication is per dataset and preserves full argument arrays."""
    db, output, state = prepare(tmp_path, table, model)
    manifest = json.loads(state.read_text())
    rows = [row for chunk in manifest['chunks'] for row in chunk['commands']]
    assert len(rows) == count
    requests = [json.loads(line) for chunk in manifest['chunks']
                for line in Path(chunk['input']).read_text().splitlines()]
    assert len({r['custom_id'] for r in requests}) == count
    assert {r['body']['model'] for r in requests} == {
        'gpt-6-luna' if model == 'luna' else 'gpt-6.1-sol'}
    assert all(r['url'] == '/v1/responses' for r in requests)
    assert not output.exists()
    if table == 'SHELL_INPUTS':
        assert rows == [['echo "a,b"\nnext'], [''], ['echo "a,b"\nnext']]
    else:
        assert sorted(rows) == sorted([['/bin/echo', 'a b', ''], ['/bin/echo', 'a', 'b'],
                                      ['/bin/echo'], ['echo']])
    repeated = run('label_commands', '--db', db, '--table', table, '--output', output,
                   '--model', model, '--datasets', 'first', 'second', '--state', state,
                   '--prepare-only')
    assert repeated.returncode == 0, repeated.stderr
    assert json.loads(state.read_text()) == manifest


@pytest.mark.parametrize('table', ['SHELL_INPUTS', 'PROCESS_LAUNCHES'])
def test_collect_downloaded_results_and_import(tmp_path, table):
    """Collect out-of-order downloaded JSONL, append once, and import all matches."""
    db, output, state = prepare(tmp_path, table)
    manifest = json.loads(state.read_text())
    write_csv(output, [['benign', 'preexisting']])
    original = output.read_bytes()
    results = tmp_path / 'download.jsonl'
    records = []
    for chunk in manifest['chunks']:
        for line in Path(chunk['input']).read_text().splitlines():
            request = json.loads(line)
            records.append({'custom_id': request['custom_id'], 'error': None,
                            'response': {'status_code': 200, 'body': {
                                'status': 'completed', 'output': [{'type': 'message',
                                'content': [{'type': 'output_text', 'text': 'malicious'}]}]}}})
    results.write_text('\n'.join(map(json.dumps, reversed(records))))
    for _ in range(2):
        result = run('label_commands', '--collect', '--state', state, '--results', results)
        assert result.returncode == 0, result.stderr
    assert output.read_bytes().startswith(original)
    with output.open(newline='') as stream:
        rows = list(csv.reader(stream))
    assert len(rows) == len(records) + 1
    result = run('import_labels', '--db', db, '--table', table, '--labels', output)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        if table == 'SHELL_INPUTS':
            assert con.execute("SELECT ai_label, label FROM SHELL_INPUTS WHERE override_label IS NOT NULL").fetchall() == [('malicious', 'benign')]
            assert con.execute("SELECT count(*) FROM SHELL_INPUTS WHERE ai_label='malicious'").fetchone() == (4,)
        else:
            assert 'warning' in result.stderr.lower()
            assert con.execute("SELECT count(*) FROM PROCESS_LAUNCHES WHERE ai_label='malicious'").fetchone() == (5,)


def test_import_is_transactional_and_last_duplicate_wins(tmp_path):
    """Invalid rows roll back earlier updates; repeated commands follow CSV order."""
    db, labels = tmp_path / 'cmds.duckdb', tmp_path / 'labels.csv'
    database(db)
    write_csv(labels, [['malicious', 'known'], ['invalid', 'known']])
    result = run('import_labels', '--db', db, '--table', 'SHELL_INPUTS', '--labels', labels)
    assert result.returncode != 0
    with duckdb.connect(str(db)) as con:
        assert con.execute("SELECT ai_label FROM SHELL_INPUTS WHERE shell_input='known'").fetchone() == ('benign',)
    write_csv(labels, [['malicious', 'known'], ['unknown', 'known']])
    result = run('import_labels', '--db', db, '--table', 'SHELL_INPUTS', '--labels', labels)
    assert result.returncode == 0, result.stderr
    assert 'warning' in result.stderr.lower()
    with duckdb.connect(str(db)) as con:
        assert con.execute("SELECT ai_label, label FROM SHELL_INPUTS WHERE shell_input='known'").fetchone() == ('unknown', 'unknown')


@pytest.mark.parametrize('row', [[], ['benign'], ['benign', 'x', 'extra'], ['label', 'shell_input']])
def test_import_rejects_invalid_shell_csv(tmp_path, row):
    """Header rows, blank records, and wrong arity cannot silently change labels."""
    db, labels = tmp_path / 'cmds.duckdb', tmp_path / 'labels.csv'
    database(db)
    write_csv(labels, [row])
    result = run('import_labels', '--db', db, '--table', 'SHELL_INPUTS', '--labels', labels)
    assert result.returncode != 0


def test_missing_database_and_invalid_model(tmp_path):
    """Bad arguments must fail without creating a database or sending requests."""
    db = tmp_path / 'absent.duckdb'
    result = run('import_labels', '--db', db, '--table', 'SHELL_INPUTS', '--labels', 'missing.csv')
    assert result.returncode != 0
    assert not db.exists()
    result = run('label_commands', '--model', 'other')
    assert result.returncode != 0
    assert 'invalid choice' in result.stderr


@pytest.mark.parametrize('name', ['label_commands', 'import_labels'])
def test_help(name):
    """Usage is available without credentials or a database."""
    result = run(name, '--help')
    assert result.returncode == 0, result.stderr
    assert '--db' in result.stdout
    if name == 'label_commands':
        assert '--collect' in result.stdout and '24 hours' in result.stdout


@pytest.mark.parametrize('kind', ['duplicate', 'foreign', 'malformed'])
def test_bad_result_files_do_not_append(tmp_path, kind):
    """Unrecognized IDs and malformed downloads leave an existing CSV intact."""
    _, output, state = prepare(tmp_path)
    output.write_bytes(b'benign,existing\r\n')
    download = tmp_path / 'download.jsonl'
    if kind == 'malformed':
        download.write_text('{')
    else:
        record = json.dumps({'custom_id': '0:0' if kind == 'duplicate' else 'other'})
        download.write_text(record + '\n' + record)
    result = run('label_commands', '--collect', '--state', state, '--results', download)
    assert result.returncode == 1
    assert output.read_bytes() == b'benign,existing\r\n'
    assert not json.loads(state.read_text())['exported']


@pytest.mark.parametrize('body,status', [({'status': 'incomplete'}, 200),
                                       ({'status': 'completed'}, 500),
                                       ({'status': 'completed', 'output': [{'type': 'message',
                                         'content': [{'type': 'refusal', 'refusal': 'no'}]}]}, 200)])
def test_failed_and_missing_results_are_reported(tmp_path, body, status):
    """Provider failures and refusals never become a guessed unknown label."""
    _, output, state = prepare(tmp_path)
    download = tmp_path / 'download.jsonl'
    download.write_text(json.dumps({'custom_id': '0:0', 'response': {'status_code': status, 'body': body}}))
    for _ in range(2):
        result = run('label_commands', '--collect', '--state', state, '--results', download)
        assert result.returncode == 1
    assert output.read_bytes() == b''
    assert json.loads(state.read_text())['failures'] == 3


def test_process_import_preserves_argument_boundaries(tmp_path):
    """Only a full pgm/args match changes; unknown labels use dataset fallback."""
    db, labels = tmp_path / 'cmds.duckdb', tmp_path / 'labels.csv'
    database(db)
    write_csv(labels, [['malicious', '/bin/echo', 'a b', ''], ['unknown', '/bin/echo']])
    result = run('import_labels', '--db', db, '--table', 'PROCESS_LAUNCHES', '--labels', labels)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute("SELECT ai_label FROM PROCESS_LAUNCHES WHERE args=['a', 'b']").fetchone() == (None,)
        assert con.execute("SELECT ai_label FROM PROCESS_LAUNCHES WHERE pgm='echo'").fetchone() == (None,)
        assert con.execute("SELECT ai_label, label FROM PROCESS_LAUNCHES WHERE pgm='/bin/echo' AND args=[]").fetchone() == ('unknown', 'benign')
        assert con.execute("SELECT count(*) FROM PROCESS_LAUNCHES WHERE ai_label='malicious'").fetchone() == (2,)


def test_empty_selection_and_default_paths(tmp_path):
    """An empty job collects without credentials and defaults to cwd/cmds.duckdb."""
    db = tmp_path / 'cmds.duckdb'
    database(db)
    command = [sys.executable, str(ROOT / 'scripts/label_commands'), '--table', 'SHELL_INPUTS',
               '--output', 'out.csv', '--model', 'luna', '--datasets', 'absent']
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/label_commands'), '--collect',
                             '--output', 'out.csv'], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'out.csv').read_bytes() == b''
    write_csv(tmp_path / 'labels.csv', [['malicious', 'known']])
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/import_labels'), '--table',
                            'SHELL_INPUTS', '--labels', 'labels.csv'], cwd=tmp_path,
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_job_option_mismatch_and_missing_key(tmp_path):
    """Saved jobs reject changed selection and online work explains missing keys."""
    db, output, state = prepare(tmp_path)
    args = ['--db', db, '--table', 'SHELL_INPUTS', '--output', output, '--model', 'luna',
            '--datasets', 'first', 'second', '--state', state]
    result = run('label_commands', *args)
    assert result.returncode == 1
    assert 'OPENAI_API_KEY' in result.stderr
    result = run('label_commands', *args, '--model', 'sol')
    assert result.returncode == 1
    assert 'Options differ' in result.stderr
    result = run('label_commands', '--collect', '--state', state, '--output', tmp_path / 'other.csv')
    assert result.returncode == 1
    assert '--output differs' in result.stderr


@pytest.mark.parametrize('args,message', [([], '--output or --state'),
    (['--output', 'out.csv'], 'submission requires'),
    (['--results', 'result.jsonl'], '--results requires'),
    (['--collect', '--state', 'missing.json'], 'No job')])
def test_invalid_cli_options(tmp_path, args, message):
    """Explain invalid workflows without a traceback or external API call."""
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/label_commands'), *args],
                            cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert message in result.stderr


def test_request_files_cannot_overwrite_csv(tmp_path):
    """An output named like a request file must retain its original contents."""
    db, state, output = (tmp_path / name for name in ('cmds.duckdb', 'job.json', 'job-0.jsonl'))
    database(db)
    output.write_bytes(b'benign,existing\r\n')
    result = run('label_commands', '--db', db, '--table', 'SHELL_INPUTS', '--output', output,
                 '--model', 'luna', '--datasets', 'first', '--state', state, '--prepare-only')
    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == b'benign,existing\r\n'


@pytest.mark.parametrize('existing,offset,success', [(b'benign,existing\r\n', 100, False),
    (b'benign,existing\r\nwrong', 17, False), (b'benign,existing\r\nmali', 17, True),
    (b'benign,existing\r\nmalicious,"echo ""a,b""\nnext"\r\n', 17, True)])
def test_interrupted_append_recovery(tmp_path, existing, offset, success):
    """Resume partial/complete appends and reject truncated or modified output."""
    _, output, state = prepare(tmp_path)
    manifest = json.loads(state.read_text())
    manifest['append_offset'] = offset
    state.write_text(json.dumps(manifest))
    output.write_bytes(existing)
    download = tmp_path / 'download.jsonl'
    download.write_text(json.dumps({'custom_id': '0:0', 'response': {'status_code': 200,
        'body': {'status': 'completed', 'output': [{'type': 'message', 'content': [
            {'type': 'output_text', 'text': 'malicious'}]}]}}}))
    result = run('label_commands', '--collect', '--state', state, '--results', download)
    # Only one result was supplied, so missing requests produce exit status 1.
    assert result.returncode == 1
    if success:
        with output.open(newline='') as stream:
            assert list(csv.reader(stream)) == [['benign', 'existing'], ['malicious', 'echo "a,b"\nnext']]
        assert json.loads(state.read_text())['exported']
    else:
        assert 'CSV changed' in result.stderr
        assert output.read_bytes() == existing
        assert not json.loads(state.read_text())['exported']


@pytest.mark.parametrize('count,length,expected', [(50_001, 1, [50_000, 1]),
                                                  (2, 95_000_000, [1, 1]),
                                                  (1, 190_000_000, None)])
def test_batch_limits(tmp_path, count, length, expected):
    """Real input crosses each API limit without replacing constants or services."""
    db, output, state = (tmp_path / name for name in ('cmds.duckdb', 'out.csv', 'job.json'))
    with duckdb.connect(str(db)) as con:
        con.execute('''CREATE TABLE SHELL_INPUTS AS
            SELECT repeat('x', ?) || i::VARCHAR AS shell_input, 'data' AS dataset,
                   NULL::VARCHAR AS ai_label FROM range(?) t(i)''', [length, count])
    result = run('label_commands', '--db', db, '--table', 'SHELL_INPUTS', '--output', output,
                 '--model', 'luna', '--datasets', 'data', '--state', state, '--prepare-only')
    if expected is None:
        assert result.returncode == 1
        assert 'single command exceeds' in result.stderr
        assert not state.exists()
    else:
        assert result.returncode == 0, result.stderr
        manifest = json.loads(state.read_text())
        assert [len(c['commands']) for c in manifest['chunks']] == expected
        ids = set()
        for chunk in manifest['chunks']:
            with Path(chunk['input']).open() as stream:
                for line in stream:
                    request = json.loads(line)
                    assert request['custom_id'] not in ids
                    ids.add(request['custom_id'])
        assert len(ids) == count


@pytest.mark.parametrize('suffix', ['.json', '.json.lock'])
def test_protected_paths(tmp_path, suffix):
    """Reject output paths that alias the state or its lock before writing."""
    db, state = tmp_path / 'cmds.duckdb', tmp_path / 'job.json'
    database(db)
    output = tmp_path / ('job' + suffix)
    output.write_text('original')
    result = run('label_commands', '--db', db, '--table', 'SHELL_INPUTS', '--output', output,
                 '--model', 'luna', '--datasets', 'first', '--state', state, '--prepare-only')
    assert result.returncode == 1
    assert 'separate files' in result.stderr
    assert output.read_text() == 'original'


def test_label_missing_database_and_import_alias(tmp_path):
    """Protect a missing source and reject reading a database as CSV."""
    db, output, state = (tmp_path / name for name in ('cmds.duckdb', 'out.csv', 'job.json'))
    result = run('label_commands', '--db', db, '--table', 'SHELL_INPUTS', '--output', output,
                 '--model', 'luna', '--datasets', 'first', '--state', state, '--prepare-only')
    assert result.returncode == 1
    assert 'Database does not exist' in result.stderr
    assert not db.exists()
    database(db)
    result = run('import_labels', '--db', db, '--table', 'SHELL_INPUTS', '--labels', db)
    assert result.returncode == 1
    assert 'separate files' in result.stderr


@pytest.mark.parametrize('changed', [False, True])
def test_csv_without_newline_and_changed_recovery_results(tmp_path, changed):
    """Add a missing line terminator, or reject results changed during recovery."""
    _, output, state = prepare(tmp_path)
    output.write_bytes(b'benign,existing')
    if changed:
        manifest = json.loads(state.read_text())
        manifest.update(append_offset=15, append_digest='different')
        state.write_text(json.dumps(manifest))
    download = tmp_path / 'download.jsonl'
    download.write_text(json.dumps({'custom_id': '0:0', 'response': {'status_code': 200,
        'body': {'status': 'completed', 'output': [{'type': 'message', 'content': [
            {'type': 'output_text', 'text': 'malicious'}]}]}}}))
    result = run('label_commands', '--collect', '--state', state, '--results', download)
    assert result.returncode == 1  # Two requests have no result.
    if changed:
        assert 'Results changed' in result.stderr
        assert output.read_bytes() == b'benign,existing'
    else:
        with output.open(newline='') as stream:
            assert list(csv.reader(stream)) == [['benign', 'existing'], ['malicious', 'echo "a,b"\nnext']]
