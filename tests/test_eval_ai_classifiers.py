"""Exercise evaluation through its CLI and real DuckDB files.

Live-provider tests require EVAL_AI_LIVE=1 and ~/.api_keys. Network failures,
provider rate limits, and unavailable provider scores cannot be triggered
reliably without test doubles; this suite deliberately does not fabricate them.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'eval_ai_classifiers'
CLASSIFIERS = ['jev', 'pplx', 'luna', 'haiku', 'sol']


def create_source(path, rows):
    """Write shell observations and corresponding process observations."""
    with duckdb.connect(str(path)) as db:
        db.execute("""CREATE TABLE PROCESS_LAUNCHES (
            record_id VARCHAR, dataset VARCHAR, dataset_label VARCHAR,
            pgm VARCHAR, pgm_base VARCHAR, args VARCHAR[],
            group_id VARCHAR, session_id VARCHAR, os VARCHAR);
            CREATE TABLE SHELL_INPUTS (
            record_id VARCHAR, dataset VARCHAR, dataset_label VARCHAR,
            shell_input VARCHAR, pgms VARCHAR[], tokens VARCHAR[],
            group_id VARCHAR, session_id VARCHAR, os VARCHAR)""")
        db.execute('BEGIN')
        for record_id, dataset, dataset_label, shell_input, pgm_base, args in rows:
            db.execute('INSERT INTO PROCESS_LAUNCHES VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)',
                       [record_id, dataset, dataset_label, pgm_base, pgm_base, args])
            if shell_input is not None:
                db.execute('INSERT INTO SHELL_INPUTS VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)',
                           [record_id, dataset, dataset_label, shell_input, [pgm_base], args])
        db.execute('COMMIT')


def run_cli(output, *arguments, success=True, timeout=180, table="SHELL_INPUTS"):
    """Run the public entry point and retain useful output on assertion failure."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(output),
         *(["--table", table] if table is not None else []), *map(str, arguments)],
        check=False, capture_output=True, text=True, timeout=timeout,
    )
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    return result


def read_rows(path, sql):
    """Read persisted output after the subprocess has closed its connection."""
    with duckdb.connect(str(path), read_only=True) as db:
        return db.execute(sql).fetchall()


@pytest.mark.parametrize("table, identity_count", [("SHELL_INPUTS", 2), ("PROCESS_LAUNCHES", 7)])
def test_sampling_identity_caps_and_reproducibility(tmp_path, table, identity_count):
    """Deduplicate per stratum before the seeded sample, preserving NULL argv."""
    source = tmp_path / 'source.duckdb'
    rows = [
        ('1', 'identity', 'benign', '', 'echo', ['one']),
        ('2', 'identity', 'benign', '', 'different', ['two']),
        ('3', 'identity', 'benign', 'echo same', 'echo', ['one']),
        ('4', 'identity', 'benign', 'echo same', 'different', ['two']),
        ('5', 'identity', 'benign', None, 'echo', None),
        ('6', 'identity', 'benign', None, 'echo', []),
        ('7', 'identity', 'benign', None, 'echo', ['']),
        ('8', 'identity', 'benign', None, 'echo', ['a b']),
        ('9', 'identity', 'benign', None, 'echo', ['a', 'b']),
        ('10', 'identity', 'benign', None, 'echo', ['a', 'b']),
        ('11', 'identity', 'malicious', 'echo same', 'echo', []),
        ('12', 'other', 'benign', 'echo same', 'echo', []),
    ]
    rows.extend((str(1000 + i), 'large', 'benign', f'echo {i}', 'echo', [str(i)])
                for i in range(260))
    create_source(source, rows)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    first, second, third = [tmp_path / f'{name}.duckdb' for name in ('first', 'second', 'third')]
    for output in (first, second):
        run_cli(output, '--source', source, '--sample-only', '--seed', '23', table=table)
    run_cli(third, '--source', source, '--sample-only', '--seed', '24', table=table)
    query = 'SELECT * FROM samples ORDER BY sample_id'
    assert read_rows(first, query) == read_rows(second, query)
    assert read_rows(first, query) != read_rows(third, query)
    assert read_rows(first, '''SELECT dataset, dataset_label, count(*) FROM samples
        GROUP BY ALL ORDER BY dataset, dataset_label''') == [
        ('identity', 'benign', identity_count), ('identity', 'malicious', 1),
        ('large', 'benign', 200), ('other', 'benign', 1),
    ]
    assert read_rows(first, "SELECT count(*) FROM samples WHERE shell_input = ''") == [(int(table == "SHELL_INPUTS"),)]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert read_rows(first, 'SELECT count(*) FROM classifier_costs') == [(5,)]
    run_cli(first, '--source', source, '--sample-only', '--seed', '23', '--resume', table=table)
    assert read_rows(first, query) == read_rows(second, query)
    run_cli(first, '--source', source, '--sample-only', '--seed', '24', '--resume', success=False, table=table)


def test_reject_overwrite_and_invalid_sampling(tmp_path):
    """Protect inputs and existing outputs and validate the sample count."""
    source = tmp_path / "source's.duckdb"
    create_source(source, [('1', 'one', 'benign', 'echo hi', 'echo', ['hi'])])
    before = source.read_bytes()
    run_cli(source, '--source', source, '--sample-only', success=False)
    assert source.read_bytes() == before
    output = tmp_path / 'output.duckdb'
    run_cli(output, '--source', source, '--sample-only', '--per-group', '1')
    saved = output.read_bytes()
    run_cli(output, '--source', source, '--sample-only', success=False)
    assert output.read_bytes() == saved
    run_cli(tmp_path / 'invalid.duckdb', '--source', source,
            '--sample-only', '--per-group', '0', success=False)
    run_cli(tmp_path / 'missing.duckdb', '--source', source, '--resume', success=False)


def test_analytics_denominators_pairing_confusion_costs_and_time(tmp_path):
    """Recompute all summaries from stored observations, including partial runs."""
    source, output = tmp_path / 'source.duckdb', tmp_path / 'output.duckdb'
    records = [
        ('1', 'a', 'benign', 'one', None, None),
        ('2', 'a', 'malicious', 'two', None, None),
        ('3', 'a', 'unknown', 'three', None, None),
        ('4', 'b', 'malicious-group', 'four', None, None),
        ('5', 'b', 'malicious', 'five', None, None),
    ]
    create_source(source, records)
    run_cli(output, '--source', source, '--sample-only')
    with duckdb.connect(str(output)) as db:
        ids = dict(db.execute('SELECT shell_input, sample_id FROM samples').fetchall())
        # Each list uses source record order; Sol is missing the last prediction.
        for classifier, predictions in [
            ('jev', ['malicious', 'benign', 'malicious', 'benign', 'malicious']),
            ('sol', ['benign', 'malicious', 'unknown', 'malicious', None]),
        ]:
            for record, prediction in zip(records, predictions):
                db.execute('''INSERT INTO results VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', [
                    ids[record[3]], classifier, 'fixture-observation', prediction,
                    prediction, 0.2 if prediction else None, 0.5 if prediction else None,
                    0.3 if prediction else None, 'self_reported' if prediction else None,
                    'ok' if prediction else 'failed', None if prediction else 'interrupted',
                ])
        db.execute('''INSERT INTO requests(classifier, stage, cost_usd, cost_kind)
            VALUES ('jev', 'classification', 0.1, 'estimated'),
                   ('jev', 'scores', 0.2, 'estimated'),
                   ('sol', 'classification', 0.4, 'reported'),
                   ('sol', 'classification', NULL, NULL)''')
        db.execute("INSERT INTO classifier_timing(classifier, seconds) VALUES ('jev', 2), ('jev', 3), ('sol', 7)")
        db.execute('UPDATE evaluation_run SET classification_seconds = 12, total_seconds = 14')
    run_cli(output, '--analyze-only')
    assert read_rows(output, '''SELECT sample_count, disagreement_count, disagreement_rate
        FROM disagreements WHERE classifier='jev' AND reference='dataset_label' AND scope='overall'
    ''') == [(5, 2, 0.4)]
    assert read_rows(output, '''SELECT dataset, sample_count, disagreement_count, disagreement_rate
        FROM disagreements WHERE classifier='jev' AND reference='dataset_label' AND scope='dataset'
        ORDER BY dataset''') == [('a', 3, 2, 2 / 3), ('b', 2, 0, 0)]
    assert read_rows(output, '''SELECT sample_count, disagreement_count, disagreement_rate
        FROM disagreements WHERE classifier='jev' AND reference='sol' AND scope='overall'
    ''') == [(4, 3, 0.75)]
    assert read_rows(output, '''SELECT dataset, sample_count, disagreement_rate
        FROM disagreements WHERE classifier='jev' AND reference='sol' AND scope='dataset'
        ORDER BY dataset''') == [('a', 3, 2 / 3), ('b', 1, 1.0)]
    assert read_rows(output, '''SELECT max(disagreement_rate) FROM disagreements
        WHERE classifier='sol' AND reference='sol' ''') == [(0.0,)]
    assert read_rows(output, '''SELECT count(*), sum(fraction), count(*) FILTER (WHERE sample_count=0)
        FROM confusion_matrices WHERE classifier='jev' AND reference='dataset_label' AND scope='overall'
    ''') == [(12, 1.0, 7)]
    assert read_rows(output, '''SELECT fraction FROM confusion_matrices WHERE classifier='jev'
        AND reference='dataset_label' AND scope='overall' AND reference_label='benign'
        AND prediction='malicious' ''') == [(0.2,)]
    assert read_rows(output, '''SELECT count(*), sum(fraction) FROM confusion_matrices
        WHERE classifier='jev' AND reference='sol' AND scope='overall' ''') == [(9, 1.0)]
    costs = read_rows(output, '''SELECT total_samples, evaluated_samples, scored_samples,
        failed_samples, request_count, known_cost_usd, unpriced_requests, total_cost_usd,
        estimated_cost_per_sample_usd, includes_estimates, classification_seconds
        FROM classifier_costs WHERE classifier='jev' ''')[0]
    assert costs[:5] == (5, 5, 5, 0, 2)
    assert costs[5] == pytest.approx(0.3)
    assert costs[6] == 0
    assert costs[7] == pytest.approx(0.3)
    assert costs[8] == pytest.approx(0.06)
    assert costs[9:] == (True, 5.0)
    assert read_rows(output, '''SELECT evaluated_samples, failed_samples, unpriced_requests,
        total_cost_usd, estimated_cost_per_sample_usd FROM classifier_costs WHERE classifier='sol'
    ''') == [(4, 1, 1, None, None)]
    assert read_rows(output, 'SELECT classification_seconds, total_seconds FROM evaluation_run') == [(12, 14)]
    saved = read_rows(output, 'SELECT * FROM disagreements ORDER BY ALL')
    run_cli(output, '--analyze-only')
    assert read_rows(output, 'SELECT * FROM disagreements ORDER BY ALL') == saved


@pytest.mark.skipif(os.environ.get('EVAL_AI_LIVE') != '1', reason='requires funded provider credentials')
def test_live_provider_contract_and_resume(tmp_path):
    """Check current APIs, model IDs, scores, and resumability against all providers."""
    source, output = tmp_path / 'source.duckdb', tmp_path / 'output.duckdb'
    create_source(source, [
        ('1', 'live-shell', 'benign', 'echo hello', 'echo', ['hello']),
        ('2', 'live-empty', 'unknown', '', 'ignored', ['ignored']),
        ('3', 'live-argv', 'benign', None, 'printf', ['hello world']),
    ])
    flags = ['--source', source, '--per-group', '1']
    run_cli(output, *flags, timeout=900, table="PROCESS_LAUNCHES")
    rows = read_rows(output, '''SELECT classifier, prediction, p_malicious, p_benign,
        p_unknown, score_kind, status FROM results ORDER BY classifier''')
    assert len(rows) == 15, 'An API/model contract changed: three results per provider are required'
    assert read_rows(output, 'SELECT classifier, count(*) FROM results GROUP BY ALL ORDER BY classifier') == [
        (name, 3) for name in sorted(CLASSIFIERS)
    ]
    assert {row[0] for row in rows} == set(CLASSIFIERS)
    for classifier, prediction, *remaining in rows:
        *scores, kind, status = remaining
        assert prediction in ('malicious', 'benign', 'unknown'), classifier
        assert status == 'ok', classifier
        if classifier in ('jev', 'pplx'):
            assert kind == 'native_probability'
            assert all(score is not None and 0 <= score <= 1 for score in scores), classifier
            assert sum(scores) == pytest.approx(1.0, abs=1e-5), classifier
        else:
            assert scores == [None, None, None], classifier
            assert kind is None, classifier
    assert read_rows(output, 'SELECT classifier, stage, count(DISTINCT sample_id) FROM requests GROUP BY ALL ORDER BY classifier') == [
        (name, 'label', 3) for name in sorted(CLASSIFIERS)
    ], 'Each sample must use only classification requests; retries may add attempts'
    responses = read_rows(output, 'SELECT response FROM requests WHERE http_status=200')
    assert responses
    assert all(json.loads(response).get('usage') for (response,) in responses), 'Provider usage contract changed'
    count = read_rows(output, 'SELECT count(*) FROM requests')
    run_cli(output, *flags, '--resume', table="PROCESS_LAUNCHES")
    assert read_rows(output, 'SELECT count(*) FROM requests') == count


def test_empty_source_and_cli_validation(tmp_path):
    """Handle zero commands and reject invalid configuration before evaluation."""
    source, output = tmp_path / 'empty.duckdb', tmp_path / 'output.duckdb'
    create_source(source, [])
    run_cli(output, '--source', source, '--sample-only')
    assert read_rows(output, 'SELECT count(*) FROM samples') == [(0,)]
    assert read_rows(output, 'SELECT count(*) FROM disagreements') == [(0,)]
    assert read_rows(output, 'SELECT count(*) FROM confusion_matrices') == [(0,)]
    assert read_rows(output, 'SELECT total_samples, evaluated_samples, total_cost_usd FROM classifier_costs') == [(0, 0, 0.0)] * 5
    for index, flags in enumerate([
        ['--concurrency', '0'], ['--max-hours', '0'], ['--max-hours', 'nan'],
        ['--request-timeout', 'inf'], ['--retries', '-1'],
        ['--classifiers', 'jev', 'jev'], ['--classifiers', 'missing-model'],
        ['--max-output-tokens', '-1'], ['--sample-only', '--analyze-only'],
    ]):
        invalid = tmp_path / f'invalid-{index}.duckdb'
        run_cli(invalid, '--source', source, '--sample-only', *flags, success=False)
        assert not invalid.exists()
    missing = tmp_path / 'missing.duckdb'
    run_cli(missing, '--analyze-only', success=False)
    assert not missing.exists()
    run_cli(missing, '--source', tmp_path / 'nonexistent.duckdb', '--sample-only', success=False)
    assert not missing.exists()
    run_cli(missing, '--source', source, '--keys', tmp_path / 'missing-keys', success=False)
    assert not missing.exists()


@pytest.mark.parametrize('corruption', ['none', 'label', 'scores'])
def test_replay_recorded_responses_and_reject_invalid_scores(tmp_path, corruption):
    """Replay actual saved responses offline and exercise validation on stored data.

    These observations were captured from the real APIs on 2026-10-11.
    Request IDs, encrypted reasoning, and echoed configuration are omitted. Mutated observations model a damaged/incompatible saved
    response. Keys are only parsed; all requests must come from the database.
    """
    source, output = tmp_path / 'source.duckdb', tmp_path / 'output.duckdb'
    create_source(source, [('1', 'replay', 'benign', 'echo hello', 'echo', ['hello'])])
    run_cli(output, '--source', source, '--sample-only')
    observations = json.loads((Path(__file__).parent / 'fixtures/eval-ai/observations.json').read_text())
    keys = tmp_path / 'keys'
    keys.write_text('OPENAI_API_KEY=unused\nANTHROPIC_API_KEY=unused\nOPENROUTER_API_KEY=unused\n')
    with duckdb.connect(str(output)) as db:
        for observation in observations:
            name, stage, response = (observation[key] for key in ('classifier', 'stage', 'response'))
            if corruption == 'label' and name == 'jev':
                response['answers']['classification']['choice'] = 'BENIGN with an explanation'
            if stage == 'scores':
                continue
            if corruption == 'scores' and name == 'jev':
                response['answers']['classification']['probabilities'] = {
                    'malicious': -1, 'benign': 2, 'unknown': 0}
            db.execute('''INSERT INTO requests(sample_id,classifier,stage,http_status,
                response,cost_usd,cost_kind) VALUES (1,?,?,200,?,?,?)''', [
                    name, stage, json.dumps(response), observation['cost_usd'], observation['cost_kind']])
    run_cli(output, '--source', source, '--keys', keys, '--resume', success=corruption != 'scores')
    assert read_rows(output, 'SELECT count(*) FROM requests') == [(5,)], 'Replay must not call the APIs'
    assert read_rows(output, 'SELECT count(*) FROM results') == [(5,)]
    if corruption == 'label':
        assert read_rows(output, "SELECT prediction,status FROM results WHERE classifier='jev'") == [('unknown', 'ok')]
    elif corruption == 'scores':
        assert read_rows(output, "SELECT status,p_malicious FROM results WHERE classifier='jev'") == [('score_error', None)]
        assert read_rows(output, """SELECT error IS NOT NULL, cost_usd > 0 FROM requests
            WHERE classifier='jev' AND stage='label'""") == [(True, True)], 'Invalid cached scores must be retriable without losing cost'
        assert read_rows(output, 'SELECT status FROM evaluation_run') == [('incomplete',)]
    else:
        assert read_rows(output, "SELECT count(*) FROM results WHERE status='ok'") == [(5,)]
        assert read_rows(output, 'SELECT status FROM evaluation_run') == [('complete',)]

    assert read_rows(output, """SELECT classifier, p_malicious, p_benign, p_unknown, score_kind, status
        FROM results WHERE classifier IN ('sol', 'luna', 'haiku') ORDER BY classifier""") == [
        (name, None, None, None, None, 'ok') for name in ('haiku', 'luna', 'sol')
    ]
    assert read_rows(output, """SELECT classifier, scored_samples FROM classifier_costs
        ORDER BY classifier""") == [
        ('haiku', 0), ('jev', 0 if corruption == 'scores' else 1),
        ('luna', 0), ('pplx', 1), ('sol', 0)
    ]
    if corruption == 'none':
        run_cli(output, '--source', source, '--keys', keys, '--resume')
        assert read_rows(output, 'SELECT count(*) FROM requests') == [(5,)]


def test_observation_table_selection_and_resume(tmp_path):
    """DuckDB must sample exactly one observation type and preserve list identity."""
    source = tmp_path / 'source.duckdb'
    create_source(source, [
        ('1', 'shell', 'benign', '/bin/echo a; /bin/echo b', 'echo', ['a']),
        ('2', 'native', 'unknown', None, 'printf', ['a b', 'c']),
    ])
    with duckdb.connect(str(source)) as db:
        db.execute("""INSERT INTO PROCESS_LAUNCHES VALUES
            ('1:1', 'shell', 'benign', '/bin/echo', 'echo', ['b'], NULL, NULL, 'Linux')""")
    process_output, shell_output = tmp_path / 'process.duckdb', tmp_path / 'shell.duckdb'
    run_cli(process_output, '--source', source, '--sample-only', table=None)
    run_cli(shell_output, '--source', source, '--sample-only')
    assert read_rows(process_output, 'SELECT shell_input, pgm_base, args FROM samples ORDER BY dataset, args') == [
        (None, 'printf', ['a b', 'c']), (None, 'echo', ['a']), (None, 'echo', ['b'])
    ], 'Process sampling must preserve DuckDB LIST values and exclude shell observations'
    assert read_rows(shell_output, 'SELECT shell_input, pgm_base, args FROM samples') == [
        ('/bin/echo a; /bin/echo b', None, None)
    ], 'Shell sampling must not include the process launches derived from that input'
    assert read_rows(process_output, 'SELECT DISTINCT dataset_label FROM samples ORDER BY 1') == [
        ('benign',), ('unknown',)
    ]
    run_cli(process_output, '--source', source, '--sample-only', '--resume', table=None)
    result = run_cli(process_output, '--source', source, '--sample-only', '--resume', success=False)
    assert 'Resume configuration differs' in result.stderr
    run_cli(tmp_path / 'invalid-table.duckdb', '--source', source, '--sample-only',
            table='COMMANDS', success=False)
