"""Exercise override imports through the CLI using real CSV files and DuckDB."""

import subprocess

import duckdb
import pytest
from test_command_labels import ROOT, database, run, write_csv


@pytest.mark.parametrize('table,fields,predicate', [
    ('SHELL_INPUTS', ['echo "a,b"\nnext'], 'shell_input = ?'),
    ('PROCESS_LAUNCHES', ['/bin/echo', 'a b', ''], 'pgm = ? AND args = ?'),
    ('PROCESS_LAUNCHES', ['/bin/echo'], 'pgm = ? AND args = ?'),
])
@pytest.mark.parametrize('label', ['benign', 'malicious', 'unknown'])
def test_override_precedence_and_exact_matching(tmp_path, table, fields, predicate, label):
    """Overrides win over AI/dataset labels and preserve every other column."""
    db, labels = tmp_path / 'cmds.duckdb', tmp_path / 'labels.csv'
    database(db)
    args = fields if table == 'SHELL_INPUTS' else [fields[0], fields[1:]]
    with duckdb.connect(str(db)) as con:
        before = con.execute(f'SELECT * FROM {table}').fetchall()
        count = con.execute(f'SELECT count(*) FROM {table} WHERE {predicate}', args).fetchone()[0]
    write_csv(labels, [[label, *fields]])
    result = run('import_overrides', '--db', db, '--table', table, '--labels', labels)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f'Updated {count} matching rows.\n'
    with duckdb.connect(str(db)) as con:
        after = con.execute(f'SELECT * FROM {table}').fetchall()
    for old, new in zip(before, after, strict=True):
        matches = list(old[:len(args)]) == args
        expected = (*old[:-3], label, old[-2], label) if matches else old
        assert new == expected


@pytest.mark.parametrize('table,fields', [
    ('SHELL_INPUTS', ['known']), ('PROCESS_LAUNCHES', ['/bin/echo', 'a b', '']),
])
def test_override_conflicts_and_duplicates(tmp_path, table, fields):
    """Warnings describe old overrides and follow repeated CSV commands in order."""
    db, labels = tmp_path / 'cmds.duckdb', tmp_path / 'labels.csv'
    database(db)
    with duckdb.connect(str(db)) as con:
        con.execute(f"UPDATE {table} SET override_label = 'benign'")
    write_csv(labels, [['malicious', *fields], ['unknown', *fields], ['benign', *fields]])
    result = run('import_overrides', '--db', db, '--table', table, '--labels', labels)
    assert result.returncode == 0, result.stderr
    count = 1 if table == 'SHELL_INPUTS' else 2
    description = (f'shell_input={fields[0]!r}' if table == 'SHELL_INPUTS'
                   else f'pgm={fields[0]!r}, args={fields[1:]!r}')
    assert result.stderr.splitlines() == [
        f'Warning: CSV record {number} overwrites {count} conflicting override labels: '
        f'{old!r} -> {new!r}; {description}'
        for number, old, new in [(1, 'benign', 'malicious'), (2, 'malicious', 'unknown')]]
    assert result.stdout == f'Updated {3 * count} matching rows.\n'
    with duckdb.connect(str(db)) as con:
        assert con.execute(f"SELECT count(*) FROM {table} WHERE label = 'benign' AND override_label = 'benign'").fetchone()[0] >= count


@pytest.mark.parametrize('contents', ['', 'benign,absent\n', 'malicious,known\ninvalid,known\n',
                                      'malicious,known\n"unterminated', '\n', 'benign\n',
                                      'benign,known,extra\n'])
def test_override_noops_and_invalid_csv(tmp_path, contents):
    """Empty/unmatched inputs do nothing; malformed files leave all rows intact."""
    db, labels = tmp_path / 'cmds.duckdb', tmp_path / 'labels.csv'
    database(db)
    with duckdb.connect(str(db)) as con:
        before = con.execute('SELECT * FROM SHELL_INPUTS').fetchall()
    labels.write_text(contents)
    result = run('import_overrides', '--db', db, '--table', 'SHELL_INPUTS', '--labels', labels)
    assert result.returncode == (0 if contents in ('', 'benign,absent\n') else 1)
    with duckdb.connect(str(db)) as con:
        assert con.execute('SELECT * FROM SHELL_INPUTS').fetchall() == before


def test_override_cli_errors_and_help(tmp_path):
    """Reject missing or overlapping files and invalid tables without tracebacks."""
    db = tmp_path / 'cmds.duckdb'
    result = run('import_overrides', '--db', db, '--table', 'SHELL_INPUTS', '--labels', db)
    assert result.returncode == 1 and 'Database does not exist' in result.stderr
    assert not db.exists()
    database(db)
    for labels, message in [(db, 'separate files'), (tmp_path / 'missing.csv', 'No such file')]:
        result = run('import_overrides', '--db', db, '--table', 'SHELL_INPUTS', '--labels', labels)
        assert result.returncode == 1 and message in result.stderr
        assert 'Traceback' not in result.stderr
    result = run('import_overrides', '--table', 'invalid', '--labels', db)
    assert result.returncode == 2
    result = subprocess.run([str(ROOT / 'scripts/import_overrides'), '--help'],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert 'override' in result.stdout and '--labels' in result.stdout
