"""Ingest examples from tldr 6baf5eaa through the real parsers and database writer.

The source fixture contains unmodified CC BY 4.0 tldr pages. Parser worker and
filesystem failure branches require external failures; these tests use no doubles.
"""

import io
import json
import tarfile
from pathlib import Path

import duckdb
from test_ingest_performance import ingest

FIXTURE = Path(__file__).parent / "fixtures" / "tldr-pages.json"
READER = "from _ingest_tldr import records\n"


def release(root, pages):
    """Package real source Markdown in the same layout as the release download."""
    with tarfile.open(root / "tldr.tar.gz", "w:gz") as archive:
        for name, text in pages.items():
            data = text.encode()
            member = tarfile.TarInfo("tldr-release/pages/" + name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def arguments(con, prefix):
    """Read parsed argument lists for a source occurrence from the actual database."""
    rows = con.execute(
        "SELECT args FROM PROCESS_LAUNCHES WHERE record_id LIKE ?", [prefix + ':%']
    ).fetchall()
    assert rows, f"Missing parsed invocations for {prefix}"
    return [row[0] for row in rows]


def test_tldr_real_release_inputs_labels_sessions_and_reingestion(tmp_path):
    """Complete submissions, paths, and variants survive the actual SQL writer."""
    release(tmp_path, json.loads(FIXTURE.read_text()))
    database = tmp_path / "commands.duckdb"
    result = ingest(tmp_path, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT record_id,shell_input,os,session_id FROM SHELL_INPUTS ORDER BY record_id").fetchall()
        assert rows
        for record, text, osname, session in rows:
            assert '{{' not in text and '}}' not in text
            assert osname == ('windows' if record.startswith('windows/') else 'linux')
            assert session == f'{tmp_path.name}:record:{record}'
        for table in ('SHELL_INPUTS', 'PROCESS_LAUNCHES'):
            assert con.execute(f"SELECT DISTINCT dataset_label,group_id FROM {table}").fetchall() == [('benign', None)]
        assert not con.execute("SELECT count(*) FROM PROCESS_LAUNCHES p LEFT JOIN SHELL_INPUTS s USING(session_id) WHERE s.session_id IS NULL").fetchone()[0]
        assert not con.execute("SELECT count(*) FROM SHELL_INPUTS WHERE record_id LIKE 'common/less.md:%' AND shell_input NOT LIKE 'less %'").fetchone()[0]
        assert not con.execute("SELECT count(*) FROM SHELL_INPUTS WHERE record_id LIKE 'common/odps.md:%' AND shell_input NOT LIKE 'odpscmd %'").fetchone()[0]
        assert con.execute("SELECT count(*) FROM SHELL_INPUTS WHERE shell_input='systemctl --failed'").fetchone()[0] == 1
        for args in arguments(con, 'common/dirname.md:11'):
            assert len(args) == 2 and args[0] != args[1]
            assert Path(args[0]).stem.endswith('a') and args[1].endswith('b')
        cp = con.execute("SELECT args FROM PROCESS_LAUNCHES WHERE record_id LIKE 'common/cp.md:7:%' ORDER BY record_id").fetchall()
        assert len(cp) == 3
        for (args,) in cp:
            assert len(args) == 2 and args[0] != args[1]
            assert Path(args[0]).name == Path(args[1]).name
        assert any(' ' in arg for (args,) in cp for arg in args), 'The real pool includes a directory containing spaces'
        windows = con.execute("SELECT args FROM PROCESS_LAUNCHES WHERE record_id LIKE 'windows/type.md:%'").fetchall()
        assert any(' ' in args[0] for (args,) in windows)
        assert all(len(args) == 1 and '\\' in args[0] for (args,) in windows)
        repeated = con.execute("SELECT args FROM PROCESS_LAUNCHES WHERE record_id LIKE 'common/postcss.md:11:%'").fetchall()
        assert repeated and all(args[0] == args[-1] for (args,) in repeated)
    with duckdb.connect(str(database)) as con:
        con.execute('UPDATE INGESTED SET ingested=false')
    again = ingest(tmp_path, database, READER)
    assert again.returncode == 0, again.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT record_id,shell_input,os,session_id FROM SHELL_INPUTS ORDER BY record_id").fetchall() == rows
        assert con.execute("SELECT count(*) FROM INGESTED").fetchone()[0] == 1


def test_tldr_semantic_numeric_alternative_and_device_rules(tmp_path):
    """Actual invocations retain symbolic choices and coherent argument roles."""
    release(tmp_path, json.loads(FIXTURE.read_text()))
    database = tmp_path / "commands.duckdb"
    result = ingest(tmp_path, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        for args in arguments(con, 'windows/eventcreate.md'):
            assert 1 <= int(args[args.index('/id') + 1]) <= 1000
            assert args[args.index('/t') + 1] in {'success', 'error', 'warning', 'information'}
        for args in arguments(con, 'windows/color.md:15'):
            assert len(args[0]) == 2 and all(c in '0123456789ABCDEF' for c in args[0])
        for args in arguments(con, 'common/ffprobe.md:19'):
            assert args[args.index('-show_entries') + 1] in {'stream=width', 'stream=height'}
        for args in arguments(con, 'linux/microcom.md:7'):
            assert args[args.index('--port') + 1] in {'/dev/ttyUSB0', '/dev/ttyACM0'}
        for args in arguments(con, 'linux/mdadm.md:7'):
            assert args == ['--create', '/dev/md0', '--level', '1', '--raid-devices', '2', '/dev/sdb', '/dev/sdc']
        for args in arguments(con, 'common/nmap.md:24'):
            assert args == ['-p', '22,80,443', '192.0.2.10']
        for args in arguments(con, 'common/duplicity.md:8'):
            if args:
                assert args[-1] == 'ftps://alex@backup.example.org/backups/'
        for args in arguments(con, 'linux/systemctl.md'):
            assert '0' not in args


def test_tldr_limits_sampling_and_missing_rules_fail_without_marker(tmp_path):
    """Limited runs stay incomplete; missing substitution coverage fails clearly."""
    release(tmp_path, json.loads(FIXTURE.read_text()))
    database = tmp_path / "limited.duckdb"
    result = ingest(tmp_path, database, READER, '--max-records', '2')
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone()[0] <= 6
        assert con.execute('SELECT ingested FROM INGESTED').fetchone()[0] is False
    sampled = ingest(tmp_path, tmp_path / 'sampled.duckdb', READER, '--sample-files', '1')
    assert sampled.returncode == 0, sampled.stderr
    release(tmp_path, {'common/missing.md': '`cat {{unregistered_placeholder}}`\n'})
    failed = ingest(tmp_path, tmp_path / 'failed.duckdb', READER)
    assert failed.returncode != 0
    assert 'common/missing.md:1: no substitution rule' in failed.stderr
    release(tmp_path, {'common/malformed.md': '`cat {{incomplete}`\n'})
    malformed = ingest(tmp_path, tmp_path / 'malformed.duckdb', READER)
    assert malformed.returncode != 0 and 'malformed template markup' in malformed.stderr
    release(tmp_path, {'osx/ignored.md': '`date`\n'})
    empty = ingest(tmp_path, tmp_path / 'empty.duckdb', READER)
    assert empty.returncode != 0 and 'no English tldr pages' in empty.stderr


def test_tldr_invalid_substitution_configuration_and_partial_markup(tmp_path):
    """Malformed real generator input cannot mark an import complete."""
    # variants accepts explicit configuration, so an empty pool is an actual
    # invalid input rather than a simulated filesystem or network failure.
    (tmp_path / 'configuration.json').write_text(json.dumps({
        'pools': {'files': []},
        'rules': {'placeholders': {'path/to/file': {'pool': 'files'}}},
    }))
    reader = """
import json
from _ingest import ShellInput, shell_commands
from _ingest_tldr import variants

def records(root, options):
    settings = json.loads((root / 'configuration.json').read_text())
    for number, text in variants('cat {{path/to/file}}', 'common/cat.md:7',
                                 'bash', settings['pools'], settings['rules']):
        yield ShellInput(text, str(number), [
            Command(pgm, args, f'{number}:{index}', label='benign')
            for index, (pgm, args, _) in enumerate(shell_commands(text))
        ], label='benign')
"""
    database = tmp_path / 'empty-pool.duckdb'
    failed = ingest(tmp_path, database, reader)
    assert failed.returncode != 0 and 'empty substitution pool' in failed.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT ingested FROM INGESTED').fetchone() == (False,)
        assert con.execute('SELECT count(*) FROM SHELL_INPUTS').fetchone() == (0,)
    release(tmp_path, {'common/broken.md': '`cat {{path/to/file}} {{incomplete}`\n'})
    failed = ingest(tmp_path, tmp_path / 'broken.duckdb', READER)
    assert failed.returncode != 0 and 'unresolved template markup' in failed.stderr
