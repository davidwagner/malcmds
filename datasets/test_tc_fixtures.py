"""Native TC excerpts exercise the Avro reader and DuckDB writer without downloads."""

import shutil
import subprocess
import sys
from pathlib import Path

import duckdb

HERE = Path(__file__).parent


def test_trace_executable_only_subjects(tmp_path):
    """Two original TRACE Subjects retain argv[0] across dependency upgrades."""
    root = tmp_path / 'datasets' / 'tc-e3-trace'
    (root / 'data').mkdir(parents=True)
    # Unmodified Subjects from ta1-trace-e3-official-1.bin.tar.gz, first
    # 200,000 records. Keep the release's original CDM18 Avro schema too.
    shutil.copyfile(HERE / 'fixtures/trace-no-args.bin.gz', root / 'data/sample.bin.gz')
    executable = root / 'ingest'
    executable.write_text((HERE / 'tc-e3-trace/ingest').read_text().replace(
        'sys.path.insert(0, str(Path(__file__).resolve().parents[1]))',
        f'sys.path.insert(0, {str(HERE.resolve())!r})'))
    database = tmp_path / 'commands.duckdb'
    argv = [sys.executable, str(executable), '--db', str(database)]
    subprocess.run(argv, capture_output=True, text=True, check=True)
    with duckdb.connect(str(database)) as con:
        before = con.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall()
        assert con.execute('SELECT pgm,args FROM COMMANDS ORDER BY pgm').fetchall() == [('-bash', []), ('groups', [])], 'Native CDM18 Subjects must retain executable-only argv'
        assert con.execute("SELECT count(*) FROM COMMANDS WHERE contains(record_id, '5325f54a-77b4-2309-3aa8-2df747293484')").fetchone()[0] == 1
        assert con.execute('SELECT count(*) FROM COMMANDS WHERE shell_input IS NOT NULL OR len(other_tokens)>0').fetchone()[0] == 0
    subprocess.run(argv, capture_output=True, text=True, check=True)
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT * FROM COMMANDS ORDER BY record_id').fetchall() == before
