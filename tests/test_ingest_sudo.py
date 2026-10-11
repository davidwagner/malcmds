"""Native sudo command records ingested into real DuckDB storage."""
import csv
import json
import shlex
from pathlib import Path
from types import SimpleNamespace

import duckdb
import openpyxl
from _ingest import Command, _initialize, _insert, command_table
from _ingest_misc import linux_apt, sudo_command_argv


def test_published_linux_apt_sudo_commands(tmp_path):
    """All 259 previously unparseable scripts retain one script argument."""
    rows = json.loads((Path(__file__).parent / "fixtures/sudo/linux-apt.json").read_text())
    source = tmp_path / "source"
    source.mkdir()
    with (source / "combine.csv").open("w") as output:
        writer = csv.DictWriter(output, fieldnames=["_index", *sorted({k for r in rows for k in r} - {"_index"})])
        writer.writeheader()
        writer.writerows(rows)
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "combined"
    sheet.append(["timestamp", "agent.name", "full_log", "rule.description", "Malicious / General"])
    for row in rows:
        if row['expected_label'] != 'unknown':
            sheet.append([row.get('_source.timestamp'), row.get('_source.agent.name'),
                          row.get('_source.full_log'), row.get('_source.rule.description'),
                          int(row['expected_label'] == 'malicious')])
    workbook.save(source / "Processed Version.xlsx")
    commands = list(linux_apt(tmp_path, SimpleNamespace(max_records=None)))
    by_id = {c.record_id: c for c in commands}
    failures = 0
    for row in rows:
        text = row['_source.full_log'].split('COMMAND=', 1)[1]
        try:
            shlex.split(text)
        except ValueError:
            failures += 1
            command = by_id[row['_index'] + ':' + row['_id'] + ':0']
            assert len(command.args) == 2 and command.args[0] == '-c'
    assert failures == 259, "Published sudo serialization changed; review the script examples"
    assert len(commands) == 1212
    for row in rows:
        assert by_id[row['_index'] + ':' + row['_id'] + ':0'].label == row['expected_label']
    with duckdb.connect(str(tmp_path / 'commands.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(commands, 'linux-apt-2024'))
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone()[0] == 1212
        assert con.execute('SELECT count(*) FROM COMMANDS WHERE shell_input IS NOT NULL OR other_tokens != []').fetchone()[0] == 0


def test_sudo_serialization_roundtrip_storage(tmp_path):
    """Quoted scripts, positional arguments, literal quotes and octal controls survive."""
    examples = [
        (r'''sh -c 'echo "$1"' name value''', ['sh', '-c', 'echo "$1"', 'name', 'value']),
        (r'''echo 'a\'b \\c' '' #011''', ['echo', "a'b \\c", '', '\t']),
        ("echo 'unfinished script", ['echo', 'unfinished script']),
        (r'echo a\q', ['echo', r'a\q']),
        ('echo #07 #0177', ['echo', '\x07', '\x7f']),
        ('', []),
    ]
    commands = []
    for i, (text, expected) in enumerate(examples):
        argv = sudo_command_argv(text)
        assert argv == expected
        if argv:
            commands.append(Command(argv[0], argv[1:], str(i)))
    with duckdb.connect(str(tmp_path / 'controls.duckdb')) as con:
        _initialize(con)
        _insert(con, command_table(commands, 'linux-apt-2024'))
        assert con.execute('SELECT args FROM COMMANDS ORDER BY record_id').fetchall() == [(e[1:],) for _, e in examples if e]
