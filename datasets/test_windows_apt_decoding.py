"""CSV export decoding through the real reader and DuckDB writer."""
import csv
import json
from pathlib import Path

import duckdb
from test_ingest_batches import invoke


def test_published_powershell_and_single_pass_exports(tmp_path):
    """Windows tokenizer upgrades must preserve complete scripts and literal escapes."""
    published = json.loads((Path(__file__).parent / 'fixtures/windows-apt/powershell.json').read_text())
    prefix = '_source.data.win.eventdata.'
    rows = [published]
    cases = [
        ('short', 'cmd.exe /c echo hello', 'cmd.exe', ['/c', 'echo', 'hello']),
        ('entities', 'cmd.exe /c echo &amp;lt;', 'cmd.exe', ['/c', 'echo', '&lt;']),
        ('pipe', r'helper.exe \\.\pipe\test', 'helper.exe', [r'\\.\pipe\test']),
        ('quoted', r'helper.exe "hello \"world\""', 'helper.exe', ['hello "world"']),
        ('malformed', r'helper.exe C:\bad\q', 'helper.exe', [r'C:\bad\q']),
    ]
    for rid, command, image, _ in cases:
        encoded = command if rid == 'malformed' else json.dumps(command)[1:-1]
        rows.append({'_id': rid, prefix+'commandLine': encoded, prefix+'image': json.dumps(image)[1:-1]})
    (tmp_path/'source').mkdir()
    fields = sorted(set().union(*(r.keys() for r in rows)))
    with (tmp_path/'source/combined.csv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    database = tmp_path/'commands.duckdb'
    source = 'from _ingest_misc import windows_apt as records\n'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        output = con.execute('SELECT record_id,pgm,args,shell_input,other_tokens FROM COMMANDS').fetchall()
    result_by_id = {row[0]: row[1:] for row in output}
    real = result_by_id['wazuh-alerts-4.x-2024.12.01:xaGygZMBrrvr6pEbHntA:0']
    assert real[0] == r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    assert real[1][:3] == ['-ExecutionPolicy', 'Bypass', '-C']
    expected = json.loads('"'+published[prefix+'commandLine']+'"').split(' -C ',1)[1][1:-1].replace('\\"', '"')
    assert real[1][3:] == [expected], 'The published PowerShell script must remain one argument'
    for rid, _, program, args in cases:
        assert result_by_id[':'+rid+':0'] == (program, args, None, [])
    again = invoke(tmp_path, database, source)
    assert again.returncode == 0, again.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone()[0] == len(rows)
