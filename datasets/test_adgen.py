"""Native narrative fields pass through the real reader and database writer."""
import json
from pathlib import Path

import duckdb
from test_ingest_batches import invoke


def test_native_narratives_and_execution_identity(tmp_path):
    """Anonymized identifiers and publisher environment mistakes must not merge launches."""
    for environment in ['LAB', 'REAL']:
        (tmp_path/environment).mkdir()
        rows = [json.loads(line) for line in (Path(__file__).parent/f'fixtures/ad-gen/{environment}.jsonl').read_text().splitlines()]
        if environment == 'LAB':
            base = rows[2]
            launch = next(line for line in base['narrative'].splitlines() if '-> Event 1 (' in line)
            extra = dict(base, sample_id='multiple', narrative=launch+'\n'+launch+'\n'+launch.replace('T0 + 0.000s','T0 + 1.000s'), label={'verdict':'suspicious'})
            rows.append(extra)
        (tmp_path/environment/f'{environment}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
    database = tmp_path/'commands.duckdb'
    source = 'from _ingest_adgen import records\n'
    result = invoke(tmp_path, database, source)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute('SELECT record_id,pgm,args,label,group_id,session_id,shell_input,other_tokens FROM COMMANDS ORDER BY record_id').fetchall()
    assert not any('0000001' in r[0] for r in rows), 'File and pipe events must never create launches'
    assert any(r[0].startswith('REAL:ADGEN_0000003:') and 'REAL:' in r[5] for r in rows)
    assert any(r[0].startswith('LAB:ADGEN_0000003:') for r in rows)
    assert len([r for r in rows if ':multiple:' in r[0]]) == 2
    assert all(r[3]=='malicious' for r in rows if ':multiple:' in r[0])
    assert all(r[4] is None and r[6] is None and r[7]==[] for r in rows)
    assert all(not r[1].lower().endswith('svchost.exe') for r in rows), 'ParentCommandLine is context, never another launch'
    again = invoke(tmp_path, database, source)
    assert again.returncode == 0, again.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone()[0] == len(rows)


def test_adgen_verdicts_and_native_fields(tmp_path):
    """Missing judgments and non-launch text must not invent labels or commands."""
    rows=[]
    for sample,verdict in [(0,'benign'),('attack','malicious'),('suspect','suspicious'),('normal','benign'),('missing',None)]:
        row={'sample_id':sample,'narrative':'Entity shared initiated behavior.\n  [T0 + 0.000s] -> Event 1 (User: analyst): Process Create: | Image: C:\\Windows\\cmd.exe | CommandLine: cmd.exe /c echo hello | ParentCommandLine: ignored.exe', 'label': {'verdict':verdict}}
        rows.append(row)
    rows.append({'sample_id':'parent-only','narrative':'[T0 + 0.000s] -> Event 1 (User: analyst): Process Create: | Image: C:\\Windows\\cmd.exe | ParentCommandLine: ignored.exe', 'label':{'verdict':'malicious'}})
    for environment in ['LAB','REAL']:
        (tmp_path/environment).mkdir()
        (tmp_path/environment/f'{environment}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
    database=tmp_path/'commands.duckdb'
    result=invoke(tmp_path,database,'from _ingest_adgen import records\n')
    assert result.returncode==0,result.stderr
    with duckdb.connect(str(database)) as con:
        rows=con.execute('SELECT record_id,args,label FROM COMMANDS ORDER BY record_id').fetchall()
    assert len(rows)==10
    assert all(args==['/c','echo','hello'] for _,args,_ in rows), 'Narrative field parsing must not include ParentCommandLine or drop native arguments'
    assert [label for _,_,label in rows]==['benign','malicious','unknown','benign','malicious']*2
    assert rows[0][0]=='LAB:0:0'
