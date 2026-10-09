"""COMISET labels derive from all events of each actual process launch."""
import json
import zipfile
from pathlib import Path

import duckdb
from test_ingest_batches import invoke


def test_native_comiset_environments_and_process_annotations(tmp_path):
    """Later annotations must survive deduplication and override routine-only exceptions."""
    examples={}
    for environment in ['LAB','REAL']:
        native=json.loads((Path(__file__).parent/f'fixtures/comiset/{environment}.json').read_text())
        rows=[entry['record'] for entry in native.values()]
        examples[environment]=native
        if environment=='LAB':
            original=native['onedrive.exe']['record']
            repeated=json.loads(json.dumps(original)); repeated['_id']='duplicate-observation'
            rows.append(repeated)
            # A distinct process with the same normal launch, then attack-specific behavior.
            launch=json.loads(json.dumps(original)); launch['_id']='attack-process'; launch['_source']['process_guid']='other-process'
            event=json.loads(json.dumps(launch)); event['_source']['event_id']='11';event['_source']['rule_technique_id']='T1055';event['_source'].pop('CommandLine',None)
            rows.extend([launch,event])
            fallback=json.loads(json.dumps(original)); fallback['_id']='fallback-only'; fallback['_source']['process_guid']='fallback'; fallback['_source']['event_id']='11'
            rows.extend([fallback,fallback])
            before=json.loads(json.dumps(fallback)); before['_id']='earlier-observation'; before['_source']['process_guid']='creation-preferred'
            created=json.loads(json.dumps(before)); created['_id']='actual-creation';created['_source']['event_id']='1'
            rows.extend([before,created])
        with zipfile.ZipFile(tmp_path/f'{environment}.zip','w') as archive:
            archive.writestr('events.json',''.join(json.dumps(r)+'\n' for r in rows))
    database=tmp_path/'commands.duckdb'
    result=invoke(tmp_path,database,'from _ingest_comiset import records\n')
    assert result.returncode==0,result.stderr
    with duckdb.connect(str(database)) as con:
        rows=con.execute('SELECT record_id,pgm,args,label,group_id,shell_input,other_tokens FROM COMMANDS').fetchall()
    assert len(rows)==sum(len(r) for r in examples.values())+3
    assert any('fallback-only' in r[0] for r in rows)
    assert any('actual-creation' in r[0] for r in rows)
    assert not any('earlier-observation' in r[0] for r in rows)
    assert all(r[4] is None and r[5] is None and r[6]==[] for r in rows)
    assert next(r[3] for r in rows if 'attack-process' in r[0])=='malicious'
    assert any(r[3]=='benign' and r[1].lower().endswith('onedrive.exe') for r in rows)
    assert any(r[3]=='benign' and r[1].lower().endswith('vmtoolsd.exe') for r in rows)
    assert any(r[3]=='malicious' for r in rows if 'REAL.zip' in r[0])
    again=invoke(tmp_path,database,'from _ingest_comiset import records\n')
    assert again.returncode==0,again.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT count(*) FROM COMMANDS').fetchone()[0]==len(rows)
