"""Use reviewed source launch evidence to label the retained ATLAS execution."""
import csv
import io
import json
import tarfile
from pathlib import Path

import duckdb
from test_ingest_batches import invoke


def test_reviewed_browser_starts_and_attack_commands(tmp_path):
    """Later attack-process labels must not relabel a verified ordinary browser start."""
    tmp_path = tmp_path/'atlasv2'
    tmp_path.mkdir()
    fixtures = Path(__file__).parent/'fixtures/atlas-browser'
    reviewed = json.loads((fixtures/'reviewed-starts.json').read_text())
    (tmp_path/'reapr/atlasv2').mkdir(parents=True)
    groups = {}
    attacks = set()
    for row in reviewed:
        launch, interaction = row['launch'], row['interaction']
        assert launch['type']=='endpoint.event.procstart' and launch['target_cmdline'].strip()
        assert launch['device_timestamp'] < interaction['device_timestamp']
        assert launch['childproc_guid']==interaction['process_guid']
        groups.setdefault(row['scenario'],[]).extend([launch,interaction])
        attacks.add(row['guid'])
    extras = json.loads((fixtures/'attack-launches.json').read_text())
    groups['h1-s4'].extend(extras)
    for row in extras:
        attacks.add(row['childproc_guid'])
    with (tmp_path/'reapr/atlasv2/test.labels').open('w') as stream:
        writer=csv.writer(stream);writer.writerow(['process_uuid','label'])
        writer.writerows((guid,'attack') for guid in sorted(attacks))
    with tarfile.open(tmp_path/'atlasv2.tar.gz','w:gz') as archive:
        for scenario, rows in groups.items():
            data=''.join(json.dumps(row)+'\n' for row in rows).encode()
            member=tarfile.TarInfo(f'atlasv2/data/attack/{scenario[:2]}/cbc-edr/edr-{scenario}.jsonl');member.size=len(data)
            archive.addfile(member,io.BytesIO(data))
    database=tmp_path/'commands.duckdb'
    source='from _ingest_windows import atlasv2 as records\n'
    result=invoke(tmp_path,database,source)
    assert result.returncode==0,result.stderr
    with duckdb.connect(str(database)) as con:
        rows=con.execute('SELECT pgm,args,label,group_id FROM COMMANDS').fetchall()
    assert sum(label=='benign' for _,_,label,_ in rows)>=len(reviewed)
    assert all(label=='malicious' for pgm,args,label,_ in rows if pgm.lower().endswith(('payload.exe','cmd.exe')))
    assert all(label=='malicious' for pgm,args,label,_ in rows if args and pgm.lower().endswith('firefox.exe'))
    assert all(group is None for _,_,label,group in rows if label in ('benign','malicious'))


def test_known_uuid_does_not_exempt_changed_command(tmp_path):
    """A reviewed UUID cannot make an attack URL or renamed binary benign."""
    from _ingest_atlas_labels import BROWSER_STARTS

    guid = next(g for g, evidence in BROWSER_STARTS.items() if evidence[0]=='h1-s4')
    records = [
        {'process_guid': guid, '_reapr_attack': True,
         'process_path': r'C:\Program Files\Mozilla Firefox\firefox.exe',
         'process_cmdline': r'"C:\Program Files\Mozilla Firefox\firefox.exe" https://attack.invalid/'},
        {'process_guid': guid, '_reapr_attack': True,
         'process_path': r'C:\Users\Public\firefox.exe',
         'process_cmdline': r'C:\Users\Public\firefox.exe'},
    ]
    source = f"from _ingest_windows import event_commands\ndef records(root,options):\n    for i,row in enumerate({records!r}):\n        yield from event_commands(row,'atlasv2','edr-h1-s4.jsonl',i)\n"
    database=tmp_path/'commands.duckdb'
    result=invoke(tmp_path,database,source)
    assert result.returncode==0,result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute('SELECT label,group_id FROM COMMANDS').fetchall()==[('malicious',None),('malicious',None)]
