"""Join COMISET process annotations without retaining its terabyte of observations."""
import json
import re
import sqlite3
import tempfile
import zipfile
from dataclasses import asdict
from pathlib import Path

from _ingest import Command, select_files
from _ingest_windows import event_commands, json_fields, value


def _techniques(fields):
    return set(re.findall(r'\bT\d{4}(?:\.\d{3})?\b', ' '.join(
        str(v) for k,v in fields.items() if k.lower().replace('_','') in {'ruletechniqueid','rulename'})))


def _label(command, tags):
    if not tags:
        return 'benign'
    path = command.pgm.lower()
    args = [a.lower() for a in command.args]
    if tags == {'T1204'}:
        if re.fullmatch(r'c:\\users\\[^\\]+\\appdata\\local\\microsoft\\onedrive\\onedrive\.exe', path) and args == ['/background']:
            return 'benign'
        if path in {r'c:\program files\vmware\vmware tools\vmtoolsd.exe', r'c:\program files (x86)\vmware\vmware tools\vmtoolsd.exe'} and args == ['-n','vmusr']:
            return 'benign'
    if tags == {'T1047'} and path in {r'c:\windows\system32\wbem\wmiprvse.exe', r'c:\windows\syswow64\wbem\wmiprvse.exe'} and args == ['-secured','-embedding']:
        return 'benign'
    return 'malicious'


def records(root, options):
    """Collect process annotations on disk, then emit each observed launch once."""
    scratch = root/'tmp'
    scratch.mkdir(exist_ok=True)
    with (tempfile.TemporaryDirectory(dir=scratch, prefix='comiset-') as temporary,
          sqlite3.connect(str(Path(temporary)/'processes.sqlite')) as db):
        db.execute('CREATE TABLE launches (identity TEXT PRIMARY KEY, command TEXT NOT NULL, creation INTEGER NOT NULL)')
        db.execute('CREATE TABLE annotations (identity TEXT, technique TEXT, PRIMARY KEY(identity,technique))')
        count = 0
        for path in select_files(root.glob('*.zip'), options):
            with zipfile.ZipFile(path) as archive:
                for member in archive.namelist():
                    if not member.endswith('.json'):
                        continue
                    with archive.open(member) as stream:
                        for number, line in enumerate(stream,1):
                            if options.max_records is not None and count>=options.max_records:
                                break
                            count += 1
                            fields = json_fields(json.loads(line))
                            source = f'{path.name}/{member}'
                            guid = value(fields,'process_guid','ProcessGuid')
                            host = value(fields,'host_name','Computer')
                            identity = json.dumps([path.name,host,guid]) if guid else f'{source}:{number}'
                            for tag in _techniques(fields):
                                db.execute('INSERT OR IGNORE INTO annotations VALUES (?,?)',(identity,tag))
                            provider = value(fields,'source_name','Provider').lower()
                            event = value(fields,'event_id','EventID')
                            creation = ((provider=='microsoft-windows-sysmon' and event=='1')
                                        or (provider=='microsoft-windows-security-auditing' and event=='4688'))
                            # An identified process may lack its creation event in
                            # the export. Keep one command-bearing observation,
                            # replacing it if the actual launch appears later.
                            if not creation and not guid:
                                continue
                            for command in event_commands(fields,'comiset',source,number):
                                db.execute(
                                    'INSERT INTO launches VALUES (?,?,?) '
                                    'ON CONFLICT(identity) DO UPDATE SET command=excluded.command, creation=excluded.creation '
                                    'WHERE excluded.creation > launches.creation',
                                    (identity,json.dumps(asdict(command)),int(creation)))
            if options.max_records is not None and count>=options.max_records:
                break
        db.commit()
        for identity, data in db.execute('SELECT identity,command FROM launches ORDER BY identity'):
            command = Command(**json.loads(data))
            tags = {row[0] for row in db.execute('SELECT technique FROM annotations WHERE identity=?',(identity,))}
            command.label = _label(command,tags)
            command.group_id = None
            yield command
