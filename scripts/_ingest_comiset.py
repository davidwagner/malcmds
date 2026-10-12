"""Join COMISET process annotations without retaining its terabyte of observations."""
import json
import re
import sqlite3
import tempfile
import zipfile
from contextlib import closing
from dataclasses import asdict
from itertools import islice
from pathlib import Path

from _ingest import Command, select_files
from _ingest_parallel import ordered_records
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
        lines = _lines(select_files(root.glob('*.zip'), options), options.max_records)
        workers = getattr(options, 'workers', 6)
        if options.max_records is not None or getattr(options, 'limit', None) is not None:
            workers = 1
        observations = ordered_records(_observations, _batches(lines), workers, scratch, 'comiset')
        with closing(lines), closing(observations):
            for identity, tags, commands, creation in observations:
                for tag in tags:
                    db.execute('INSERT OR IGNORE INTO annotations VALUES (?,?)', (identity, tag))
                for command in commands:
                    db.execute(
                        'INSERT INTO launches VALUES (?,?,?) '
                        'ON CONFLICT(identity) DO UPDATE SET command=excluded.command, creation=excluded.creation '
                        'WHERE excluded.creation > launches.creation',
                        (identity, json.dumps(asdict(command)), int(creation)))
        db.commit()
        for identity, data in db.execute('SELECT identity,command FROM launches ORDER BY identity'):
            command = Command(**json.loads(data))
            tags = {row[0] for row in db.execute('SELECT technique FROM annotations WHERE identity=?',(identity,))}
            command.label = _label(command,tags)
            command.group_id = None
            yield command


def _lines(paths, max_records):
    count = 0
    for path in paths:
        with zipfile.ZipFile(path) as archive:
            for member in archive.namelist():
                if not member.endswith('.json'):
                    continue
                source = f'{path.name}/{member}'
                with archive.open(member) as stream:
                    for number, line in enumerate(stream, 1):
                        if max_records is not None and count >= max_records:
                            return
                        count += 1
                        yield path.name, source, number, line
        if max_records is not None and count >= max_records:
            return


def _batches(lines):
    # The release has just two huge JSON members. Split their parsing across
    # workers, bounding raw input memory independently of the DB batch size.
    while batch := list(islice(lines, 1000)):
        yield (batch,)


def _observations(lines):
    for archive, source, number, line in lines:
        fields = json_fields(json.loads(line))
        guid = value(fields, 'process_guid', 'ProcessGuid')
        host = value(fields, 'host_name', 'Computer')
        identity = json.dumps([archive, host, guid]) if guid else f'{source}:{number}'
        tags = _techniques(fields)
        provider = value(fields, 'source_name', 'Provider').lower()
        event = value(fields, 'event_id', 'EventID')
        creation = ((provider == 'microsoft-windows-sysmon' and event == '1')
                    or (provider == 'microsoft-windows-security-auditing' and event == '4688'))
        # Preserve a fallback observation until its actual launch appears.
        commands = list(event_commands(fields, 'comiset', source, number)) if creation or guid else []
        if tags or commands:
            yield identity, tags, commands, creation
