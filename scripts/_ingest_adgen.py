"""Read native process-creation fields from AD-GEN's derived narratives."""

import json
import re

from _ingest import Command, normalize, select_files

_EVENT = re.compile(r'^\s*\[([^\]]+)\] -> Event 1 \([^\n]*?\): (.*)$', re.MULTILINE)
_FIELDS = re.compile(r'(?:^| \| )([A-Z][A-Za-z0-9]*): ')


def records(root, options):
    """Import explicit launches, keeping LAB and REAL identifiers separate."""
    paths = [root/'LAB/LAB.jsonl', root/'REAL/REAL.jsonl']
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        raise FileNotFoundError('Missing AD-GEN files: ' + ', '.join(missing))
    count = 0
    for path in select_files(paths, options):
        environment = path.parent.name
        with path.open(encoding='utf-8') as stream:
            for number, line in enumerate(stream, 1):
                if options.max_records is not None and count >= options.max_records:
                    return
                count += 1
                row = json.loads(line)
                narrative = row.get('narrative', '')
                sample = row.get('sample_id')
                if sample is None or sample == '':
                    sample = str(number)
                judgment = row.get('label') or {}
                verdict = judgment.get('verdict', '')
                label = {'malicious': 'malicious', 'suspicious': 'malicious', 'benign': 'benign'}.get(verdict, 'unknown')
                entity = re.match(r'Entity (.*?) initiated ', narrative)
                session = f'ad-gen:{environment}:' + (entity[1] if entity else str(sample))
                seen = set()
                for occurrence, match in enumerate(_EVENT.finditer(narrative)):
                    timestamp, description = match.groups()
                    matches = list(_FIELDS.finditer(description))
                    fields = {field[1]: description[field.end():matches[i+1].start() if i+1<len(matches) else len(description)].strip()
                              for i, field in enumerate(matches)}
                    command = fields.get('CommandLine')
                    image = fields.get('Image')
                    if not command or not image:
                        continue
                    identity = fields.get('EventRecordID') or (timestamp, fields.get('ProcessGuid'), fields.get('ProcessId'), image, command)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    for pgm, args in normalize(command, os='windows', pgm=image):
                        result = label
                        installed = pgm.lower() in {r'c:\program files\mozilla firefox\firefox.exe', r'c:\program files (x86)\mozilla firefox\firefox.exe'}
                        # Some supplied verdicts say suspicious while the accompanying
                        # judgment explicitly describes a normal, low-risk browser start.
                        if (installed and not args and judgment.get('risk_level') == 'Low'
                                and judgment.get('mitre_techniques') == ['None']
                                and re.search(r'executed normally|normal user execution|standard, benign user execution', judgment.get('summary', ''), re.IGNORECASE)):
                            result = 'benign'
                        yield Command(pgm, args, f'{environment}:{sample}:{occurrence}', result, None, session, 'windows')
