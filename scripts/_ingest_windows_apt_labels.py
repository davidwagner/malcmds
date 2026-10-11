"""Label Windows-APT events using specific operations, provenance and alert defaults."""

from __future__ import annotations

import csv
import html
import json
import ntpath
import re
from collections.abc import Mapping, Sequence
from itertools import islice
from typing import Literal

from _ingest import normalize, windows_split

PREFIX = "_source.data.win.eventdata."
WAZUH = r"c:\program files (x86)\ossec-agent\wazuh-agent.exe"
VMWARE = r"c:\program files\vmware\vmware tools\vmtoolsd.exe"
SYSTEM32 = "c:\\windows\\system32\\"
SYSWOW64 = "c:\\windows\\syswow64\\"
ACCOUNT_QUERIES = {("accounts",), ("user", "administrator"), ("user", "guest")}


def decode_windows_apt_field(raw: str, *, json_contents: bool, html_entities: bool) -> str:
    """Decode the CSV field's known export layers once, preserving malformed JSON."""
    if json_contents:
        try:
            raw = json.loads('"' + raw + '"')
        except json.JSONDecodeError:
            pass
    return html.unescape(raw) if html_entities else raw


def _field(row, name):
    return decode_windows_apt_field(
        row.get(PREFIX + name, "").strip(), json_contents=True, html_entities=True
    )


def _path(text):
    return ntpath.normcase(ntpath.normpath(text))


def _identity(row, field):
    host = row.get("_source.data.win.system.computer", "").strip().lower()
    guid = row.get(PREFIX + field, "").strip().lower()
    if host and re.fullmatch(r"\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}", guid) and guid.strip("{}0-"):
        return host, guid
    return None


def _launch(row):
    if (row.get("_source.data.win.system.providerName", "").strip().lower()
            != "microsoft-windows-sysmon"
            or row.get("_source.data.win.system.eventID", "").strip() != "1"):
        return None
    command = _field(row, "commandLine")
    parsed = normalize(command, os="windows")
    if len(parsed) != 1:
        return None
    program, args = parsed[0]
    return _path(_field(row, "image")), _path(_field(row, "parentImage")), _path(program), tuple(arg.lower() for arg in args), command


def _direct(launch):
    image, parent, program, args, command = launch
    if (parent == WAZUH and image in {SYSTEM32 + "net.exe", SYSWOW64 + "net.exe"}
            and program in {"net", "net.exe", SYSTEM32 + "net.exe", SYSWOW64 + "net.exe"}
            and args in ACCOUNT_QUERIES):
        return "wazuh", image, args
    if (parent == VMWARE and image == SYSTEM32 + "cmd.exe"
            and program == image):
        # cmd /c uses a second pair of quotes around a script path with spaces.
        text = command.replace("\\\\", "\\").lower()
        for action in ("poweron", "poweroff", "suspend", "resume"):
            expected = (SYSTEM32 + 'cmd.exe /c ""c:\\program files\\vmware\\vmware tools\\'
                        + action + '-vm-default.bat""')
            if text == expected:
                return "vmware", image, ("/renew" if action in {"poweron", "resume"} else "/release",)
    defender = parent == r"c:\program files\windows defender\msmpeng.exe" or re.fullmatch(
        r"c:\\programdata\\microsoft\\windows defender\\platform\\[0-9.]+-[0-9]+\\msmpeng\.exe", parent
    )
    if defender and image == SYSTEM32 + "svchost.exe" and program == image and not args:
        return "defender", image, args
    return None


def infrastructure_parents(path, max_records):
    """Collect exact observed parent identities within the requested input prefix.

    The second pass can then recognize helpers even when the CSV puts children
    first. Only direct Wazuh checks and VMware lifecycle scripts authorize helpers.
    """
    parents = {}
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for row in islice(csv.DictReader(stream), max_records):
            identity = _identity(row, "processGuid")
            launch = _launch(row)
            direct = _direct(launch) if launch else None
            if identity and direct and direct[0] in {"wazuh", "vmware"}:
                parents[identity] = direct
    return parents


def is_infrastructure(row, parents):
    """Identify exact collection/defense launches and their expected helper calls."""
    launch = _launch(row)
    if not launch:
        return False
    if _direct(launch):
        return True
    image, parent, program, args, _ = launch
    origin = parents.get(_identity(row, "parentProcessGuid"))
    if not origin:
        return False
    kind, parent_image, expected_args = origin
    if parent != parent_image or args != expected_args:
        return False
    if kind == "wazuh":
        return (image == ntpath.dirname(parent_image) + "\\net1.exe"
                and program in {SYSTEM32 + "net1", SYSTEM32 + "net1.exe",
                                SYSWOW64 + "net1", SYSWOW64 + "net1.exe"})
    return image == SYSTEM32 + "ipconfig.exe" and program in {SYSTEM32 + "ipconfig", SYSTEM32 + "ipconfig.exe"}


# These defaults describe this collection, not ATT&CK techniques in general.
Label = Literal["malicious", "benign", "unknown"]
ParentMap = Mapping[tuple[str, str], tuple[str, str, tuple[str, ...]]]

RULE_DEFAULTS: dict[str, Label] = {
    **dict.fromkeys(('61620', '92024', '92029', '92041', '92046', '92056', '92074'), 'malicious'),
    **dict.fromkeys(('61640', '92000', '92031', '92033', '92036', '92039', '92055', '92057', '92076'), 'benign'),
    **dict.fromkeys(('61618', '61625', '92004', '92005', '92006', '92021', '92027', '92032', '92043', '92052', '92066'), 'unknown'),
}
TAG_DEFAULTS: dict[str, Label] = {
    **dict.fromkeys(('T1003.002', 'T1027', 'T1105', 'T1112'), 'malicious'),
    **dict.fromkeys(('T1059.005', 'T1218', 'T1546', 'T1574.001'), 'benign'),
}
RDP_KEY = r'hklm\system\currentcontrolset\control\terminal server\winstations\rdp-tcp'
EXPLORER_KEY = r'hklm\software\microsoft\windows\currentversion\explorer\mycomputer' + '\\'
POLICIES_KEY = r'hkcu\software\microsoft\windows\currentversion\policies' + '\\'
MARKER_VALUE = ('U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0'
                'IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI=').lower()
LOG_EXPORT = ("get-eventlog 'security' | where {$_.message -like '*system*'} | "
              r'export-csv $env:temp\t1654_events.txt')


def _tag_decision(tags: Sequence[str]) -> Label:
    decisions = [TAG_DEFAULTS.get(tag, 'unknown') for tag in tags]
    if 'malicious' in decisions:
        return 'malicious'
    return 'benign' if decisions and all(d == 'benign' for d in decisions) else 'unknown'


def windows_apt_label(row: Mapping[str, str], command: str, parents: ParentMap) -> Label:
    """Label a decoded event using infrastructure, operations, rules, then tags.

    An explicit unknown operation or mapped rule ends the decision. Only an
    absent rule falls back to tags. Inventory observations bypass this function.
    """
    if is_infrastructure(row, parents):
        return 'benign'
    decision = _command_decision(row, command)
    if decision is not None:
        return decision
    rule = row.get('_source.rule.id', '').strip()
    if rule in RULE_DEFAULTS:
        return RULE_DEFAULTS[rule]
    return _tag_decision(re.findall(r'(?<![\w.])T\d{4}(?:\.\d{3})?(?![\w.])', row.get('_source.rule.mitre.id', '')))


def _registry_key(key):
    key = key.lower().replace('hkey_local_machine', 'hklm').replace('hkey_current_user', 'hkcu')
    return key.replace('hkey_classes_root', 'hkcr').replace(':\\', '\\')


def _registry_decision(args):
    if len(args) < 2:
        return 'unknown'
    action, key = args[:2]
    key = _registry_key(key)
    if action in {'save', 'export'} and key in {r'hklm\sam', r'hklm\security', r'hklm\system'}:
        return 'malicious'
    if action == 'query':
        return 'benign'
    if action != 'add':
        return 'unknown'
    options = {}
    i = 2
    while i < len(args):
        flag = args[i]
        if flag in {'/f', '-f', '/ve'}:
            options[flag] = ''
            i += 1
        elif flag in {'/v', '/t', '/d'} and i + 1 < len(args) and flag not in options:
            options[flag] = args[i + 1]
            i += 2
        else:
            return 'unknown'
    value, data, kind = options.get('/v', ''), options.get('/d'), options.get('/t', 'reg_sz')
    if data is None:
        return 'unknown'
    if key == RDP_KEY and kind == 'reg_dword':
        if value == 'userauthentication':
            return {'0': 'malicious', '1': 'benign'}.get(data, 'unknown')
        if value == 'portnumber':
            return 'benign' if data == '3389' else 'unknown'
    benign_values = {
        (r'hkcu\environment', 'appx_process', 'reg_expand_sz'): '1',
        (r'hklm\system\currentcontrolset\services\lanmanserver\parameters', 'maxmpxct', 'reg_dword'): '65535',
        (r'hkcu\software\classes\atomicredteam', 'art', 'reg_sz'): MARKER_VALUE,
        (EXPLORER_KEY + 'backuppath', '', 'reg_expand_sz'): r'c:\windows\system32\sdclt.exe',
        (EXPLORER_KEY + 'cleanuppath', '', 'reg_expand_sz'): r'c:\windows\system32\cleanmgr.exe /d %%c',
    }
    data = data.replace('%%systemroot%%', r'c:\windows').replace('%systemroot%', r'c:\windows')
    if benign_values.get((key, value, kind)) == data:
        return 'benign'
    if key in {POLICIES_KEY + 'explorer', POLICIES_KEY + 'system'}:
        return 'unknown'
    if (key == r'hklm\software\microsoft\windows\currentversion\policies\system'
            and value == 'consentpromptbehavioradmin' and kind == 'reg_dword' and data == '0'):
        return 'malicious'
    if (key.startswith('hklm\\system\\currentcontrolset\\services\\') and value == 'imagepath'
            and re.search(r'(?:^|\\)cmd\.exe(?:\s|$)', data)):
        return 'malicious'
    if (key.endswith((r'\shell\open\command', r'\inprocserver32'))
            or key.startswith(EXPLORER_KEY)
            or re.search(r'\\currentversion\\run(?:onceex|once)?(?:\\|$)', key)
            or (key == r'hkcu\environment' and value in {'userinitmprlogonscript', 'windir'})
            or r'\accessibility\ats' in key
            or r'\appcompatflags\telemetrycontroller' in key
            or (key.endswith(r'\terminal server\wds\rdpwd') and value == 'startupprograms')
            or (r'\print processors\atomicredteam' in key and value == 'driver')):
        return 'malicious'
    return None


def _operations(text, powershell):
    """Split visible shell operations without splitting quoted argument data.

    This is a bounded recognizer for the observed syntax. Unsupported constructs
    stay unknown; payloads are never evaluated or launched.
    """
    parts, start, quote, escaped = [], 0, '', False
    for i, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == ('`' if powershell else '^'):
            escaped = True
        elif quote:
            if char == quote:
                quote = ''
        elif char == '"' or (powershell and char == "'"):
            quote = char
        elif char in (';&|\n' if powershell else '&|\n'):
            part = text[start:i].strip()
            if part:
                parts.append(part)
            start = i + 1
    parts.append(text[start:].strip())
    return parts, bool(quote or escaped)


def _powershell_payload(args):
    """Return visible or decoded script text; None denotes unsupported options."""
    import base64
    import binascii

    i = 0
    while i < len(args):
        flag = args[i].lower()
        if flag in {'-e', '-ec', '-enc', '-encodedcommand'}:
            if i + 1 >= len(args):
                return None
            # The source sometimes includes serialization options after encoding.
            tail = tuple(a.lower() for a in args[i + 2:])
            if tail not in {(), ('-inputformat', 'xml', '-outputformat', 'text')}:
                return None
            try:
                return base64.b64decode(args[i + 1], validate=True).decode('utf-16-le')
            except (ValueError, binascii.Error, UnicodeError):
                return None
        if flag in {'-c', '-command'}:
            return ' '.join(args[i + 1:]) or None
        if flag in {'-noprofile', '-nop', '-nologo', '-noninteractive', '-noexit'}:
            i += 1
        elif flag in {'-executionpolicy', '-ep', '-windowstyle', '-w', '-version'} and i + 1 < len(args):
            i += 2
        elif flag.startswith('-'):
            return None
        else:
            return ' '.join(args[i:])
    return None


def _combine(decisions):
    if 'malicious' in decisions:
        return 'malicious'
    return 'benign' if decisions and all(d == 'benign' for d in decisions) else 'unknown'


def _expressions(text):
    """Find PowerShell argument expressions, respecting literal single quotes.

    Unknown expressions prevent a benign result. A recognizable attack inside
    an expression still supplies evidence, including inside interpolated strings.
    """
    expressions, visible, quote, escaped, start, nesting, copied = [], [], '', False, 0, 0, 0
    for i, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == '`' and quote != "'":
            escaped = True
        elif nesting:
            if char == '(':
                nesting += 1
            elif char == ')':
                nesting -= 1
                if not nesting:
                    expressions.append(text[start:i])
                    copied = i + 1
        elif char == quote:
            quote = ''
        elif char in {'"', "'"} and not quote:
            quote = char
        elif char == '(' and (not quote or (quote == '"' and i and text[i - 1] == '$')):
            visible.append(text[copied:i - 1] if i and text[i - 1] == '$' else text[copied:i])
            visible.append('unresolved-expression')
            start, nesting = i + 1, 1
    if nesting:
        expressions.append('')
        copied = len(text)
    visible.append(text[copied:])
    return expressions, ''.join(visible)


def _command_decision(row: Mapping[str, str], command: str) -> Label | None:
    rule = row.get('_source.rule.id', '').strip()
    parent = _field(row, 'parentCommandLine').lower()
    # Context precedes harmless child recognition, as required by issue #115.
    if rule == '92046' and _path(_field(row, 'parentImage')) == SYSTEM32 + 'fodhelper.exe':
        return 'malicious'
    if rule == '92056' and _verified_uac_parent(parent):
        return 'malicious'
    return _visible_decision(command)


def _verified_uac_parent(parent):
    """Match the complete four-operation ms-settings bypass in this export."""
    tokens = windows_split(parent)
    if not tokens or ntpath.basename(tokens[0]) not in {'powershell', 'powershell.exe'}:
        return False
    payload = _powershell_payload(tokens[1:])
    if payload is None:
        return False
    operations, malformed = _operations(payload, True)
    parsed = [windows_split(operation) for operation in operations]
    key = r'hkcu:\software\classes\ms-settings\shell\open\command'
    setup = [
        ['new-item', key, '-force'],
        ['new-itemproperty', key, '-name', 'delegateexecute', '-value', '', '-force'],
        ['set-itemproperty', key, '-name', '(default)', '-value', SYSTEM32 + 'cmd.exe', '-force'],
    ]
    return (not malformed and len(parsed) == 4 and parsed[:3] == setup
            and parsed[3] in [['start-process', SYSTEM32 + 'fodhelper.exe'],
                              ['start-process', SYSTEM32 + 'computerdefaults.exe']])


def _visible_decision(text, *, powershell=False, shell=False, depth=0):
    if depth > 12:
        return 'unknown'
    text = text.strip()
    # This exact observed pipeline exports local logs, including its filter/output.
    if powershell and ' '.join(text.lower().split()) == LOG_EXPORT:
        return 'benign'
    # Discard only the observed suppression redirects, retaining all operations.
    text = re.sub(r'(?i)(?:[12]?\s*>\s*nul\b|2\s*>\s*&1)', '', text)
    if powershell:
        # This is the complete observed SAM-copy exercise, including its loop.
        sam_copy = (r'1..10 | %% { ; try { [system.io.file]::copy("\\?\globalroot\device\harddiskvolumeshadowcopy$_\windows\system32\config\sam" , '
                    r'"$env:temp\samvss$_", "true") } catch {}; ls "$env:temp\samvss$_" -erroraction ignore; }')
        if ' '.join(text.lower().split()) == sam_copy:
            return 'malicious'
    if shell or powershell:
        parts, malformed = _operations(text, powershell)
        if len(parts) > 1:
            decisions = [_visible_decision(part, powershell=powershell, shell=shell, depth=depth + 1) for part in parts]
            if malformed:
                decisions.append('unknown')
            return _combine(decisions)
        if malformed:
            return 'unknown'
        if powershell:
            expressions, visible = _expressions(text)
            if expressions:
                return _combine(['unknown', *[
                    _visible_decision(part, powershell=True, depth=depth + 1)
                    for part in [visible, *expressions]
                ]])
    tokens = windows_split(text)
    if not tokens:
        return 'unknown'
    program = _path(tokens[0])
    name = ntpath.basename(program).removesuffix('.exe')
    # Unwrap cmd before splitting: /c "a & b" executes both operations.
    if name == 'cmd':
        match = re.match(r'(?is)^\s*(?:"[^"]+"|\S+)\s+(?:/[dq]\s+)*/[ck]\s+(.*)$', text)
        if match:
            payload = match[1].strip()
            if payload.startswith('"') and payload.endswith('"'):
                payload = payload[1:-1]
            return _visible_decision(payload, shell=True, depth=depth + 1) or 'unknown'
    if name in {'powershell', 'pwsh'}:
        payload = _powershell_payload(tokens[1:])
        if payload is None:
            # Visible disguised scripts are recognizable even with -File.
            if any(re.fullmatch(r'(?i).*t1036\.003_masquerading\.(doc|pdf|rtf)\.ps1', a) for a in tokens[1:]):
                return 'malicious'
            return 'unknown'
        return _visible_decision(payload, powershell=True, depth=depth + 1) or 'unknown'
    if powershell:
        assignment = re.fullmatch(r'\$[a-zA-Z_][\w]*\s*=\s*(.+)', text)
        if assignment:
            # Recognize a command's captured output, not quoted strings as code.
            value = assignment[1]
            if not value.startswith(('"', "'")):
                return _visible_decision(value, powershell=True, depth=depth + 1) or 'unknown'
            return 'unknown'
    if powershell and tokens[0] == '.' and len(tokens) == 2:
        return _visible_decision(tokens[1], powershell=True, depth=depth + 1)
    args = [a.lower() for a in tokens[1:]]
    if powershell and name in {'invoke-maldoc', 'bypass-uac'} and args:
        return 'malicious'
    if name == 'del':
        targets = [a for a in args if a not in {'/f', '/q'}]
        if len(targets) == 1 and targets[0] in {
            r'c:\users\public\music\allthethingsx64.dll', r'c:\programdata\allthethingsx64.dll',
            r'%%temp%%\allthethingsx64.dll', r'c:\inetpub\wwwroot\b.jsp',
            r'c:\inetpub\wwwroot\tests.jsp', r'c:\inetpub\wwwroot\cmd.aspx',
            r'%%appdata%%\updater.exe', r'%%appdata%%\amsi.dll',
        }:
            return 'benign'
    if name == 'reg':
        return _registry_decision(args)
    if name in {'net', 'net1'}:
        if args == ['user', 'guest', '/active:no']:
            return 'benign'
        if args == ['user', 'guest', '/active:yes'] or args == ['stop', 'termservice', '/y']:
            return 'unknown'
        if args and args[0] in {'user', 'accounts', 'group', 'groups', 'localgroup', 'session', 'view'}:
            if len([a for a in args[1:] if not a.startswith('/')]) <= 1 and all(
                not a.startswith('/') or a in {'/domain', '/doma', '/domai'} for a in args[1:]
            ):
                return 'benign'
            return 'unknown'
    if name in {'svchost', 'lsass'}:
        if '\\temp\\' in program:
            return 'malicious'
        if program == SYSTEM32 + name + '.exe' and (not args or (name == 'svchost' and tuple(args) in {
            ('-k', 'localservicenonetwork', '-p'), ('-k', 'localservicenetworkrestricted', '-p'),
            ('-k', 'localservice', '-p', '-s', 'dispbrokerdesktopsvc'),
        })):
            return 'benign'
        return 'unknown'
    if re.fullmatch(r't1036\.003_masquerading\.(ps1|docx|pdf)\.exe', ntpath.basename(program)):
        return 'malicious'
    if name in {'wscript', 'cscript'} and any(
        re.fullmatch(r'.*t1036\.003_masquerading\.(png|xls|xlsx)\.vbs', a) for a in args
    ):
        return 'malicious'
    if (name == 'bitsadmin' and len(args) == 4 and args[:2] == ['/addfile', 'atomicbits']
            and args[2] == 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/t1197/t1197.md'
            and re.fullmatch(r'c:\\users\\(?:mari|maryam)\\appdata\\local\\temp\\bitsadmin3_flag\.ps1', args[3])):
        return 'benign'
    if name == 'xordump' and args == ['-out', r'c:\windows\temp\lsass-xordump.t1003.001.dmp', '-x', '0x41']:
        return 'malicious'
    if program == SYSTEM32 + 'secedit.exe' and args == ['/export', '/cfg', r'c:\windows\temp/secexport.cfg']:
        return 'benign'
    if name == 'debug' and '\\temp\\' in program:
        return 'unknown'
    if name in {'mimikatz', 'invoke-mimikatz'} and any(
        a == '-dumpcreds' or a.startswith(('sekurlsa::', 'lsadump::')) for a in args
    ):
        return 'malicious'
    if name in {'procdump', 'procdump64'} and '-ma' in args and 'lsass.exe' in args:
        return 'malicious'
    if name == 'esentutl' and '/y' in args and any(a.replace('/', '\\').endswith(r'\config\sam') for a in args):
        return 'malicious'
    if name in {'sc', 'sc.exe'} and 'binpath=' in args:
        pos = args.index('binpath=')
        if pos + 1 < len(args) and any(a in args for a in ('create', 'config')):
            binary = args[pos + 1]
            if re.search(r'(?:^|\\)(?:cmd|powershell)(?:\.exe)?\s', binary) or binary.startswith('%%comspec%% '):
                return 'malicious'
    if name == 'xcopy' and args == ['/i', '/y', r'pathtoatomicsfolder\t1505.003\src', r'c:\inetpub\wwwroot']:
        return 'malicious'
    if name in {'curl', 'iwr', 'invoke-webrequest', 'regsvr32', 'rundll32'} and any(
        re.search(r'(?:/|\\|^)allthethingsx(?:64|86)\.dll(?:,|$)', a) for a in args
    ):
        return 'malicious'
    if powershell and name in {'new-itemproperty', 'set-itemproperty'}:
        lowered = ' '.join(args)
        if (r'hkcu:\software\microsoft\windows script\settings' in args and '-name amsienable -value 0' in lowered
                or r'hklm:\software\microsoft\.netframework' in args and '-name etwenabled -value 0' in lowered):
            return 'malicious'
    if powershell and name == 'remove-item' and args == ['-path', r'hklm:\software\microsoft\amsi\providers\{2781761e-28e0-4109-99fe-b9d127c57afe}', '-recurse']:
        return 'malicious'
    if powershell and name == 'copy-item' and len(args) == 2 and (args[0], args[1]) in {
            (r'c:\users\mari\appdata\local\temp\bitsadmin3_flag.ps1', r'c:\users\mari\staged'),
            (r'c:\users\maryam\appdata\local\temp\bitsadmin3_flag.ps1', r'c:\windows\system32\staged'),
    }:
        return 'benign'
    if (powershell and name == 'remove-item' and len(args) == 3 and args[1:] == ['-erroraction', 'ignore']
            and (args[0] == r'c:\users\public\art.jse' or re.fullmatch(
            r'(?:c:\\users\\(?:mari|maryam)\\appdata\\local\\temp|\$env:temp)\\t1654_events\.txt', args[0]
    ))):
        return 'benign'
    if name in {'whoami', 'hostname', 'calc', 'notepad', 'exit'} and not args:
        return 'benign'
    if name == 'whoami' and args in [['/all'], ['/user'], ['/groups'], ['/priv']]:
        return 'benign'
    if name == 'wmic' and args in [['csproduct', 'get', 'uuid'], ['process', 'get', 'caption,executablepath,commandline', '/format:csv'], ['qfe', 'get', 'description,installedon', '/format:csv']]:
        return 'benign'
    if name == 'wevtutil' and args == ['enum-logs']:
        return 'benign'
    if name in {'echo', 'write-host'} and not any(c in text for c in '$`()>'):
        return 'benign'
    return None
