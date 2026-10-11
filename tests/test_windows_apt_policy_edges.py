"""Exercise supported operation variants and ambiguous input through ingestion."""

import base64

from test_windows_apt_policy import event, ingest_rows


def test_supported_operations_and_ambiguous_variants(tmp_path):
    """Similar-looking commands need their actual arguments assessed."""
    rdp = r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    cases = [
        ('reg-missing-key', 'reg.exe add', 'unknown'),
        ('delete-unrelated', r'del C:\unrelated.txt', 'unknown'),
        ('unclosed-expression', 'powershell -Command \"reg query HKLM $(whoami\"', 'unknown'),
        ('compound-dangling-escape', 'cmd /c whoami & hostname ^', 'unknown'),
        ('hidden-before-attack', r'cmd /c powershell -File opaque.ps1 & reg save HKLM\SAM C:\Temp\sam', 'malicious'),
        ('powershell-expression-attack', 'powershell -Command \"reg query HKLM $(Invoke-Mimikatz -DumpCreds)\"', 'malicious'),
        ('powershell-single-quoted-expression', 'powershell -Command "reg query \'HKLM\\$(Invoke-Mimikatz -DumpCreds)\'"', 'benign'),
        ('reg-query', 'reg query HKCU\\Environment', 'benign'),
        ('reg-delete', 'reg delete HKCU\\Environment /v APPX_PROCESS /f', 'unknown'),
        ('reg-missing-data', 'reg add HKCU\\Environment /v APPX_PROCESS', 'unknown'),
        ('reg-duplicate-flag', 'reg add HKCU\\Environment /v APPX_PROCESS /v Other /d 1', 'unknown'),
        ('reg-dangling-flag', 'reg add HKCU\\Environment /d', 'unknown'),
        ('reg-unrecognized-option', 'reg add HKCU\\Environment /bad value', 'unknown'),
        ('reg-auth-other-value', f'reg add "{rdp}" /v UserAuthentication /d 2 /t REG_DWORD', 'unknown'),
        ('reg-rdp-other-name', f'reg add "{rdp}" /v Other /d 1 /t REG_DWORD', 'unknown'),
        ('reg-other-key', 'reg add HKCU\\Example /v Value /d example', 'unknown'),
        ('reg-restoration-wrong-type', f'reg add "{rdp}" /v UserAuthentication /d 1 /t REG_SZ', 'unknown'),
        ('reg-security-export', 'reg export HKLM\\SECURITY C:\\Temp\\security.reg', 'malicious'),
        ('empty-shell-body', 'cmd /c ""', 'unknown'),
        ('nested-shell-limit', ('cmd /c ' * 15) + 'whoami', 'unknown'),
        ('quoted-shell-pair', 'cmd /c "whoami & hostname"', 'benign'),
        ('cmd-options', 'cmd /d /q /k whoami', 'benign'),
        ('unmatched-quote', 'cmd /c whoami "unterminated', 'unknown'),
        ('trailing-escape', 'cmd /c whoami ^', 'unknown'),
        ('escaped-shell-operator', 'cmd /c echo hello ^& world', 'benign'),
        ('unknown-shell-body', 'cmd /c unclassified.exe', 'unknown'),
        ('powershell-empty', 'powershell', 'unknown'),
        ('powershell-empty-command', 'powershell -Command', 'unknown'),
        ('powershell-profile-options', 'powershell -NoProfile -NoLogo -NonInteractive -NoExit -Command whoami', 'benign'),
        ('powershell-option-values', 'powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Version 5.1 -Command whoami', 'benign'),
        ('powershell-dangling-option', 'powershell -ExecutionPolicy', 'unknown'),
        ('powershell-only-options', 'powershell -NoProfile', 'unknown'),
        ('powershell-unsupported-tail', 'powershell -enc dwBoAG8AYQBtAGkA -File hidden.ps1', 'unknown'),
        ('powershell-unknown-command', 'powershell -Command unclassified.exe', 'unknown'),
        ('powershell-quoted-assignment', 'powershell -Command "$message = \'Invoke-Mimikatz -DumpCreds\'"', 'unknown'),
        ('powershell-unknown-assignment', 'powershell -Command "$result = unclassified.exe"', 'unknown'),
        ('powershell-assigned-query', 'powershell -Command "$result = whoami"', 'benign'),
        ('powershell-single-quotes', 'powershell -Command "Write-Host \'hello; world\'"', 'benign'),
        ('net-multiple-operands', 'net user guest example /add', 'unknown'),
        ('net-unsupported-switch', 'net accounts /maxpwage:unlimited', 'unknown'),
        ('net-domain-query', 'net group "Domain Admins" /domain', 'benign'),
        ('net-no-args', 'net', 'unknown'),
        ('net-service-start', 'net start TermService', 'unknown'),
        ('svchost-unobserved-options', 'C:\\Windows\\System32\\svchost.exe -k unexpected', 'unknown'),
        ('svchost-other-directory', 'C:\\Other\\svchost.exe', 'unknown'),
        ('lsass-unexpected-argument', 'C:\\Windows\\System32\\lsass.exe hidden', 'unknown'),
        ('bits-other-source', 'bitsadmin /addfile AtomicBITS https://example.com/T1197.md C:\\Users\\mari\\AppData\\Local\\Temp\\bitsadmin3_flag.ps1', 'unknown'),
        ('bits-other-destination', 'bitsadmin /addfile AtomicBITS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\\Other.ps1', 'unknown'),
        ('procdump-lsass', 'procdump64 -ma lsass.exe C:\\Temp\\lsass.dmp', 'malicious'),
        ('esentutl-sam', 'esentutl /y C:\\Windows\\System32\\config\\SAM /d C:\\Temp\\sam', 'malicious'),
        ('service-cmd', 'sc config example binPath= "C:\\Windows\\System32\\cmd.exe /c calc"', 'malicious'),
        ('service-powershell', 'sc create example binPath= "powershell -Command whoami"', 'malicious'),
        ('service-empty-binpath', 'sc config example binPath=', 'unknown'),
        ('service-ordinary-binary', 'sc config example binPath= C:\\Example.exe', 'unknown'),
        ('service-other-action', 'sc query example binPath= C:\\Example.exe', 'unknown'),
        ('powershell-amsi-provider-remove', 'powershell -Command "Remove-Item -Path HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE} -Recurse"', 'malicious'),
        ('powershell-registry-other-value', 'powershell -Command "New-ItemProperty -Path HKLM:\\Software\\Microsoft\\.NETFramework -Name ETWEnabled -Value 1"', 'unknown'),
        ('powershell-copy-other', 'powershell -Command "Copy-Item C:\\unknown.ps1 C:\\staged"', 'unknown'),
        ('powershell-remove-other', 'powershell -Command "Remove-Item C:\\unknown.ps1 -ErrorAction Ignore"', 'unknown'),
        ('whoami-privileges', 'whoami /priv', 'benign'),
        ('wmic-uuid', 'wmic csproduct get uuid', 'benign'),
        ('wmic-processes', 'wmic process get caption,executablepath,commandline /format:csv', 'benign'),
        ('wmic-updates', 'wmic qfe get description,installedon /format:csv', 'benign'),
        ('event-log-list', 'wevtutil enum-logs', 'benign'),
        ('echo-expression', 'powershell -Command "Write-Host $(unclassified.exe)"', 'unknown'),
    ]
    for flag in ('-e', '-ec'):
        encoded = base64.b64encode('whoami'.encode('utf-16le')).decode()
        cases.append(('encoding-' + flag, 'powershell ' + flag + ' ' + encoded, 'benign'))
    rows = [event(name, command, '92004', ()) for name, command, _ in cases]
    rows.append(event('overlong-tag', 'unclassified.exe', 'unmapped', ('T1027.0000',)))
    cases.append(('overlong-tag', 'unclassified.exe', 'unknown'))
    saved = ingest_rows(tmp_path, rows)
    differences = [f'{name}: {saved["policy:" + name + ":0"][0]} != {label}'
                   for name, _, label in cases if saved['policy:' + name + ':0'][0] != label]
    assert not differences, '\n'.join(differences)


def test_powershell_expressions_preserve_outer_attack_evidence(tmp_path):
    """An unresolved argument cannot erase visible credential-dump behavior."""
    cases = [
        ('outer-sam-export', r'reg save HKLM\SAM $(Join-Path $env:TEMP sam.hiv)', 'malicious'),
        ('nested-attack', 'Write-Host $((Invoke-Mimikatz -DumpCreds))', 'malicious'),
        ('multiple-expressions', 'Write-Host $(whoami) $(Invoke-Mimikatz -DumpCreds)', 'malicious'),
        ('interpolated-attack', 'Write-Host "identity: $(Invoke-Mimikatz -DumpCreds)"', 'malicious'),
        ('unsupported-expression', r'reg query HKLM $(Join-Path $env:TEMP example)', 'unknown'),
        ('literal-expression', "Write-Host 'identity: $(Invoke-Mimikatz -DumpCreds)'", 'unknown'),
    ]
    rows = []
    for name, payload, _ in cases:
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()
        rows.append(event(name, 'powershell -EncodedCommand ' + encoded, '92004', ()))
    saved = ingest_rows(tmp_path, rows)
    differences = [f'{name}: {saved["policy:" + name + ":0"][0]} != {label}'
                   for name, _, label in cases if saved['policy:' + name + ':0'][0] != label]
    assert not differences, '\n'.join(differences)


def test_verified_uac_parent_precedes_ordinary_child(tmp_path):
    """Only the complete observed bypass makes an ordinary child malicious."""
    import json

    from test_windows_apt_policy import FIXTURE, PREFIX

    examples = json.loads(FIXTURE.read_text())
    source = next(example['row'] for example in examples if example['name'] == 'fodhelper-bypass')
    parent = source[PREFIX + 'parentCommandLine']
    variants = [
        ('verified-fodhelper', parent, 'malicious'),
        ('verified-computerdefaults', parent.replace('fodhelper.exe', 'ComputerDefaults.exe'), 'malicious'),
        ('different-key', parent.replace('ms-settings', 'other-settings'), 'benign'),
        ('different-value', parent.replace('DelegateExecute', 'OtherValue'), 'benign'),
        ('different-command', parent.replace('cmd.exe', 'notepad.exe'), 'benign'),
        ('different-launcher', parent.replace('fodhelper.exe', 'notepad.exe'), 'benign'),
        ('missing-parent', '', 'benign'),
        ('unsupported-parent', 'powershell.exe -File unavailable.ps1', 'benign'),
        ('echo-parent', 'echo ' + parent, 'benign'),
        ('truncated-parent', parent.split('Set-ItemProperty', 1)[0], 'benign'),
    ]
    rows = []
    for name, parent_command, _ in variants:
        row = event(name, 'whoami', '92056')
        row[PREFIX + 'parentCommandLine'] = parent_command
        rows.append(row)
    rows.append(event('fodhelper-missing-parent', 'whoami', '92046'))
    saved = ingest_rows(tmp_path, rows)
    differences = [f'{name}: {saved["policy:" + name + ":0"][0]} != {label}'
                   for name, _, label in variants if saved['policy:' + name + ':0'][0] != label]
    assert saved['policy:fodhelper-missing-parent:0'][0] == 'benign'
    assert not differences, '\n'.join(differences)
