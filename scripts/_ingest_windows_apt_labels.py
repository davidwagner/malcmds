"""Recognize observed Windows-APT collection and defense commands by provenance."""

from __future__ import annotations

import csv
import html
import json
import ntpath
import re
from itertools import islice

from _ingest import normalize

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
