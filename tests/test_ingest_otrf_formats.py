"""End-to-end checks for incomplete OTRF events, archive forms and bounded imports.

The duplicate-launch guard's missing-prior-PID branch cannot be reached through
the public reader: every stored launch identity also writes its PID state, and
that state is never removed. Exercising it would require a fabricated internal
state. Disk-full and interrupted-I/O failures propagate from the real archive
libraries; these tests do not replace those libraries or inject fake failures.
"""

import io
import json
import tarfile

import duckdb
import pytest
from test_ingest_lade_otrf import add_member, zipped
from test_ingest_performance import ingest

READER = "from _ingest_otrf import records\n"


def test_otrf_incomplete_and_unrelated_syslog_preserves_local_cli(tmp_path):
    """Incomplete XML and service messages do not masquerade as local commands."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    rows = [
        {"SyslogMessage": "<Event><System><Provider Name=\"Linux-Sysmon\"/><EventID>1</EventID>"},
        {"SyslogMessage": "systemd: Started session 104 of user analyst."},
        {"eventSource": "sts.amazonaws.com", "eventName": "GetCallerIdentity"},
        {"Provider": "Linux-Sysmon", "Image": "/usr/bin/aws", "CommandLine": "aws sts get-caller-identity"},
    ]
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/compound/capture/events.json", "\n".join(json.dumps(row) for row in rows))
    database = tmp_path / "syslog.duckdb"
    result = ingest(root, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT pgm,args,os,label,shell_input FROM COMMANDS").fetchall() == [
            ("/usr/bin/aws", ["sts", "get-caller-identity"], "linux", "unknown", None),
        ]


def test_otrf_empty_audit_observations_do_not_invent_arguments(tmp_path):
    """An audit event without an invocation or attempted target produces no row."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    text = '''type=SYSCALL msg=audit(1604994496.155:92733): arch=c000003e syscall=0 success=yes pid=1631 exe="/usr/sbin/arp"
type=PATH msg=audit(1604994496.155:92733): name="/tmp/input" nametype=NORMAL
type=EOE msg=audit(1604994496.155:92733):
type=SYSCALL msg=audit(1604994497.155:92734): arch=c000003e syscall=59 success=no pid=1631 exe="/usr/sbin/arp"
type=PATH msg=audit(1604994497.155:92734): name="/tmp" nametype=PARENT
type=EOE msg=audit(1604994497.155:92734):
'''
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/atomic/linux/host/audit.zip", zipped("audit.log", text))
    database = tmp_path / "empty-audit.duckdb"
    result = ingest(root, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT count(*) FROM COMMANDS").fetchone() == (0,)
        assert con.execute("SELECT * FROM INGESTED").fetchall() == [(root.name, True)]


@pytest.mark.parametrize("container", ["zip", "tar.gz", "json"])
def test_otrf_record_limit_and_complete_retry_across_archive_formats(tmp_path, container):
    """A bounded scan remains incomplete and its retry replaces rows without duplication."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    text = '\n'.join(json.dumps({"Image": "cmd.exe", "CommandLine": "cmd.exe /c " + name}) for name in ["whoami", "hostname"])
    if container == "zip":
        data = zipped("events.json", text)
    elif container == "tar.gz":
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as nested:
            directory = tarfile.TarInfo("capture")
            directory.type = tarfile.DIRTYPE
            nested.addfile(directory)
            add_member(nested, "capture/README.txt", "Export instructions, not command telemetry.\n")
            add_member(nested, "capture/events.json", text)
        data = output.getvalue()
    else:
        data = text
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/atomic/windows/host/export." + container, data)
    database = tmp_path / "bounded.duckdb"
    result = ingest(root, database, READER, "--max-records", "1")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT args FROM COMMANDS").fetchall() == [(["/c", "whoami"],)]
        assert con.execute("SELECT * FROM INGESTED").fetchall() == [(root.name, False)]
    result = ingest(root, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT args FROM COMMANDS ORDER BY record_id").fetchall() == [(["/c", "whoami"],), (["/c", "hostname"],)]
        assert con.execute("SELECT * FROM INGESTED").fetchall() == [(root.name, True)]


def test_otrf_corrupt_json_is_retryable(tmp_path):
    """A malformed event must fail ingestion rather than mark a partial release complete."""
    root = tmp_path / "otrf-security-datasets"
    root.mkdir()
    with tarfile.open(root / "security-datasets.tar.gz", "w:gz") as archive:
        add_member(archive, "OTRF/datasets/atomic/windows/host/events.json", '{"CommandLine":"cmd /c whoami"}\n{"CommandLine":')
    database = tmp_path / "corrupt.duckdb"
    result = ingest(root, database, READER)
    assert result.returncode != 0, "Invalid JSON was silently accepted as a complete OTRF release"
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT * FROM INGESTED").fetchall() == [(root.name, False)]
