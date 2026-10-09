"""Promote only observed commands that match reviewed publisher attack steps."""

import io
import json
import shutil
import tarfile
import zipfile
from pathlib import Path

import duckdb
from test_ingest_aviator_parallel import archive_root, ingest as aviator_ingest
from test_ingest_performance import ingest

FIXTURES = Path(__file__).parent / "fixtures"


def test_five_aviator_deletions_and_context_controls(tmp_path):
    """Procedure variables and host/scenario checks survive actual archive ingestion."""
    source = FIXTURES / "aviator"
    native = [(f"sysmon_{i}.xml", (source / f"attack-{i}.xml").read_text()) for i in range(5)]
    # Same command text with a distinct source occurrence must remain an execution.
    native.append(("sysmon_repeat.xml", native[0][1]))
    wrong_host = native[0][1].replace("DESKTOP-G3MEF77", "OTHER-HOST")
    wrong_arg = native[0][1].replace("/accepteula", "/different")
    root = archive_root(tmp_path, [("ex_APT29-1.zip", [*native,
        ("sysmon_wronghost.xml", wrong_host), ("sysmon_wrongargs.xml", wrong_arg),
        ("sysmon_normal_operation.xml", native[0][1])]),
        ("ex_APT29-2.zip", [("sysmon_wrongscenario.xml", native[0][1])])])
    procedure = (source / "scenario1.sh").read_bytes()
    with tarfile.open(root / "aviator-ground-truth-and-tools.tar.gz", "w:gz") as a:
        member = tarfile.TarInfo("release/ground_truth/apt29/scenario1.sh")
        member.size = len(procedure)
        a.addfile(member, io.BytesIO(procedure))
    database = tmp_path / "commands.duckdb"
    aviator_ingest(root, database, 2)
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT record_id,label,group_id,session_id FROM COMMANDS").fetchall()
    assert len(rows) == 10
    assert sum(r[1] == "malicious" for r in rows) == 6, "Five native deletions and one distinct repeat match attack steps"
    assert sum(r[1] == "malicious-group" for r in rows) == 3
    assert sum(r[1] == "benign" for r in rows) == 1
    assert all((r[1] == "malicious-group") == (r[2] is not None) and r[3] for r in rows)
    aviator_ingest(root, database, 2)
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT count(*) FROM COMMANDS").fetchone()[0] == 10


def test_splunk_old_catalog_headless_and_current_precedence(tmp_path):
    """Only the recorded conhost --headless launches become malicious."""
    root = tmp_path / "splunkad"
    target = root / "source/datasets/attack_techniques/T1564.003/headless"
    target.mkdir(parents=True)
    text = (FIXTURES / "4688_conhost_headless.log").read_text()
    (target / "4688_conhost_headless.log").write_text(text + text.replace("--headless", "--visible"))
    shutil.copyfile(FIXTURES / "headless_old.yml", target / "z_old.yml")
    # An independent file has both catalogs; current must win even when read first.
    (target / "other.log").write_text(text)
    old = (target / "z_old.yml").read_text()
    (target / "z_old.yml").write_text(old + "\n")
    (target / "a_current.yml").write_text("id: current\ndatasets:\n- path: datasets/attack_techniques/T1564.003/headless/other.log\n")
    (target / "zz_old_other.yml").write_text(old.replace("4688_conhost_headless.log", "other.log"))
    database = tmp_path / "commands.duckdb"
    result = ingest(root, database, "from _ingest_windows import splunkad as records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT label,group_id,args FROM COMMANDS").fetchall()
    assert sum(label == "malicious" for label, _, _ in rows) == 4
    assert sum(group == "splunkad:current" for _, group, _ in rows) == 4
    assert sum(label == "malicious-group" and "--visible" in args for label, _, args in rows) == 4
    assert all(group is None for label, group, _ in rows if label == "malicious")


def test_publicarena_attack_windows_and_background(tmp_path):
    """Native mimikatz/task/PAExec matches retain host/time limits and generic services."""
    root = tmp_path / "publicarena"
    logs = root / "source/SystemAuditLogs"
    shutil.copytree(FIXTURES / "publicarena-config", logs / "GroundTruth/F-Lateral-config")
    rows = json.loads((FIXTURES / "publicarena-attacks.json").read_text())
    native = next(r for r in rows if r["uuid"] == "b01d675b97179cf93b6a4a4e9499973c")
    rows.append(dict(native, uuid="outside", date="05/13/2022 10:00:00"))
    rows.append(dict(native, uuid="different-args", CommandLine="mimikatz.exe version"))
    with zipfile.ZipFile(logs / "events.zip", "w") as archive:
        archive.writestr("HostA-2-attack.json", "\n".join(json.dumps(r) for r in rows))
        archive.writestr("HostB-2-attack.json", json.dumps(dict(native, uuid="wrong-host")))
    database = tmp_path / "commands.duckdb"
    result = ingest(root, database, "from _ingest_misc import publicarena as records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        saved = con.execute("SELECT record_id,label,group_id,pgm_base FROM COMMANDS").fetchall()
    labels = {r[0].split(":")[-2]: r[1] for r in saved}
    assert labels[native["uuid"]] == "malicious"
    assert labels["outside"] == labels["wrong-host"] == "unknown"
    assert labels["different-args"] == "malicious-group"
    assert sum(r[1] == "malicious" for r in saved) == 4
    assert any(r[1] == "malicious-group" and r[3].lower() == "svchost.exe" for r in saved)
    assert all((r[1] == "malicious-group") == (r[2] is not None) for r in saved)
