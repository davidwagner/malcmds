"""PublicArena JSON escaping survives archive reading and DuckDB insertion."""

import json
import shutil
import zipfile
from pathlib import Path

import duckdb
from test_ingest_batches import invoke


def test_publicarena_paths_and_paexec_labels(tmp_path):
    """JSON/tokenizer upgrades must preserve paths and both PAExec attack labels."""
    root = tmp_path / "publicarena"
    logs = root / "source/SystemAuditLogs"
    fixtures = Path(__file__).parent / "fixtures"
    shutil.copytree(fixtures / "publicarena-config", logs / "GroundTruth")
    # Published commands and configurations cover both recognized PAExec steps.
    published = json.loads((fixtures / "publicarena-attacks.json").read_text())
    attack_ids = {"3699e6ceb0ddfa44615103bea5f8b0b4", "da37c79159780643953c245f210ce8dd"}
    attacks = [row for row in published if row["uuid"] in attack_ids]
    assert len(attacks) == 2, "The fixture must retain both published PAExec attacks"
    controls = [
        ("network", r"\\server\share", r"\\server\share"),
        ("pipe", r"\\.\pipe\iisipm", r"\\.\pipe\iisipm"),
        ("local", r"C:\Temp\file", r"C:\Temp\file"),
        ("quoted-network", r'"\\server\shared folder"', r"\\server\shared folder"),
        ("entities", "&amp;lt;", "&lt;"),
    ]
    rows = [
        dict(attacks[0], uuid=rid, PName="helper", CommandLine=f"helper.exe {text}")
        for rid, text, _ in controls
    ]
    background = dict(attacks[0], uuid="background", CommandLine="paexec.exe /help")
    # A genuinely single-backslash source must not match the repaired attack rule.
    single = dict(attacks[0], uuid="single", CommandLine=attacks[0]["CommandLine"].replace("\\\\", "\\"))
    with zipfile.ZipFile(logs / "events.zip", "w") as archive:
        archive.writestr("HostA-benign.json", "\n".join(json.dumps(row) for row in rows))
        archive.writestr("HostA-attack.json", "\n".join(json.dumps(row) for row in [*attacks, background, single]))
    database = tmp_path / "commands.duckdb"
    result = invoke(root, database, "from _ingest_misc import publicarena as records\n")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database), read_only=True) as con:
        saved = con.execute("SELECT record_id, args, label, group_id FROM COMMANDS").fetchall()
        assert con.execute("SELECT dataset, ingested FROM INGESTED").fetchall() == [("publicarena", True)]
    by_id = {rid.split(":")[-2]: (args, label, group) for rid, args, label, group in saved}
    assert len(saved) == len(controls) + 4, "Archive parsing must preserve every source event"
    for rid, _, expected in controls:
        assert by_id[rid] == ([expected], "benign", None), (
            f"JSON decoding and Windows argument parsing must preserve {rid}: {expected!r}"
        )
    for attack in attacks:
        args, label, group = by_id[attack["uuid"]]
        assert args[0] == r"\\192.168.0.110", "PAExec's network target needs both leading backslashes"
        assert (label, group) == ("malicious", None), "Preserving the network target must retain direct attack recognition"
    for rid in ("background", "single"):
        assert by_id[rid][1] == "malicious-group", "Other PAExec commands only inherit the attack-window label"
        assert by_id[rid][2].startswith("publicarena:A:"), "Attack-window commands need their group identity"
    assert by_id["single"][0][0] == r"\192.168.0.110", "Do not add backslashes absent from the source"
