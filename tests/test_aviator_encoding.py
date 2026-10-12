"""Read AVIATOR's native single-byte exports without manufacturing characters."""

import io
import tarfile
import zipfile
from pathlib import Path

import duckdb
import pytest
from test_ingest_aviator_parallel import archive_root, event, ingest, rows


@pytest.mark.parametrize("workers", [1, 2])
def test_native_exports_and_declared_encodings(tmp_path, workers):
    """Serial and parallel ingestion agree on source bytes and UTF encodings."""
    root = tmp_path / "aviator"
    root.mkdir()
    fixtures = Path(__file__).parent / "fixtures/aviator"
    first = (fixtures / "0.xml").read_bytes()
    second = (fixtures / "1.xml").read_bytes()
    variants = [first, second, first.decode("cp1252").encode("utf-8"),
                second.decode("cp1252").encode("utf-16"),
                b'<?xml version="1.0" encoding="windows-1252"?>' + first,
                first.decode("cp1252").replace("Richtlinien+ñnderung", "Richtlinien�nderung").encode()]
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as z:
        for index, raw in enumerate(variants):
            z.writestr(f"Oilrig/sysmon_{index}.xml", raw)
    with tarfile.open(root / "10.35097-8s5b0u5yqgfs2y0d.tar", "w") as archive:
        member = tarfile.TarInfo("ex_Oilrig.zip")
        member.size = len(zipped.getvalue())
        archive.addfile(member, io.BytesIO(zipped.getvalue()))
    database = tmp_path / "commands.duckdb"
    result = ingest(root, database, workers)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        args = [r[0] for r in con.execute("SELECT args FROM PROCESS_LAUNCHES ORDER BY record_id").fetchall()]
    assert [a[1] for a in args] == ["/category:Richtlinien+ñnderung", "/category:Richtlinienänderung",
                                     "/category:Richtlinien+ñnderung", "/category:Richtlinienänderung",
                                     "/category:Richtlinien+ñnderung", "/category:Richtlinien�nderung"], (
        "Decoder must recover recorded bytes while preserving upstream mojibake and genuine U+FFFD"
    )


@pytest.mark.parametrize("workers,bounds", [(1, ()), (2, ()),
                                             (2, ("--max-records", "1000000")),
                                             (1, ("--limit", "2"))])
@pytest.mark.parametrize("kind", ["registry", "command", "late", "utf8"])
def test_undefined_bytes_preserved_in_database(tmp_path, workers, bounds, kind):
    """Real archives retain evidence through XML, worker IPC, and DuckDB decoding."""
    if kind == "registry":
        # Original EventRecordID 603 from Sandworm-1/sysmon_audit_24_10_2023_
        # 20_39_37.87_DESKTOP-G3MEF77_sandworm_scenario1.xml; see issue #123.
        middle = (Path(__file__).parent / "fixtures/aviator/registry-603.xml").read_bytes()
        raw = event(601, "tool.exe before /a").encode() + middle + event(604, "tool.exe after /b").encode()
        expected = [["before", "/a"], ["after", "/b"]]
        identifiers = [":601:1:0", ":604:3:0"]
    else:
        value = "x\x81\x8d\x8f\x90\x9dy € ‘quoted’ café"
        if kind in {"late", "utf8"}:
            value = "ā café"
            raw = event(1, "tool.exe " + value).encode()
            raw += event(2).encode() * 20000
            if kind == "late":
                raw += b"\xff"
                value = "Ä\x81 cafÃ©"
        else:
            raw = (
                event(1, "tool.exe " + value).replace("\x81\x8d\x8f\x90\x9d", "UNDEFINED").encode("cp1252")
                .replace(b"UNDEFINED", b"\x81\x8d\x8f\x90\x9d"))
        expected = [value.split(" ")]
        identifiers = [":1:1:0"]
    root = archive_root(tmp_path, [("ex_Sandworm-1.zip", [
        ("sysmon.xml", raw), ("empty.xml", event(9)),
    ])])
    database = tmp_path / "commands.db"
    result = ingest(root, database, workers, *bounds)
    persisted = rows(database)
    assert [row[2] for row in persisted] == expected, (
        "AVIATOR must preserve undefined bytes as C1 controls, CP1252 punctuation, and valid UTF-8 through DuckDB"
    )
    assert all(row[4].endswith(suffix) for row, suffix in zip(persisted, identifiers, strict=True))
    warnings = [line for line in result.stderr.splitlines() if "undefined Windows-1252 bytes" in line]
    if kind == "utf8":
        assert warnings == [], "UTF-8 continuation bytes must not trigger a CP1252 warning"
    else:
        affected = [i for i, byte in enumerate(raw) if byte in (0x81, 0x8d, 0x8f, 0x90, 0x9d)]
        assert len(warnings) == 1
        assert "ex_Sandworm-1.zip/sysmon.xml" in warnings[0]
        assert f"{len(affected)} undefined Windows-1252 bytes" in warnings[0]
        assert f"first at byte offset {affected[0]}" in warnings[0]
