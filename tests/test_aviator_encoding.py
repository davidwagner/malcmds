"""Read AVIATOR's native single-byte exports without manufacturing characters."""

import io
import tarfile
import zipfile
from pathlib import Path

import duckdb
import pytest
from test_ingest_aviator_parallel import ingest


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
        args = [r[0] for r in con.execute("SELECT args FROM COMMANDS ORDER BY record_id").fetchall()]
    assert [a[1] for a in args] == ["/category:Richtlinien+ñnderung", "/category:Richtlinienänderung",
                                     "/category:Richtlinien+ñnderung", "/category:Richtlinienänderung",
                                     "/category:Richtlinien+ñnderung", "/category:Richtlinien�nderung"], (
        "Decoder must recover recorded bytes while preserving upstream mojibake and genuine U+FFFD"
    )
