"""Ingest real pinned Microsoft examples through the Windows parsers and writer.

The fixture Markdown files are unchanged excerpts of the pinned source release.
Network and parser-process failures require external fault injection; these tests
exercise the actual archives, PowerShell runtime, CMD parser and DuckDB writer.
"""

import io
import tarfile
from pathlib import Path

import duckdb
from test_ingest_performance import ingest

FIXTURES = Path(__file__).parent / "fixtures" / "microsoft-command-docs"
READER = "from _ingest_microsoft_docs import records\n"


def release(root):
    """Package the authentic documents using their upstream archive paths."""
    for shell, filename, prefix in [
        ("cmd", "windowsserverdocs.tar.gz", "windows/WindowsServerDocs/administration/windows-commands"),
        ("powershell", "powershell-docs.tar.gz", "powershell/reference/5.1"),
    ]:
        with tarfile.open(root / filename, "w:gz") as archive:
            for path in sorted((FIXTURES / shell).rglob("*.md")):
                archive.add(path, arcname=f"{prefix}/{path.relative_to(FIXTURES / shell)}")


def test_authentic_microsoft_inputs_and_output_separation(tmp_path):
    """Prompts, output, syntax descriptions and script bodies remain distinct."""
    release(tmp_path)
    database = tmp_path / "commands.duckdb"
    result = ingest(tmp_path, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        rows = con.execute("SELECT record_id,shell_input FROM SHELL_INPUTS").fetchall()
        inputs = dict(rows)
        assert inputs["cmd/ping.md:2:1"] == "ping example.microsoft.com"
        assert inputs["cmd/for.md:4:1"] == "for %f in (*.doc *.txt) do type %f"
        assert "cmd/for.md:3:1" not in inputs, "Syntax placeholders became an input"
        assert inputs["cmd/if.md:5:1"] == (
            "IF EXIST Product.dat (\ndel Product.dat\n) ELSE (\necho The Product.dat file is missing.\n)"
        )
        assert inputs["powershell/Microsoft.PowerShell.Management/Get-PSDrive.md:3:1"] == "Get-PSDrive"
        multiline = inputs["powershell/Microsoft.PowerShell.Management/Get-Process.md:11:1"]
        assert "Format-Table" in multiline and "\n" in multiline
        assert "function Enable-ProcessCreationEvent\n{" in "\n".join(inputs.values())
        assert not any(key.startswith(("cmd/ftp-", "cmd/set-context")) for key in inputs)
        assert not any(key.startswith("cmd/select-disk.md") for key in inputs)
        assert inputs["powershell/Microsoft.PowerShell.Core/Exit-PSHostProcess.md:2:1"] == "Exit-PSHostProcess"
        assert not any(key.startswith("powershell/Microsoft.PowerShell.Core/About/about_Classes_Inheritance.md:34:") for key in inputs)
        assert inputs["powershell/Microsoft.PowerShell.Utility/Set-PSBreakpoint.md:11:2"] == (
            'function CheckLog {\nGet-EventLog -Log Application |\n'
            'Where-Object {($_.Source -like "TestApp") -and ($_.Message -like "*failed*")}\n}'
        )
        assert inputs["powershell/Microsoft.PowerShell.Management/New-Item.md:19:2"] == (
            'New-Item ./TestFile.txt -ItemType File -Force'
        )
        assert any("<#" in text and 'PS> Add-Extension' in text for text in inputs.values()), (
            "Prompts inside a script's help comment must remain part of that script"
        )
        programs = {row[0] for row in con.execute("SELECT pgm FROM PROCESS_LAUNCHES").fetchall()}
        assert {"ping", "type", "del", "echo", "Get-Process", "Format-Table", "New-Object"} <= programs
        assert not programs & {"Reply", "Handles", "Name", "Select-Object:", "John", "Jane", "Joe", "WindowsPowerShell2.0", "for", "if"}
        for table in ["SHELL_INPUTS", "PROCESS_LAUNCHES"]:
            assert con.execute(f"SELECT DISTINCT dataset_label,group_id,os FROM {table}").fetchall() == [
                ("benign", None, "windows")
            ]
            assert con.execute(f"SELECT count(*) FROM {table} WHERE session_id='' OR session_id IS NULL").fetchone() == (0,)
        assert con.execute("SELECT count(*) FROM PROCESS_LAUNCHES p WHERE NOT EXISTS (SELECT 1 FROM SHELL_INPUTS s WHERE p.session_id=s.session_id)").fetchone() == (0,)
        snapshot = con.execute("SELECT record_id,shell_input,session_id FROM SHELL_INPUTS ORDER BY record_id").fetchall()
        con.execute("UPDATE INGESTED SET ingested=false")
    repeated = ingest(tmp_path, database, READER)
    assert repeated.returncode == 0, repeated.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT record_id,shell_input,session_id FROM SHELL_INPUTS ORDER BY record_id").fetchall() == snapshot
        assert con.execute("SELECT ingested FROM INGESTED").fetchone() == (True,)


def test_microsoft_limits_and_missing_archive(tmp_path):
    """Limited and failed reads leave the shared ingestion marker incomplete."""
    release(tmp_path)
    database = tmp_path / "commands.duckdb"
    result = ingest(tmp_path, database, READER, "--max-records", "2", "--sample-files", "2")
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT count(*) FROM SHELL_INPUTS").fetchone() == (2,)
        assert con.execute("SELECT ingested FROM INGESTED").fetchone() == (False,)
    (tmp_path / "powershell-docs.tar.gz").unlink()
    failed = ingest(tmp_path, database, READER)
    assert failed.returncode != 0
    assert "powershell-docs.tar.gz" in failed.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT ingested FROM INGESTED").fetchone() == (False,)


def test_empty_example_is_not_a_submission(tmp_path):
    """An empty shell fence contributes no row alongside a real command."""
    document = b"## EXAMPLES\n```powershell\n\n```\n```powershell\nGet-Process\n```\n"
    with tarfile.open(tmp_path / "windowsserverdocs.tar.gz", "w:gz"):
        pass
    with tarfile.open(tmp_path / "powershell-docs.tar.gz", "w:gz") as archive:
        member = tarfile.TarInfo("powershell/reference/5.1/Empty.md")
        member.size = len(document)
        archive.addfile(member, io.BytesIO(document))
    database = tmp_path / "commands.duckdb"
    result = ingest(tmp_path, database, READER)
    assert result.returncode == 0, result.stderr
    with duckdb.connect(str(database)) as con:
        assert con.execute("SELECT shell_input FROM SHELL_INPUTS").fetchall() == [("Get-Process",)]
