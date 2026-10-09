# LADE

Source: [LADE dataset](https://github.com/jgwak1/LADE), revision
`1c2f217bb57e944829946f38af5189c36ea9dcca`. This release accompanies
*LADE: LLM-Assisted Advanced Persistent Threat Detection and Explanation*.

Run `./fetch`, then `./ingest`. The normal ingestion options apply, including
`--db`, `--limit`, `--max-records` and `--sample-files`. Fetch downloads the complete
8.6 MB source archive, the original AVIATOR scenario plans, and the 76 MB Linux
x64 PowerShell 7.6.6 runtime used for static parsing. An installed `pwsh` or
`LADE_PWSH=/absolute/path/to/pwsh` takes precedence. The downloaded runtime is
extracted under the repository's `tmp/` directory. No dataset command is executed.

The importer reads all 133 canonical sequences: 33 Caldera attack GroundTruth
files, 33 Caldera benign files, 35 AVIATOR attack files and 32 AVIATOR benign
files. The matching Caldera Processed attack files and each GroundTruth record's
`Resolved Code` are alternative representations and produce no additional rows.
All 864 original GroundTruth snippets are inspected.

The platform field selects a Bash, cmd.exe, PowerShell or direct-process parser.
The PowerShell parser uses `Parser.ParseInput` and inspects command AST nodes;
strings, comments and operators never become commands. Arguments remain static:
variables and expressions are preserved without expansion. cmd.exe redirections
are separated from program arguments. For example,
`"adfind.exe" -f (objectcategory=person) > ad_users.txt` has two arguments and
`other_tokens = [">", "ad_users.txt"]`. Snippets whose nominal cmd platform
contains explicit PowerShell syntax use the PowerShell parser. Unknown platform
tags in this release also contain PowerShell syntax. Unrecognized platform tags
with an unambiguous Unix executable path or shell name use Linux shell parsing.

Only original Caldera shell snippets fill `shell_input`. Process command lines
and AVIATOR Event 4104 script-block text leave it null. The processed sequence
format removes original snippet delimiters: recognizable executable command
lines use process quoting, while remaining multiline script text is parsed
together. Individual AST commands receive distinct occurrence IDs, including
repeated identical commands. The source format cannot establish which branches
of an expanded script actually ran; these rows describe commands present in
the published snippets.

GroundTruth distinguishes malicious snippets from inserted benign snippets.
Harmless delay, directory-change and output-discard operations within an attack
snippet receive benign labels. Normal browser launches and routine browser
helpers are also benign. AVIATOR attack sequences initially use
`malicious-group`; exact program-and-argument matches against their original
actor/scenario plan become malicious. Matching excludes bare shell launches and
scenario-control commands. Unmatched rows retain the sequence group label.
The original plans are pinned to AVIATOR revision
`4a8a815ee723ee7c6dec871409be67fef272da6b`. No connection identifier is released,
so rows use the shared per-record session fallback. Only `malicious-group` rows
have a group ID.

The parser dependency is exercised with authentic GroundTruth records and
archive-to-DuckDB tests in `test_ingest_lade_otrf.py`. Before those tests, run
`./fetch` or set `LADE_PWSH` to an installed PowerShell runtime.
