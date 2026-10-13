# Microsoft command documentation

This source adds benign examples of Windows administration from Microsoft's
[Windows command reference](https://github.com/MicrosoftDocs/windowsserverdocs/tree/312d2998c621f384c4e404fe63c7c1c4cbaf61a0/WindowsServerDocs/administration/windows-commands)
and [Windows PowerShell 5.1 reference](https://github.com/MicrosoftDocs/PowerShell-Docs/tree/a3de8f22552170e70852470d46cd52cd9ca471ec/reference/5.1).
The revisions are `312d2998c621f384c4e404fe63c7c1c4cbaf61a0` and
`a3de8f22552170e70852470d46cd52cd9ca471ec`, respectively. Only the 5.1
PowerShell documentation tree is read, so other versions do not duplicate it.

Run `./fetch`, then `./ingest`. The standard `--db`, `--limit`, `--max-records`,
`--sample-files` and `--seed` options apply. Fetch verifies sizes and SHA-256
hashes of both archives and the PowerShell 7.6.6 Linux x64 parser runtime.
The documentation archives total about 429 MB; the parser archive is 76 MB.
The shared LADE helper extracts the parser under `tmp/`. An installed `pwsh`
or the `LADE_PWSH` environment variable overrides the bundled parser; set
`LADE_PWSH` to that pinned executable when reproducing ingestion counts.

Extraction reads fenced code blocks below Markdown Examples headings, ending
at the next heading at the same or a higher level. Output, XML and other
non-shell fence languages are excluded. `extraction-rules.json` lists CMD
document families and recognized program names, excluding interactive FTP,
DiskPart, DiskShadow and similar utility subcommands. Syntax-reference blocks
with angle-bracket placeholders and incomplete examples with ellipsis lines
are excluded. CMD pages that explicitly mark PowerShell code use the
PowerShell parser.

Displayed CMD and PowerShell prompts start separate submissions. Prompt paths,
remote-host and process decorations are removed; printed results are excluded.
Explicit continuation prompts, open parentheses/braces and trailing pipeline,
caret or backtick continuations retain their multiline input. Prompts inside
PowerShell block comments and here-strings remain literal script text. A code
block with no prompts is one complete multiline example. No session identifier
is published, so every submission receives the shared per-record session.

Some source blocks mix unmarked commands with output or another language.
The checked-in `line_ranges` rules select their actual input, using inclusive,
one-based line ranges inside a code fence. An empty list excludes the block.
For example, Start-Transaction mixes registry output with more commands, and
Add-Type includes a Visual Basic source listing. Those listings are excluded.
Standalone class-method definitions that require an enclosing class are also
excluded; complete class examples remain intact.
The conceptual debugger transcript chapter is excluded because its prompts
accept debugger actions rather than ordinary PowerShell submissions.

The CMD parser extracts command lists and the bodies of IF and FOR statements.
Long CMD option lists wrapped onto lines beginning with `/` are joined only
for parsing; the stored shell input retains the source newlines. PowerShell's
AST parser provides static invocations, retaining variables and expressions
without evaluating them. Published mistakes in actual command input remain
as written. The complete script is stored even when it has no invocation.
Source text is never executed.

Both shell inputs and their derived invocations receive `benign`, with
`group_id = NULL`. This is the dataset's label policy for documentation examples.
Record IDs contain the corpus, relative document path, original fence number,
and submission number. Derived commands append an invocation number. Output
filtering and file sampling preserve those source occurrence identities.

The upstream license notices are included beside this README. The real-source
test fixtures in `tests/fixtures/microsoft-command-docs/` are unchanged files
from these revisions and are covered by the same notices.
