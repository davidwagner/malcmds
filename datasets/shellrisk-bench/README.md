# shellrisk-bench

Source: https://huggingface.co/datasets/kontext-security/ShellRisk-Bench

Pinned revision: `437467862139b4e9cdd5322024ef3434a67c7ec8`. Prepare and ingest from this directory:

```sh
./fetch
./ingest --db ../../cmds.duckdb
```

`./fetch` runs the session builder automatically using `uv`, which also supplies
the builder's pinned Python dependency. The builder downloads or reuses the
pinned SWE-smith and Terminal-Bench trajectories and adapter code in
`../../tmp/shellrisk-upstream`. This is a large, one-time download. It checks file
sizes and SHA-256 hashes, replays extraction in the original order, and matches
every published agent command by source, extraction ID, exact text and command
hash. It writes `sessions.jsonl` and `sessions.manifest.json` beside this README.
The manifest records input revisions, ordered file hashes, extraction settings,
coverage and the mapping hash. Rebuilding from the same inputs produces the same
files. Ordinary ingestion reads only the published files and this mapping.
To rebuild using a different cache directory, run
`./build_sessions --upstream-root /path/to/cache` directly.
The shared downloader verifies byte counts and SHA-256 hashes and saves the source
card, including publisher license information, as `SOURCE_README.md`.

Read `command` from both Parquet splits. Map `not_risky` to benign and `risky` to unknown for inputs and all derived invocations; reject other labels.

Complete decoded strings are preserved as Linux shell input, including pipelines,
redirections, quoting and newlines. The existing Bash parser extracts program
invocations without executing source text. Source row numbers and field names
identify occurrences before filtering or sampling. Descriptions and other source
fields are discarded from the database. All group IDs are NULL.

For SWE-smith and Terminal-Bench, a session is one recorded agent attempt at a
task. Its ID hashes the upstream dataset, pinned revision, full source file path
and zero-based trajectory row. Two retained commands from the same attempt share
an ID. Different attempts remain separate even when their task IDs agree or
Terminal-Bench trial IDs are empty. The mapping retains task IDs, agent and trial
metadata, and message/Bash-block or step/tool positions for ordering. The other
four sources retain one fallback session per input. Parsed process rows inherit
their input's session, and labels keep their existing meaning.

These are partial sessions. Upstream deduplication, command-pattern caps, tool
filtering and publication sampling remove commands. The mapping identifies the
occurrence selected by extraction; it cannot reconstruct full task histories.
The adapter's multiline `session` category describes a single submission and is
different from a recorded task attempt. Published train/test splits can contain
commands from the same attempt: construct a new split grouped by session for
session-level experiments, or by task ID to keep repeated attempts together.

Ingestion validates both complete splits before yielding any records, even for
limited runs. Missing entries, changed text or hashes, duplicate keys, invalid
source positions and inconsistent session IDs stop ingestion.

`./fetch` also fetches the pinned QuasarNix release. Ingestion requires every
QuasarNix array in the adjacent `quasarnix` directory, including malicious arrays,
and excludes exact decoded string matches before parsing. It never normalizes
whitespace, quotes or case for this comparison. Even limited runs load the full
reference. A JSON summary on stderr reports candidates examined and overlaps
removed; limited runs report only examined candidates.

To update an existing database, first ingest into a fresh database and inspect
the result. The pinned release has 18,643 mapped agent commands across 12,081
attempts. After overlap filtering, expect 19,699 inputs, 41,663 process rows and
13,137 distinct input sessions. Back up the existing database while no writer is
running. Mark only this dataset incomplete, then rerun its ingestion command:

```sh
python - <<'PY'
import duckdb
with duckdb.connect('../../cmds.duckdb') as connection:
    connection.execute("UPDATE INGESTED SET ingested = false WHERE dataset = 'shellrisk-bench'")
PY
./ingest --db ../../cmds.duckdb
```

The driver replaces this dataset's rows on retry. Completion flags and rows for
other datasets stay as they were.
