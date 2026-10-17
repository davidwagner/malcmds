# shellrisk-bench

Source: https://huggingface.co/datasets/kontext-security/ShellRisk-Bench

Pinned revision: `437467862139b4e9cdd5322024ef3434a67c7ec8`. Prepare and ingest from this directory:

```sh
./fetch
./ingest --db ../../cmds.duckdb
```

The shared downloader verifies byte counts and SHA-256 hashes and saves the source
card, including publisher license information, as `SOURCE_README.md`.

Read `command` from both Parquet splits. Map `not_risky` to benign and `risky` to unknown for inputs and all derived invocations; reject other labels.

Complete decoded strings are preserved as Linux shell input, including pipelines,
redirections, quoting and newlines. The existing Bash parser extracts program
invocations without executing source text. Source row numbers and field names
identify occurrences before filtering or sampling. Descriptions and other source
fields are discarded from the database. All group IDs are NULL.

Every input has its own `shellrisk-bench:record:<record_id>` session. Parsed
process rows inherit that input's session. Published commands are selected
examples, so grouping them by an upstream attempt does not provide a complete
interaction history. Ingestion uses only the published Parquet files and the
QuasarNix overlap reference. Existing `sessions.jsonl` and manifest files are
ignored; `./fetch` no longer downloads trajectories or builds them.
The standalone `./build_sessions` tool remains available for source analysis.

`./fetch` also fetches the pinned QuasarNix release. Ingestion requires every
QuasarNix array in the adjacent `quasarnix` directory, including malicious arrays,
and excludes exact decoded string matches before parsing. It never normalizes
whitespace, quotes or case for this comparison. Even limited runs load the full
reference. A JSON summary on stderr reports candidates examined and overlaps
removed; limited runs report only examined candidates.

The pinned release retains 19,699 inputs and 41,663 process rows after overlap
filtering, with 19,699 distinct input sessions.

To update sessions in an existing database, stop other writers, back up the
file, and run from the repository root:

```sh
./scripts/migrate_record_sessions --db cmds.duckdb
```

This transaction updates ShellRisk and Shell Honeypot sessions in both tables.
It preserves command text, labels (including AI labels), record IDs and completion
flags. It removes these datasets' `SESSION_LABELS` entries for IDs absent from the
updated shell table when that optional table exists. Labels for IDs still
present are preserved. It is safe to run again. Missing or ambiguous shell parents stop the
migration without applying changes.
