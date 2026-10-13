# shellrisk-bench

Source: https://huggingface.co/datasets/kontext-security/ShellRisk-Bench

Pinned revision: `437467862139b4e9cdd5322024ef3434a67c7ec8`. Run `./fetch`, then `./ingest --db ../../cmds.duckdb`.
The shared downloader verifies byte counts and SHA-256 hashes and saves the source
card, including publisher license information, as `SOURCE_README.md`.

Read `command` from both Parquet splits. Map `not_risky` to benign and `risky` to unknown for inputs and all derived invocations; reject other labels.

Complete decoded strings are preserved as Linux shell input, including pipelines,
redirections, quoting and newlines. The existing Bash parser extracts program
invocations without executing source text. Source row numbers and field names
identify occurrences before filtering or sampling. Descriptions and other source
fields are discarded. Each input gets its own fallback session; derived
invocations share that session. All group IDs are NULL.

`./fetch` also fetches the pinned QuasarNix release. Ingestion requires every
QuasarNix array in the adjacent `quasarnix` directory, including malicious arrays,
and excludes exact decoded string matches before parsing. It never normalizes
whitespace, quotes or case for this comparison. Even limited runs load the full
reference. A JSON summary on stderr reports candidates examined and overlaps
removed; limited runs report only examined candidates.
