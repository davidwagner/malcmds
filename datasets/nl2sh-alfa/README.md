# nl2sh-alfa

Source: https://huggingface.co/datasets/westenfelder/NL2SH-ALFA

Pinned revision: `a99cb5784cf5c2a42b1cc26c1903d9c3b35206ba`. Run `./fetch`, then `./ingest --db ../../cmds.duckdb`.
The shared downloader verifies byte counts and SHA-256 hashes and saves the source
card, including publisher license information, as `SOURCE_README.md`.

Read `bash` from train.csv and both `bash` and `bash2` from test.csv. Label retained inputs and their program invocations benign.

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

One source command has inline Markdown fences; ingestion removes that wrapper.
