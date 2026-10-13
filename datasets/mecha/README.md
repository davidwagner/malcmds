# mecha

Source: https://huggingface.co/datasets/mecha-org/linux-command-dataset

Pinned revision: `d3883ec38c0458a73a0b8aef19103cb2d006c87c`. Run `./fetch`, then `./ingest --db ../../cmds.duckdb`.
The shared downloader verifies byte counts and SHA-256 hashes and saves the source
card, including publisher license information, as `SOURCE_README.md`.

Read `output` from linuxcommands.json. Label inputs and their program invocations benign.

Complete decoded strings are preserved as Linux shell input, including pipelines,
redirections, quoting and newlines. The existing Bash parser extracts program
invocations without executing source text. Source row numbers and field names
identify occurrences before filtering or sampling. Descriptions and other source
fields are discarded. Each input gets its own fallback session; derived
invocations share that session. All group IDs are NULL.
