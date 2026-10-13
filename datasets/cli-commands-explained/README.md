# cli-commands-explained

Source: https://huggingface.co/datasets/b-mc2/cli-commands-explained

Pinned revision: `f7bf751e0d5c43ce26dd51a56d5eed5c51503196`. Run `./fetch`, then `./ingest --db ../../cmds.duckdb`.
The shared downloader verifies byte counts and SHA-256 hashes and saves the source
card, including publisher license information, as `SOURCE_README.md`.

Read `code` from cli_commands_explained.json. Label inputs and all derived invocations unknown.

Complete decoded strings are preserved as Linux shell input, including pipelines,
redirections, quoting and newlines. The existing Bash parser extracts program
invocations without executing source text. Source row numbers and field names
identify occurrences before filtering or sampling. Descriptions and other source
fields are discarded. Each input gets its own fallback session; derived
invocations share that session. All group IDs are NULL.

The pinned release has eight empty `code` values; these supply no shell input
and are skipped. Stable row IDs include their original positions.

Two source rows contain fenced TOML configuration. Ingestion omits the configuration and retains the shell command following the fence when present.
