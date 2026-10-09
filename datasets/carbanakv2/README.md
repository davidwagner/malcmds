# CARBANAK v2

Source: [PIDSMaker](https://github.com/ubc-provenance/PIDSMaker/tree/438a05a7c55256f639e5b5945cf4828fe3ee078e). `./fetch` downloads the complete `carbanakv2_edr` PostgreSQL custom dump (1,178,382,514 bytes) and the ground-truth UUID CSV pinned to this revision.

Install PostgreSQL client tools version 17 or newer, or set `PG_RESTORE` to that version's `pg_restore` executable. Run `./fetch`, then `./ingest --db /path/to/commands.duckdb`.

The importer streams `subject_node_table` through `pg_restore --data-only --table=subject_node_table --file=-`. It parses PostgreSQL COPY text and never executes the dump's SQL or creates a second database. Graph edges do not produce command records. Each subject UUID produces at most one command. Missing paths cannot identify a command and are skipped.

`path` gives the executable. `cmd` is tokenized according to the observed OS; its first token is removed only when it repeats that executable or its basename. Thus argument-only command fields retain their first argument. Duplicate ground-truth UUIDs are combined before joining. Matched processes are malicious, except ordinary desktop launches and normal browser helpers whose invocation supports benign use. Other commands are unknown. These process observations have no submitted shell input or recovered session; the shared writer supplies its per-record session fallback.
