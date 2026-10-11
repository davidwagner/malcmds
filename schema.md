The native DuckDB database contains two observation tables. `PROCESS_LAUNCHES` records individual program executions, as an in-kernel logger could observe them. `SHELL_INPUTS` records complete inputs submitted to a command shell. A dataset that observes shell input populates both tables: one shell row per observed input and one process row per parsed program invocation.

Both tables have these columns:

- `dataset` - the original dataset, e.g., `optc` (VARCHAR).
- `record_id` - an identifier that locates the original record in the dataset (VARCHAR). Shell-derived process identifiers can include an additional invocation index.
- `dataset_label` - `malicious`, `benign`, `unknown`, or `malicious-group` (ENUM). `malicious-group` means the session or group is believed to contain malicious activity, but the particular observation is not individually labelled.
- `group_id` - the label group's identifier when `dataset_label` is `malicious-group`; otherwise NULL (VARCHAR).
- `session_id` - the login session, SSH connection, or other session identifier (VARCHAR). When unavailable, this defaults to an identifier derived from the dataset and record.
- `os` - `windows` or `linux`, inferred best-effort (ENUM).

`PROCESS_LAUNCHES` also has:

- `pgm` - the executable's full path, or its observed program name when the path is unavailable (VARCHAR).
- `pgm_base` - `pgm` with leading directory components removed (VARCHAR).
- `args` - the program's arguments, excluding `argv[0]` (LIST(VARCHAR)).

`SHELL_INPUTS` also has:

- `shell_input` - the complete observed input, preserved verbatim (VARCHAR).
- `pgms` - the basenames of the programs parsed from that input, in parser order, including repeated invocations (LIST(VARCHAR)).
- `tokens` - all source words and syntax tokens in source order, including program names, arguments, assignments, redirections, and command separators (LIST(VARCHAR)). Quotes and escapes are retained as written; whitespace separating tokens is omitted.

For example, `/bin/ls dir; ./go > out` produces one shell row with `pgms = ['ls', 'go']` and `tokens = ['/bin/ls', 'dir', ';', './go', '>', 'out']`. It also produces two process rows: `pgm = '/bin/ls', args = ['dir']` and `pgm = './go', args = []`. An observed assignment or other input with no parsed invocation still has a shell row with an empty `pgms` list. Repeated observations are retained, even when their input text is identical.

Native process telemetry populates only `PROCESS_LAUNCHES`. Shell strings passed as arguments to a native process remain arguments; they do not establish a separately observed shell submission. Parsing and normalization are best-effort and never execute captured input. A shell observation and the process rows derived from it are inserted in the same transaction.

The `INGESTED` table tracks completion across both observation tables:

- `dataset` - the dataset name (VARCHAR).
- `ingested` - true only after a complete ingestion run (BOOLEAN).

A failed or bounded run leaves `ingested = false`. Retrying replaces that dataset's rows in both tables. `--limit` counts emitted observations: one native process record or one complete shell input with all its parsed invocations. Parallel process batches retain one observation per process.

To migrate an existing `COMMANDS` database, run:

```sh
scripts/migrate_observations --db /path/to/cmds.duckdb
```

The script removes the old rows for `cyberlab`, `kypo`, `lade`, `microsoft-iot`, `quasarnix`, `shell-honeypot`, and `splunk-bots`; renames the remaining table to `PROCESS_LAUNCHES`; removes `shell_input` and `other_tokens`; and renames `label` to `dataset_label`. It creates `SHELL_INPUTS` and resets those seven datasets' completion markers in the same transaction, then reruns their ingest scripts against locally downloaded data. If reingestion fails, rerun the migration command to resume. `--schema-only` performs the conversion and leaves reingestion for a later run. The script refuses to discard shell data found in any other dataset.

Classifier evaluation selects an observation type explicitly: `scripts/eval_ai_classifiers --table PROCESS_LAUNCHES` (the default) or `--table SHELL_INPUTS`. Each run samples only the selected table.
