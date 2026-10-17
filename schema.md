cmds.duckdb contains two tables:
- `PROCESS_LAUNCHES` records individual program executions, as an in-kernel logger could observe them.
- `SHELL_INPUTS` records complete inputs submitted to a command shell.
A dataset that records shell input populates both tables: one shell row per observed input and one process row per parsed program invocation.

Both tables have these columns:

- `dataset` - the original dataset, e.g., `optc` (VARCHAR).
- `record_id` - an identifier that locates the original record in the dataset (VARCHAR). Shell-derived process identifiers can include an additional invocation index.
- `dataset_label` - label for this single command, `malicious`, `benign`, `unknown`, or `malicious-group` (ENUM). `malicious-group` means the group identified by `group_id` is believed to contain some malicious activity, but it's not known which commands are malicious and which are benign (each command is not individually labelled).
- `group_id` - the label group's identifier when `dataset_label` is `malicious-group`; otherwise NULL (VARCHAR).
- `session_id` - the login session, SSH connection, recorded agent task attempt, or other session identifier (VARCHAR).
- `os` - `windows` or `linux`, inferred best-effort (ENUM).
- `ai_label` - `malicious`, `benign`, or `unknown`, obtained by an AI classifier (ENUM)

Label policy:
- 'malicious' means the command is malicious, or evidence of an intrusion; commands that should trigger an alert to a sysadmin. If something looks like a security scan but it's ambiguous whether it is authorized or unauthorized, still label it 'malicious'.
- 'benign' means the command is benign, harmless, does not contain evidence of an intrusion, should not trigger an alert to a system admin.
- 'unknown' means it is unclear whether the command is malicious or benign.

`PROCESS_LAUNCHES` also has:

- `pgm` - the executable's full path, or its observed program name when the path is unavailable (VARCHAR).
- `pgm_base` - `pgm` with leading directory components removed (VARCHAR).
- `args` - the program's arguments, excluding `argv[0]` (LIST(VARCHAR)).

`SHELL_INPUTS` also has:

- `shell_input` - the complete input line to the command shell, preserved verbatim, as recorded in the dataset (VARCHAR).
- `pgms` - the basenames of the programs parsed from that input, including repeated invocations (LIST(VARCHAR)).
- `tokens` - all source words and syntax tokens, including program names, arguments, assignments, redirections, and command separators (LIST(VARCHAR)). Quotes and escapes are retained as written; whitespace separating tokens is omitted.

For example, `/bin/ls dir; ./go > out` produces one shell row with `pgms = ['ls', 'go']` and `tokens = ['/bin/ls', 'dir', ';', './go', '>', 'out']`. It also produces two process rows: `pgm = '/bin/ls', args = ['dir']` and `pgm = './go', args = []`.

Native process telemetry populates only `PROCESS_LAUNCHES`. Parsing and normalization are best-effort.

`SESSION_LABELS` labels each session, and has these rows:
- `dataset`
- `session_id`
- `ai_label` - label for this session considered in its entirety, `malicious`, `benign`, or `unknown`, obtained by an AI classifier (ENUM)


The `INGESTED` table tracks completion across both observation tables:

- `dataset` - the dataset name (VARCHAR).
- `ingested` - true only after a complete ingestion run finishes (BOOLEAN).

A failed or bounded run leaves `ingested = false`. Retrying replaces that dataset's rows in both tables.
