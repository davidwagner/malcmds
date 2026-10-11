# CyberLab honeynet

CyberLab records SSH and Telnet connections to a Cowrie honeynet in 2019–2020. It captures remote shell input on emulated Unix/Linux systems and, from November 2019, real Ubuntu instances. Daily `cyberlab_YYYY-MM-DD.json.gz` files contain JSON objects that group events by connection.

## Mapping to the database

The reader prefers original `cowrie.command.input` events. When a connection has no original input, it uses `cowrie.command.success` and `cowrie.command.failed` messages after removing Cowrie's prefixes. Handler echoes do not duplicate original input.

Each observed shell input produces one `SHELL_INPUTS` row. `shell_input` retains the complete input, `pgms` lists parsed program basenames, and `tokens` retains all source words and shell syntax. Parsed program-and-argument rows populate `PROCESS_LAUNCHES`. Handler-only messages populate only `PROCESS_LAUNCHES` because they lack complete shell input.

- Shell `record_id` identifies the daily file, connection object's position, connection ID and event position. Process rows append the parsed-command position.
- `session_id` combines `cyberlab:`, the daily file, destination host identifier (or sensor), and Cowrie connection ID.
- `dataset_label` is `malicious` for each retained remote input and command; `group_id` is NULL.

These labels are best-effort attribution to attacker input captured by the honeypot. Individual rows have not all been independently reviewed. An attacker-issued `uname -a` remains `malicious`, including when Cowrie reports failure; the label does not mean that the command's syntax is inherently harmful. The connection is still available in `session_id`.

## Ingestion

Run `./ingest` from this directory to append to the root `cmds.duckdb`. To inspect a separate sample, run `./ingest --db ../../tmp/cyberlab.duckdb --sample-files 2 --seed 83 --limit 100`. Repeated imports preserve one shell row per observed input and one process row per parsed invocation.

The published January 29, 2020 file is truncated. The reader retains its complete JSON objects.

Sources: [dataset and description](https://zenodo.org/records/3687527), [Cowrie event reference](https://docs.cowrie.org/en/latest/OUTPUT.html). See the shared [database schema](../../schema.md) for column definitions.
