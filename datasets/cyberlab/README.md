# CyberLab honeynet

CyberLab records SSH and Telnet connections to a Cowrie honeynet in 2019–2020. It captures remote shell input on emulated Unix/Linux systems and, from November 2019, real Ubuntu instances. Daily `cyberlab_YYYY-MM-DD.json.gz` files contain JSON objects that group events by connection.

## Mapping to the database

The reader prefers original `cowrie.command.input` events. When a connection has no original input, it uses `cowrie.command.success` and `cowrie.command.failed` messages after removing Cowrie's prefixes. Handler echoes do not duplicate original input.

Shell input is split into program-and-argument rows. `shell_input` retains the original input, and `other_tokens` retains shell syntax outside the program and arguments. Handler-only messages have no complete `shell_input`.

- `record_id` identifies the daily file, connection object's position, connection ID, event position and parsed command.
- `session_id` combines `cyberlab:`, the daily file, destination host identifier (or sensor), and Cowrie connection ID.
- `label` is `malicious` for each retained remote command; `group_id` is NULL.

These labels are best-effort attribution to attacker input captured by the honeypot. Individual rows have not all been independently reviewed. An attacker-issued `uname -a` remains `malicious`, including when Cowrie reports failure; the label does not mean that the command's syntax is inherently harmful. The connection is still available in `session_id`.

## Ingestion

Run `./ingest` from this directory to append to the root `cmds.duckdb`. To inspect a separate sample, run `./ingest --db ../../tmp/cyberlab.duckdb --sample-files 2 --seed 83 --limit 100`. Repeated imports preserve one row per source command.

The published January 29, 2020 file is truncated. The reader retains its complete JSON objects.

Sources: [dataset and description](https://zenodo.org/records/3687527), [Cowrie event reference](https://docs.cowrie.org/en/latest/OUTPUT.html). See the shared [database schema](../../schema.md) for column definitions.
