# Microsoft IoT attack command sequences

Microsoft's IoT honeypots captured Unix/Linux malware and attack command sequences during four months in 2019. Repeated observations of the same sequence are combined into one record with a count and first/last observation times. A sequence is an aggregate, not an individual connection.

## Mapping to the database

The reader opens `Microsoft.IoT-Dump-pwd-infected.zip` with the publisher's password, `infected`. Its JSON records contain an `ID` and an ordered `Commands` array. Each shell input is parsed into program-and-argument rows; `shell_input` retains that input and `other_tokens` retains the remaining shell syntax. Repeated observations are imported once per recorded sequence.

- `record_id` combines the sequence ID, zero-based `Commands` position and parsed-command position.
- `session_id` is `microsoft-iot:` followed by the sequence ID. It groups the recorded sequence; individual connection IDs are unavailable.
- `label` is `malicious` for every parsed command; `group_id` is NULL.

These are best-effort labels attributing commands to malware/attack input captured by the publisher's honeypots. Individual rows have not all been independently reviewed. For example, `uname -a` in an attacker sequence stays `malicious`, although administrators also use it. Normalized row counts are counts of commands, not connections or distinct sequences.

## Ingestion

Run `./ingest` from this directory to append to the root `cmds.duckdb`. For a separate sample, run `./ingest --db ../../tmp/microsoft-iot.duckdb --limit 100`. Repeated imports preserve one row per source command.

Sources: [Microsoft announcement](https://techcommunity.microsoft.com/t5/azure-sentinel/enabling-security-research-amp-hunting-with-open-source-iot/ba-p/1279037), [published archive](https://github.com/Azure/Azure-Sentinel/blob/048039639702f528379307aca6f6881d74b142c8/Sample%20Data/Microsoft.IoT-Dump-pwd-infected.zip). See the shared [database schema](../../schema.md) for column definitions.
