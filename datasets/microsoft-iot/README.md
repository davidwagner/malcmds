# Microsoft IoT attack command sequences

Unix/Linux shell command sequences captured by Microsoft's IoT honeypot network during four months in 2019. The collection contains more than 125,000 distinct sequences seen over 150 million times. Repeated occurrences of a sequence are combined into one record with a count and the first and last times it appeared.

`Microsoft.IoT-Dump1.json` contains a JSON array of sequence records. Every record contains commands.

## Fields

| Field | Meaning |
| --- | --- |
| `Commands` | Ordered array of full command strings. A string can include pipelines, multiple commands, and other shell syntax. |
| `ID` | SHA-256 identifier for the sequence. This ID and a command's array position identify that command within the sequence. |
| `FirstSeen`, `LastSeen` | First and last times the sequence appeared. The timestamps contain fractional seconds and have no timezone suffix. |

The data has no individual connection/session ID or per-command timestamp.

## Labels

Microsoft describes the collection as malware and attack activity. That classification applies to the collected sequences, and each sequence's commands are grouped under its `ID`. The JSON has no separate malicious/benign field, and the collection has no benign partition.

Sources: [Microsoft release announcement](https://techcommunity.microsoft.com/t5/azure-sentinel/enabling-security-research-amp-hunting-with-open-source-iot/ba-p/1279037), [dataset in Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/blob/048039639702f528379307aca6f6881d74b142c8/Sample%20Data/Microsoft.IoT-Dump-pwd-infected.zip).

## Ingestion

Run `./ingest` to append commands to the root `cmds.duckdb`. Repeated runs preserve one row per source command. For a reproducible sample, use `./ingest --db ../../tmp/sample.duckdb --sample-files 2 --seed 83 --limit 100`.

The reader opens the publisher ZIP with password infected and streams its UTF-8-BOM JSON array. Commands are parsed as shell input. Aggregated repetitions are ingested once per recorded sequence.

`record_id` is sequence ID + zero-based Commands array index + normalized-command index. `session_id` and `group_id` are `microsoft-iot:` + sequence ID, the available grouping for these aggregated observations. All sequences have `label=malicious-group`, matching the publisher's honeypot attack collection.

Validation streamed the encrypted source and inspected 100 normalized commands. A real-data end-to-end test imports 50 commands twice and checks identical stored rows, identifiers, labels and typed argument lists.
