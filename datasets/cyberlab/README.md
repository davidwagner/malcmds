# CyberLab honeynet

SSH and Telnet connections to a distributed Cowrie honeynet in 2019–2020. The logs contain remote shell input and connection events targeting Unix/Linux. Early sessions use an emulated shell; from November 2019, the collection also includes sessions on real Ubuntu instances.

Daily files named `cyberlab_YYYY-MM-DD.json.gz` contain JSON arrays. Each element maps one session ID to an array of events. The filename date is the UTC day on which the connections began.

## Commands and fields

| Field | Meaning |
| --- | --- |
| `eventid` | Event type. Command events use `cowrie.command.success`, `cowrie.command.failed`, or `cowrie.command.input`. |
| `message` | Command text and a prefix indicating the event type. Successful command messages use `Command found: `; input messages use `CMD: `. The command follows the prefix. Failed-command events also contain command text. |
| `timestamp` | UTC event timestamp in ISO 8601 format. |
| `session_id` | Connection identifier, also used as the containing object's key. |
| `sensor`, `dst_host_identifier`, `dst_ip_identifier` | Identify the honeypot associated with a session. Together with the daily file and session ID, they distinguish connections across honeypots. |

A record can be identified by the filename, session object's position in the file, and event's position within that session. Events have no separate unique event ID.

## Labels

The publisher describes the honeypot connections as attack sessions. Commands are associated with those sessions through `session_id` and the containing JSON object. The files have no separate per-command malicious/benign field or benign dataset. The `success` and `failed` event types report how Cowrie handled a command.

Sources: [dataset description and files](https://zenodo.org/records/3687527), [Cowrie event reference](https://docs.cowrie.org/en/latest/OUTPUT.html).

## Ingestion

Run `./ingest` to append commands to the root `cmds.duckdb`. Repeated runs preserve one row per source command. For a reproducible sample, use `./ingest --db ../../tmp/sample.duckdb --sample-files 2 --seed 83 --limit 100`.

The reader streams daily compressed JSON arrays. It uses cowrie.command.input when a session contains original input; otherwise it reads success/failed command messages after removing their documented prefixes. This avoids counting Cowrie's handler echoes in addition to the original input. Shell syntax is parsed into individual commands.

`record_id` is daily filename + zero-based session-object index + session ID + event index + normalized-command index. `session_id` is `cyberlab:` + daily filename + destination host identifier (sensor fallback) + Cowrie session ID. Honeypot attack sessions have `label=malicious-group` and `group_id=session_id`.

Validation sampled daily files with seed 83 and checked 100 normalized commands. A real-data end-to-end test imports 50 commands twice and checks identical stored rows, identifiers, labels and typed argument lists.
