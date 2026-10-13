# DARPA Transparent Computing E5 — CADETS

CADETS records FreeBSD activity with DTrace. This dataset contains activity from DARPA Transparent Computing engagement E5, including scripted benign activity and red-team attacks. The files contain process, execution, file and network records in Avro format using Common Data Model version 20 (CDM20).

## Commands and fields

Commands appear in `Event.properties.cmdLine` on events whose `Event.type` is `EVENT_EXECUTE`. An example is `/usr/bin/resizewin -z`.

| Field | Meaning |
| --- | --- |
| `Event.uuid` | Unique event ID. |
| `Event.type` | Operation recorded by the event, such as `EVENT_EXECUTE` or `EVENT_FORK`. |
| `Event.timestampNanos` | Event time, in nanoseconds since the Unix epoch. |
| `Event.properties.cmdLine` | Command line, including arguments. |
| `Event.predicateObjectPath` | Path of the program executed. |
| `TCCDMDatum.hostId` | Computer ID used to match a record to an attack on that computer. |

The CDM schema has no common field for a login or connection session ID.

## Malicious and benign activity

`ground_truth/TA51_Final_report_E5.pdf` and its `.docx` version describe the red-team attacks: actions, affected computers, times, commands and file or network details. Commands are associated with an attack by matching these details to the event time, computer and command. The dataset contains both benign and malicious activity, and individual commands have no malicious/benign field.

## Sources

- [official E5 release notes](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README.md)
- [official release files](https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf)
- [CDM20 schema](https://drive.google.com/file/d/12_rZEiaPLQmFfnu0YUeMFMcqHxJWAg_D/view)
- [CDM design paper](https://www.usenix.org/system/files/tapp2020-paper-khoury.pdf)

## Ingestion

Run `./ingest` from this directory, or `datasets/tc-e5-cadets/ingest` from the repository root. The executable installs its declared Python dependencies with `uv`. It streams every completed Avro file in `data/`, including every binary member of E3 tar archives, into the root `cmds.duckdb`. A malformed record is reported with its source and Avro block number; the parser resumes at the next block, preserving the rest of the file. Incomplete download files (`.part` and `.part.bad`) are excluded. `--db PATH`, `--sample-files N --seed N`, `--max-records N` (per file), and `--limit N` support bounded validation.

Commands come from process `Subject.cmdLine` snapshots and `Event.properties.cmdLine` or `CommandLine` on execute events (also Windows process-creation/fork and exit events). The inner Avro union identifies the record type. Thread snapshots, executable-only Subject snapshots, placeholders, and process titles such as `sshd: admin [priv]` are excluded. Execution events with a full command field retain genuine zero-argument commands. These are captured process arguments: operators passed to a program remain arguments. Windows uses Windows quoting rules. Linux NUL-delimited vectors preserve argument boundaries; flattened strings use shell quoting rules without interpreting operators. For an unquoted shell `-c` payload with multiple words, the remainder is inferred to be the single script argument. CADETS uses the executed object's path as `pgm`; other collectors use argv[0]. TRACE audit hex tokens containing whitespace or quoting characters are decoded into single arguments.

- **`record_id`:** host identity, inner record type, source UUID, and a 16-character SHA-256 suffix over collector session, process UUID, timestamp and normalized command. The suffix distinguishes changed snapshots of the same Subject. Exact observations repeated as Subject, fork and execute records are collapsed when their process, timestamp and normalized command agree. Source UUIDs allow lookup in the original Avro records.
- **`session_id`:** `<dataset>:<host>:<sessionNumber>:ssh-tree:<child-UUID>` groups one direct child of an accepting SSH server with that child's descendants. For example, if server S creates A and B, and A creates C, then A and C share A's full UUID in their ID; B uses B's UUID.

  An `EVENT_ACCEPT` whose `properties.exec` is `sshd` (or a path ending in `/sshd`) identifies the server. Parents come from `Subject.parentSubject` and `EVENT_FORK`: the fork's `subject` is the parent and `predicateObject` is the child. A missing parent value adds no relationship; a later fork record can supply it. Each accepting server gets its own `<dataset>:<host>:<sessionNumber>:process:<process-UUID>` ID. A server nested under another server starts separate groups for its children. Missing parents, conflicting parents, cycles, or an ancestry with no accepting SSH server also give each affected process its own ID.

  These groups describe related process activity. Identifying authenticated logins would additionally require successful authentication records. The collector's `sessionNumber` separates recording runs. An all-zero/missing host UUID falls back to the filename's producer prefix before `.bin`, shared across numbered chunks.

  Relationships are collected in a temporary SQLite database across all selected files before commands are emitted, so later records can supply earlier commands' parents. `--limit` caps output commands but still scans those files; `--sample-files` and `--max-records` limit the source used for both commands and relationships.

- **Labels and `group_id`:** commands on a host/day with a documented attack receive `malicious-group`, with `group_id = dataset:host:attack-day:YYYY-MM-DD`. This is deliberately a coarse host/day group, including concurrent benign commands, rather than an individual malicious-command assertion. All other commands are `unknown`, with NULL `group_id`. The explicit date/instance mappings are in `scripts/_ingest_tc.py`. E3 uses UTC calendar days, without assuming a time zone for the report's clock times; E5 uses America/New_York, corroborated by the report's `date`/`nmap` output. Host instances for E5 come from the producer filename. Failed-only scenarios and benign setup sections do not create groups.

The E3 mapping follows ground-truth report sections 3–4. The E5 mapping follows sections 4.3–4.4, 5.2, 7.3, 8.4, 8.6, 9.3–9.4, 10.4, 10.6, 10.8 and 10.11. CADETS' FreeBSD records use the schema's `linux` value as its available Unix category.

Validation scanned 200,000 records from one file chosen with seed 3 and produced 393 commands. The end-to-end test reruns the same ingestion and checks unchanged rows, nonempty programs/session identifiers, valid labels and native DuckDB types. Inspection of longest program names and argument strings checked process-title filtering, TRACE hex decoding, shell `-c` payloads and Windows paths.
