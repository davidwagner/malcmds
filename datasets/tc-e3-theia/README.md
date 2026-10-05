# DARPA Transparent Computing E3 — THEIA

THEIA records Linux activity with kernel instrumentation. This dataset contains activity from DARPA Transparent Computing engagement E3, including scripted benign activity and red-team attacks. The files contain process, execution, file and network records in Avro format using Common Data Model version 18 (CDM18).

## Commands and fields

Commands appear in `Subject.cmdLine`. An example is `/bin/sh -e /proc/self/fd/9`. Events refer to these Subject records by UUID. The command field also contains process names and titles.

| Field | Meaning |
| --- | --- |
| `Event.uuid` | Unique event ID. |
| `Event.type` | Operation recorded by the event, such as `EVENT_EXECUTE` or `EVENT_FORK`. |
| `Event.timestampNanos` | Event time, in nanoseconds since the Unix epoch. |
| `Subject.uuid` | Unique Subject ID, used to associate the command with events. |
| `Subject.cmdLine` | Command line, including arguments, or the process name or title. |
| `Subject.startTimestampNanos` | Start time, in nanoseconds since the Unix epoch. |
| `Event.subject` | UUID of the Subject performing the operation; joins to `Subject.uuid`. |
| `Event.predicateObject` | UUID of the target of the operation. When the target is a Subject, it joins to `Subject.uuid` for its command. |
| `Event.hostId` | Computer ID used to match an event to an attack on that computer. |

The CDM schema has no common field for a login or connection session ID.

## Malicious and benign activity

`ground_truth/TC_Ground_Truth_Report_E3_Update.pdf` describes the red-team attacks: actions, affected computers, times, commands and file or network details. Commands are associated with an attack by matching these details to the event time, computer and command. The dataset contains both benign and malicious activity, and individual commands have no malicious/benign field.

## Sources

- [official E3 release notes](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README-E3.md)
- [official release files](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK)
- [CDM18 schema](https://drive.google.com/file/d/1zVKApkZwuPsk3y8BnR1bWTqze929y1qp/view)
- [CDM design paper](https://www.usenix.org/system/files/tapp2020-paper-khoury.pdf)
- [THEIA contributor project description](https://www.evandowning.com/pages/projects.html)

## Ingestion

Run `./ingest` from this directory, or `datasets/tc-e3-theia/ingest` from the repository root. The executable installs its declared Python dependencies with `uv`. It streams every completed Avro file in `data/`, including every binary member of E3 tar archives, into the root `cmds.duckdb`. A malformed record is reported with its source and Avro block number; the parser resumes at the next block, preserving the rest of the file. Incomplete download files (`.part` and `.part.bad`) are excluded. `--db PATH`, `--sample-files N --seed N`, `--max-records N` (per file), and `--limit N` support bounded validation.

Commands come from process `Subject.cmdLine` snapshots and `Event.properties.cmdLine` or `CommandLine` on execute events (also Windows process-creation/fork and exit events). The inner Avro union identifies the record type. Thread snapshots, executable-only Subject snapshots, placeholders, and process titles such as `sshd: admin [priv]` are excluded. Execution events with a full command field retain genuine zero-argument commands. These are captured process arguments: operators passed to a program remain arguments. Windows uses Windows quoting rules. Linux NUL-delimited vectors preserve argument boundaries; flattened strings use shell quoting rules without interpreting operators. For an unquoted shell `-c` payload with multiple words, the remainder is inferred to be the single script argument. CADETS uses the executed object's path as `pgm`; other collectors use argv[0]. TRACE audit hex tokens containing whitespace or quoting characters are decoded into single arguments.

- **`record_id`:** host identity, inner record type, source UUID, and a 16-character SHA-256 suffix over collector session, process UUID, timestamp and normalized command. The suffix distinguishes changed snapshots of the same Subject. Exact observations repeated as Subject, fork and execute records are collapsed when their process, timestamp and normalized command agree. Source UUIDs allow lookup in the original Avro records.
- **`session_id`:** dataset, host identity and CDM collector `sessionNumber`, followed by the native Windows `SessionId`/`SessionID` when present. Otherwise it uses the Subject's `parentSubject` UUID, falling back to the process UUID. Events join the preceding Subject records through UUID to obtain that parent. This groups sibling processes under the same parent; it does not claim that collector `sessionNumber` is a login ID. A disk-backed temporary index bounds memory use. An all-zero/missing host UUID falls back to the filename's stable producer prefix before `.bin`, shared across numbered chunks.
- **Labels and `group_id`:** commands on a host/day with a documented attack receive `malicious-group`, with `group_id = dataset:host:attack-day:YYYY-MM-DD`. This is deliberately a coarse host/day group, including concurrent benign commands, rather than an individual malicious-command assertion. All other commands are `unknown`, with NULL `group_id`. The explicit date/instance mappings are in `datasets/_ingest_tc.py`. E3 uses UTC calendar days, without assuming a time zone for the report's clock times; E5 uses America/New_York, corroborated by the report's `date`/`nmap` output. Host instances for E5 come from the producer filename. Failed-only scenarios and benign setup sections do not create groups.

The E3 mapping follows ground-truth report sections 3–4. The E5 mapping follows sections 4.3–4.4, 5.2, 7.3, 8.4, 8.6, 9.3–9.4, 10.4, 10.6, 10.8 and 10.11. CADETS' FreeBSD records use the schema's `linux` value as its available Unix category.

Validation scanned 200,000 records from one file chosen with seed 3 and produced 180 commands. The end-to-end test reruns the same ingestion and checks unchanged rows, nonempty programs/session identifiers, valid labels and native DuckDB types. Inspection of longest program names and argument strings checked process-title filtering, TRACE hex decoding, shell `-c` payloads and Windows paths.
