# DARPA Transparent Computing E5 — MARPLE

MARPLE records Windows activity. This dataset contains activity from DARPA Transparent Computing engagement E5, including scripted benign activity and red-team attacks. The files contain process, execution, file and network records in Avro format using Common Data Model version 20 (CDM20).

## Commands and fields

Commands appear in `Subject.cmdLine`. An example is `scp  -r C:\Users\admin\Pictures admin@128.55.12.119:./backup/`. An `EVENT_EXECUTE` event links to the Subject containing this command through `Event.predicateObject`. The record inside `TCCDMDatum.datum` identifies whether it is a Subject or Event; some of these records have an incorrect outer `type` value of `RECORD_HOST`.

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

The CDM schema has no common field for a login or connection session ID.

## Malicious and benign activity

`ground_truth/TA51_Final_report_E5.pdf` and its `.docx` version describe the red-team attacks: actions, affected computers, times, commands and file or network details. Commands are associated with an attack by matching these details to the event time, computer and command. The dataset contains both benign and malicious activity, and individual commands have no malicious/benign field.

Some MARPLE records have an all-zero `TCCDMDatum.hostId`. Filenames identify the MARPLE instance that produced each file, such as `ta1-marple-1-e5-official-1`.

## Sources

- [official E5 release notes](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README.md)
- [official release files](https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf)
- [CDM20 schema](https://drive.google.com/file/d/12_rZEiaPLQmFfnu0YUeMFMcqHxJWAg_D/view)
- [CDM design paper](https://www.usenix.org/system/files/tapp2020-paper-khoury.pdf)

## Ingestion

Run `./ingest` from this directory, or `datasets/tc-e5-marple/ingest` from the repository root. The executable installs its declared Python dependencies with `uv`. It streams every completed Avro file in `data/`, including every binary member of E3 tar archives, into the root `cmds.duckdb`. A malformed record is reported with its source and Avro block number; the parser resumes at the next block, preserving the rest of the file. Incomplete download files (`.part` and `.part.bad`) are excluded. `--db PATH`, `--sample-files N --seed N`, `--max-records N` (per file), and `--limit N` support bounded validation.

Commands come from process `Subject.cmdLine` snapshots and `Event.properties.cmdLine` or `CommandLine` on execute events (also Windows process-creation/fork and exit events). The inner Avro union identifies the record type. Thread snapshots, executable-only Subject snapshots, placeholders, and process titles such as `sshd: admin [priv]` are excluded. Execution events with a full command field retain genuine zero-argument commands. These are captured process arguments: operators passed to a program remain arguments. Windows uses Windows quoting rules. Linux NUL-delimited vectors preserve argument boundaries; flattened strings use shell quoting rules without interpreting operators. For an unquoted shell `-c` payload with multiple words, the remainder is inferred to be the single script argument. CADETS uses the executed object's path as `pgm`; other collectors use argv[0]. TRACE audit hex tokens containing whitespace or quoting characters are decoded into single arguments.

- **`record_id`:** host identity, inner record type, source UUID, and a 16-character SHA-256 suffix over collector session, process UUID, timestamp and normalized command. The suffix distinguishes changed snapshots of the same Subject. Exact observations repeated as Subject, fork and execute records are collapsed when their process, timestamp and normalized command agree. Source UUIDs allow lookup in the original Avro records.
- **`session_id`:** dataset, host identity and CDM collector `sessionNumber`, followed by the native Windows `SessionId`/`SessionID` when present. Otherwise it uses the Subject's `parentSubject` UUID, falling back to the process UUID. Events join the preceding Subject records through UUID to obtain that parent. This groups sibling processes under the same parent; it does not claim that collector `sessionNumber` is a login ID. A disk-backed temporary index bounds memory use. An all-zero/missing host UUID falls back to the filename's stable producer prefix before `.bin`, shared across numbered chunks.
- **Labels and `group_id`:** MARPLE-2 and MARPLE-3 commands are `benign`. MARPLE-1 commands are `benign` outside the two documented attacks: May 9, 2019, 13:57–14:02 and May 17, 2019, 13:00–13:29, US Eastern daylight time (UTC−04:00). Each interval includes the full ending minute. Unknown filename instances or missing timestamps remain `unknown`. Benign and unknown commands have NULL `group_id`.

Within those intervals on MARPLE-1, the existing attack-label rules apply. A matching process or other direct annotation can give `malicious`; remaining commands receive `malicious-group` with `group_id = dataset:host:episode:first-last`, where `first` and `last` are Unix nanoseconds. A group contains an attack and may also contain benign commands. The intervals and annotation rules are in `scripts/_tc_attacks.json`; `TCAnnotations.label()` in `scripts/_tc_labels.py` applies them.

The [official E5 report](https://drive.google.com/file/d/1cc3C5JW-Kn-VdXqeBGwvHBKSdR_YmSGj/view) describes these two MARPLE attacks in sections 4.4 and 10.8 and summarizes them in section 11.2.6 (pages 139–140). Both targeted MARPLE-1 (`128.55.12.66`). These are best-effort benign labels based on the report. Its unexplained May 13 Mimikatz alert has no confirmed attack, host or time range; the labels accept that uncertainty. A browser launched before an attack stays benign even when its process is later annotated as compromised. For example, MARPLE-1 `firefox.exe` at May 9 13:56:59 is benign; at 13:57:00 the attack rules apply.

On October 10, 2026, validation of the benign-label rule compared separate old and new databases using the first 200,000 source records from each of all 55 installed files (11,000,000 records total). The sample produced 40,390 commands, all changing from `unknown` to `benign`: 15,611 on MARPLE-1, 8,127 on MARPLE-2 and 16,652 on MARPLE-3. All other fields stayed identical, and every benign command had NULL `group_id`. This bounded sample contained no previously labeled attack commands; the native CDM20 regression test checks both attack intervals and their exact nanosecond endpoints separately. These counts describe the sample, not the full corpus. The existing database was not refreshed.
