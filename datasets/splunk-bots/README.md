# Splunk Boss of the SOC, version 3

BOTS v3 contains logs from a fictional organization's Windows and Unix/Linux systems, applications, cloud services and network. It was created for a security investigation competition. The data includes ordinary activity and attacks, with commands in process-creation events, Linux audit events and shell history.

## What the Splunk app contains

Splunk is software for storing, searching and analyzing logs. A Splunk **app** is a folder of files that extends or configures Splunk. It can contain settings, dashboards and data.

The BOTS app, `botsv3_data_set`, contains the event data already organized for searching in Splunk, plus configuration files that tell Splunk how to read it. The events belong to an index named `botsv3`. An index is a named collection of stored events that Splunk can search.

The app's `default/` directory contains configuration files. Its `var/lib/splunk/botsv3/db/` directory contains the events and search indexes. The event data combines multiple log formats and sources.

## Records containing commands

| Records | Command fields | Event ID, time and session |
| --- | --- | --- |
| Sysmon, source type `xmlwineventlog:microsoft-windows-sysmon/operational`, Event ID 1 | `CommandLine` contains the full command; `Image` names the program. | `UtcTime` and XML `System/TimeCreated/@SystemTime` give the event time. `EventRecordID` identifies the record within a computer's event log. `LogonGuid` identifies a Windows logon session; `LogonId` identifies it on a particular computer until restart. |
| Windows event logs, source type `wineventlog`, Security Event ID 4688 | The process-creation event contains the program name and, when command-line auditing is enabled, its command line. | Event time and record number identify the event within the computer's Security log. Subject and target logon IDs associate it with Windows logon sessions. |
| Linux audit, source type `linux_audit`, `type=EXECVE` | `argc` is the argument count; `a0`, `a1`, and subsequent fields give the program and arguments. `PROCTITLE` records can also contain the arguments in encoded form. The related `SYSCALL` record gives the executable in `exe`. | `msg=audit(timestamp:serial)` gives the event time and event number and connects records belonging to the same execution. The computer plus timestamp and serial identify the event. `ses` identifies the audit session on that computer until restart. |
| Shell history, source type `bash_history` | The raw record contains the text entered in the shell, including shell operators and quoting. | Some history records include timestamps. The history has no login-session ID. |
| Process lists, source types `osquery:results`, `ps`, `top`, `perfmonmk:process` | Process-list records contain running programs; the fields depend on the query or listing. For osquery, `columns.cmdline` contains a command line when the query includes that column. | The event time gives the time of the process listing. Repeated listings can include the same running command. |

Splunk's `_time` is the event timestamp, `_raw` contains the original event text, and `sourcetype` identifies its format. `host` identifies the computer and combines with Windows logon IDs or Linux audit session numbers to distinguish sessions on different computers. `source` identifies the originating log. `_cd` identifies an event's location within the Splunk index.

## Labels

The competition's incident questions describe attacks to investigate. The dataset has no per-command malicious/benign labels or session labels. It includes lookup tables such as ransomware file extensions and dynamic DNS providers; these can help identify suspicious activity while investigating an incident.

Sources: [official release and list of log sources](https://github.com/splunk/botsv3), [BOTS v3 archive](https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz).

## Ingestion

`./ingest` reads the original indexed archive using Splunk's native `exporttool`.
It uses `SPLUNK_HOME` when set; otherwise it downloads the pinned Splunk 9.1.3
Linux x86-64 distribution, verifies its SHA-256, and caches it under
`../../tmp/ingest/splunk`. It runs the offline exporter only. Extracted buckets
and CSV exports are cached under `../../tmp/ingest/`; source files are unchanged.

Commands come from Sysmon XML, rendered Windows process events, WinHostMon
process command lines, osquery `columns.cmdline`, Bash history, sudo messages,
joined Linux audit events, and `ps` process tables. WinHostMon's outer value
quotes are removed only when they wrap the entire value; quotes belonging to
the executable or its arguments are preserved for argument parsing. The `ps` collector separates COMMAND from
ARGS and joins arguments with underscores; ingestion restores those separators.
Process titles, kernel threads, `<noArgs>` rows, and `top`/performance listings
without arguments are excluded. Audit records join across buckets by host and
audit event ID. The release contains 112 audit records; the join retains these
small records while streaming all other sources.

- `record_id`: archive name, native index bucket name, exported event ordinal,
  and the XML event/JSON object/process-table row/shell-command ordinal as needed.
  Audit IDs additionally include the original `audit(timestamp:serial)` value.
- `label`: `unknown`; competition questions are not individual command labels.
- `group_id`: NULL.
- `session_id`: host and native LogonGuid when present; otherwise host, collection
  scope and numeric logon ID. Osquery uses host, UID, and parent PID (audit UID
  when no parent is present). Shell history uses host and history-file path;
  process tables add user and TTY. WinHostMon uses host, `ProcessId`, and
  `StartTime` to distinguish process instances when login/parent IDs are absent.
  Audit records use host, source and `ses`, with
  parent PID as fallback. All IDs start with `splunk-bots`.

The complete native export contains 1,944,094 source events across 17 buckets.
Use `--sample-files` to select buckets reproducibly and `--max-records` to bound
source records per selected bucket. Normal invocations process every bucket.

Full local validation ingested 320,479 commands from all 17 buckets. A seeded
bucket passed repeat-ingestion equality checks; a regression verifies that apt
history metadata produces only the recorded `apt-get install netcat` command.
