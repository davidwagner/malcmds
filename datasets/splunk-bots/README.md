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
