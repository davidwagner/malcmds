# Splunk Attack Data

Splunk Attack Data contains security logs from attack exercises, including Atomic Red Team and Attack Range tests. It covers Windows, Unix/Linux, macOS and ESXi systems. Commands appear in process-creation events, Linux audit records, PowerShell logs and process lists. Each exercise has a description and associated log files. The logs include both attack activity and background activity.

Files under `source/` include Windows XML events, Windows events rendered as text, Linux audit and syslog records, and JSON records. Some files contain events exported from Splunk. YAML files describe the exercises and identify their logs.

## Records containing commands

| Records | Command fields | Event ID, time and session |
| --- | --- | --- |
| Windows or Linux Sysmon, Event ID 1 | `CommandLine` is the full command line; `Image` names the program. | `UtcTime` and XML `System/TimeCreated/@SystemTime` give the event time. `System/EventRecordID` identifies the record within a computer's event log. Windows records can include `LogonGuid` or `LogonId` for the logon session. |
| Windows Security, Event ID 4688 | `CommandLine` gives the command line and `NewProcessName` gives the executable. Command lines are empty when command-line auditing is disabled. | `TimeCreated` gives the time. `EventRecordID` identifies the record within a computer's Security log. `SubjectLogonId` and `TargetLogonId` identify the associated Windows logon sessions. |
| PowerShell Operational, Event ID 4104 | `ScriptBlockText` contains the PowerShell code. `ScriptBlockId` connects pieces of the same script; `MessageNumber` orders them and `MessageTotal` gives the number of pieces. | The Windows event time and record number identify each event within the computer's PowerShell log. |
| Linux audit, `type=EXECVE` | `argc` gives the argument count; `a0`, `a1`, and subsequent fields contain the program and arguments. `PROCTITLE` records also contain arguments, sometimes encoded. The related `SYSCALL` record gives the executable in `exe`. | `msg=audit(time:serial)` contains the timestamp and event number and connects records from the same execution. The computer plus time and serial identify the event. `ses` identifies the audit session on that computer until restart. |
| osquery process queries | `columns.cmdline` contains the command line when included by the query; `columns.path` gives the executable path. | `unixTime` or `calendarTime` gives the query time. Process lists can include the same running command in successive queries. |

Windows logon IDs are used together with the computer and the period between restarts. Windows event record numbers are used together with the computer and log name; numbering can restart after a log is cleared. Field names and formatting differ between XML, text and JSON files.

## Labels

The YAML file for each exercise contains:

| Field | Meaning |
| --- | --- |
| `id` | Unique ID of the exercise. |
| `date` | Date associated with the exercise. |
| `description` | Attack actions performed during the exercise. |
| `mitre_technique` | ATT&CK technique tested. |
| `datasets[].path` | Log file belonging to the exercise; connects the attack description to its events. |
| `datasets[].source`, `datasets[].sourcetype` | Source and format of the log records. |

The description and ATT&CK technique identify the attack being tested. They apply to the exercise, whose logs also contain ordinary activity. Individual commands have no common malicious/benign field across the collection. Attack commands can be identified by matching the actions in the exercise description to commands in its log files.

Sources: [publisher repository](https://github.com/splunk/attack_data), [source files](https://github.com/splunk/attack_data/tree/a28608b53aa3d8222052e8f3ada59e2d9a4adfff), [scenario catalog](https://research.splunk.com/attack_data/).
