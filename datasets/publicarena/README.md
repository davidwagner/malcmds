# PublicArena

PublicArena contains Windows system events and user activity from attack exercises on a Windows 10 computer, Host A, and a Windows Server computer, Host B. System events include process creation, file access, program loading and network connections. `Process/Start` events contain the commands used to launch programs. `Process/Stop` events can repeat the command line when the program exits.

## Files

- `source/SystemAuditLogs/Host A win10/HostA-F-Lateral.*` contains Host A events in a split ZIP archive, including `HostA-F-Lateral/HostA-1-benign.json`.
- `source/SystemAuditLogs/Host B winserver/HostB-E-Insider-F-Lateral.*` contains Host B events in a split ZIP archive.
- `source/SystemAuditLogs/GroundTruth/{E-Insider-config,F-Lateral-config}/*.config` contains attack labels expressed as time ranges and process names.
- `source/AttackCampaignsDescriptions.xlsx` describes the attack scenarios. `source/AttackGraphs/*.pdf` shows the steps and relationships in each attack.
- `source/UserLogs/dataset.csv` contains file, web, logon and logoff activity. `source/UserLogs/groundtruth.csv` contains the malicious user-activity records. These CSVs have no process-launch commands.

## Command fields

The system event files contain one JSON record per line.

| Field | Meaning |
| --- | --- |
| `EventName` | `Process/Start` identifies a program launch. |
| `uuid` | Unique record ID. |
| `CommandLine` | Full command line. Quotes and other characters can be written as HTML entities, such as `&quot;` for `"`. |
| `timestamp` | Event time in seconds since the Unix epoch. |
| `date` | Event date and time in `MM/DD/YYYY HH:MM:SS` format, without a timezone. |
| `MSec` | Milliseconds from the start of event collection. |
| `SessionID` | Windows session number. Combined with `pc` and the session's logon/logoff times, it identifies the session; Windows can reuse session numbers. |
| `pc` | Computer name, used to identify the session and match the computer named in an attack description. |
| `PName` | Process name, used with the time and scenario to match attack labels. |

## Labels

Each attack `.config` file contains `[occurTime]` start and end times and `[PName]` process names. A command belongs to the labelled attack step when its computer and scenario match the configuration file, its time falls in the specified range, and its process name matches. Attack archives also contain benign activity.

The user-activity CSVs use `id` to identify records. Membership in `groundtruth.csv` marks a user-activity record as malicious. `pc` identifies the computer and `date` gives the activity time. These fields connect user actions with system events on the same computer at the same time; the CSVs have no shared command ID.

Sources: [publisher repository and file descriptions](https://github.com/security0528/PublicArena), [attack annotations](https://github.com/security0528/PublicArena/tree/main/SystemAuditLogs/GroundTruth).
