# PublicArena

Windows process and user activity from attack exercises on a Windows 10 host (A) and Windows Server host (B). The system audit records have ETW event names and process, file, image-load and TCP/IP events. These record process activity, including launches, rather than everything typed into a shell. The repository does not identify the collector implementation or publish a dataset license.

Run `./fetch` with Python 3.10+ and curl. It downloads the selected files from GitHub commit `ba3dbeb6d17df6d44a0a0fa727144f1619bae2ed`, preserves upstream paths beneath `source/`, verifies Git blob hashes, and keeps archives compressed. Completed files are skipped and partial downloads are resumed. `FETCH_LIST=1 ./fetch` lists files without downloading their payloads.

Files:

- `source/SystemAuditLogs/Host A win10/HostA-F-Lateral.z01` through `.z11`, plus `.zip`: one split ZIP archive of Host A audit JSONL files, including `HostA-F-Lateral/HostA-1-benign.json`.
- `source/SystemAuditLogs/Host B winserver/HostB-E-Insider-F-Lateral.z01` through `.z14`, plus `.zip`: the Host B split archive. All pieces of each archive are necessary; an individual `.zNN` is not an independent ZIP.
- `source/SystemAuditLogs/GroundTruth/{E-Insider-config,F-Lateral-config}/*.config`: attack annotations specifying occurrence-time intervals and process names.
- `source/AttackCampaignsDescriptions.xlsx` and `source/AttackGraphs/*.pdf`: scenario descriptions and attack graphs.
- `source/UserLogs/{dataset,groundtruth}.csv`: derived user activity and malicious user-activity rows. Included for labels and context; the inspected CSVs contain file, web, logon and logoff activities, with no process-launch commands.

The system JSONL sample was inspected directly. Relevant fields:

| Field | Use |
| --- | --- |
| `EventName` | Select `Process/Start` for launches. `Process/Stop` can also carry the command, so including both duplicates executions. |
| `CommandLine` | Complete launch command, with HTML entities such as `&quot;`; decode entities after JSON parsing. |
| `ImageFileName`, `PName`, `PPName` | Image, process name, and parent-process name; some are blank or `unknown`. |
| `uuid` | Record identifier. |
| `PID`, `ProcessID`, `ParentID`, `UniqueProcessKey`, `TID` | Process/thread correlation. Some numeric strings contain thousands separators. Scope process keys and PIDs to the host and process lifetime. |
| `timestamp`, `date`, `MSec` | Epoch-seconds field, formatted `MM/DD/YYYY HH:MM:SS`, and collector-relative milliseconds. The formatted date has no timezone annotation. |
| `SessionID`, `user`, `pc` | Windows session number, account and host. A session number alone is not globally unique or an attack label. |

For example, an inspected `Process/Start` record has `CommandLine` naming `NOTEPAD.EXE` and a text-file argument, `SessionID="2"`, a parent PID, and a unique record `uuid`.

Ground truth is not a malicious/benign field on every audit row. The `.config` files contain `[occurTime]` start/end timestamps and `[PName]` values, giving process/time criteria for attack steps. Match within the correct host and scenario, and retain uncertainty where these criteria match multiple process instances. A whole attack archive also contains benign activity. The CSV labels apply to **user-activity records**, joined by `id` (with `pc` and `date` for verification), not directly to each system process command. Their schema is an unnamed row-index column, `activity,user,pc,id,content,date`; `content` is an activity description, not a shell-command field. The repository calls `groundtruth.csv` malicious user logs but does not explain their annotation procedure further.

Source: [publisher repository and file descriptions](https://github.com/security0528/PublicArena), [audit annotations](https://github.com/security0528/PublicArena/tree/main/SystemAuditLogs/GroundTruth). Source inventory and representative audit/CSV records checked on 2026-10-02; the full archives were not downloaded for verification.
