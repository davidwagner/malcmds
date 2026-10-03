# ATLASv2

Windows endpoint logs from two Windows 7 virtual machines used as researchers' primary workstations in July 2022. Four days of benign activity precede ten attack scenarios: four on a single machine and six involving both machines. Ordinary activity continues during the attacks. The dataset includes Sysmon, Windows Security, Carbon Black, Firefox, and DNS logs.

`atlasv2/data/{benign,attack}/{h1,h2}/` groups the logs by collection period and machine. Attack scenarios are named `s1`–`s4` and `m1`–`m6`. Sysmon and Windows Security logs are XML files; Carbon Black logs are JSONL files.

## Commands and fields

Sysmon process-creation records contain commands. They have provider `Microsoft-Windows-Sysmon` and event ID `1`. The fields below are named entries in `EventData`, except for paths beginning with `System/`.

| Field | Meaning |
| --- | --- |
| `CommandLine` | Full command line. |
| `Image` | Executable path. |
| `System/EventRecordID` | Event number. Machine and event channel together with this number identify a record. |
| `System/Computer`, `System/Channel` | Machine and event channel used to identify records. |
| `UtcTime` | UTC time of process creation. |
| `System/TimeCreated/@SystemTime` | Windows event timestamp. |
| `LogonGuid`, `LogonId`, `TerminalSessionId` | Login and terminal session identifiers when included. Numeric session identifiers are local to a machine and can repeat after a restart. |
| `ProcessGuid`, `ProcessId` | Process identifiers used to associate commands with process labels. |

## Labels

The `benign` directory contains ordinary activity. The `attack` directory contains attacks alongside ordinary activity.

REAPr `.labels` files contain process labels. Their comma-separated fields are:

| Field | Meaning |
| --- | --- |
| `attack` | Attack scenario. |
| `process_name` | Process name. |
| `process_id` | Numeric process ID. |
| `process_uuid` | Process identifier in the authors' attack graphs. |
| `label` | Process classification, including `attack`. The methodology distinguishes malicious, contaminated, and benign processes; contaminated processes are those affected by the attack. |

The `.seeds` files identify processes used as starting points for tracing an attack. `atlasv2_attack_igraphs.tar.gz` contains the attack graphs that connect those processes to other activity. The graph's `process_uuid`, scenario, machine, process ID, and process lifetime provide the information for associating a process label with its command records. Sysmon's `ProcessGuid` and the graph's `process_uuid` use their respective systems' identifiers.

Sources: [dataset repository](https://bitbucket.org/sts-lab/atlasv2), [paper](https://arxiv.org/abs/2401.01341), [REAPr label methodology](https://bitbucket.org/sts-lab/reapr-ground-truth), [Sysmon event reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
