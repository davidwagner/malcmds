# Windows-APT 2025

Windows-APT 2025 contains logs from 36 APT-inspired attack scenarios run with Caldera on Windows 10 computers. Wazuh collected Sysmon and Windows event logs. The data includes program launches, logons, network activity, registry changes and file changes. Process-creation events contain commands.

## Files

- `source/combined.csv` contains the merged event records.
- `source/scenario_manifest.csv` describes each attack scenario, the threat groups it represents, the tactics and techniques used, and the expected results.
- `source/validation_summary.csv` summarizes repeated runs and reviews of each scenario.

## Command fields

Sysmon process-creation records have `_source.data.win.system.providerName` equal to `Microsoft-Windows-Sysmon` and `_source.data.win.system.eventID` equal to `1`.

| Field | Meaning |
| --- | --- |
| `_index`, `_id` | Together, identify a record in the collection. |
| `_source.id` | Wazuh alert ID. |
| `_source.data.win.eventdata.commandLine` | Full command line. |
| `_source.data.win.eventdata.image` | Path of the program executed. |
| `_source.data.win.eventdata.utcTime` | UTC event time recorded by Sysmon. |
| `_source.data.win.system.systemTime` | Windows event time. |
| `_source.timestamp`, `_source.@timestamp` | Timestamps added while processing the event. |
| `_source.data.win.eventdata.logonGuid` | Windows logon-session GUID. |
| `_source.data.win.eventdata.logonId` | Windows logon-session number, used with the computer and the period between restarts. |
| `_source.data.win.eventdata.terminalSessionId` | Windows terminal-session number, used with the computer and that session's start and end times. |
| `_source.data.win.eventdata.subjectLogonId`, `_source.data.win.eventdata.targetLogonId` | Logon-session numbers in Windows Security events. |
| `_source.data.win.system.computer` | Computer name, needed to distinguish session numbers used on different computers. |

Process inventory records also contain commands: `_source.data.process.cmd` gives the command, `_source.data.process.args` gives its arguments, and `_source.data.process.start_time` gives the process start time. These records list running processes.

## Labels

The CSV has no binary malicious/benign column. Wazuh's rules identify suspicious activity and associate alerts with ATT&CK techniques:

| Field | Meaning |
| --- | --- |
| `_source.rule.id` | Rule that produced the alert. |
| `_source.rule.description` | Description of the activity matched by the rule. |
| `_source.rule.level` | Rule severity. |
| `_source.rule.mitre.id` | ATT&CK technique IDs associated with the alert. |
| `_source.rule.mitre.tactic`, `_source.rule.mitre.technique` | ATT&CK tactic and technique names. |

Both metadata CSVs use the column `Scenrario_ID` to identify scenarios. In the manifest, `Scenario_Name` names the scenario, `Mitre_Groups` lists the associated threat groups, `Simiulated Tactics` and `Simulated Techniques` describe the attacks, and `Expected_artifacts` describes their expected results. These column names include the publisher's spelling errors.

The event CSV has no scenario ID, and the manifest has no start or end times for scenario runs. The metadata therefore describes the scenarios without assigning individual commands to them. Attack runs include ordinary background activity.

Sources: [Mendeley version 3](https://data.mendeley.com/datasets/b8fmtzvpy8/3), [publisher paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC12950481/).

## Ingestion

Run `./ingest` to append commands to the root `cmds.duckdb`. Repeated runs preserve one row per source command. For a reproducible sample, use `./ingest --db ../../tmp/sample.duckdb --sample-files 2 --seed 83 --limit 100`.

The reader uses commandLine together with image when present and includes process inventory entries only when both cmd and args exist. Windows argument parsing follows CRT quoting rules; the extra JSON escaping retained in CSV backslashes is decoded once. Inventory paths beginning with / are Linux observations.

`record_id` is index + event ID + normalized-command index. `session_id` is `windows-apt-2025:` + computer + logonGuid. Missing/all-zero GUIDs fall back to observation day + logonId, process session, parent PID or source row. Labels remain unknown and `group_id` is NULL: rule severity and ATT&CK technique metadata are not individual malicious/benign labels, and the scenario manifest has no joinable event/time identifiers.

A complete validation run emitted 20,815 commands, including one Linux process-inventory observation. A real-data end-to-end test imports 50 commands twice and checks identical stored rows, identifiers, labels and typed argument lists.
