# COMISET

Windows endpoint events from ordinary university computer-lab use in July 2022 and a controlled red-team lab in November 2022. The dataset calls these environments `REAL` and `LAB`. It includes Sysmon and other Windows events collected with Winlogbeat and processed by the authors' EBDS/Elastic system.

`Comiset23_Lab_Environment_Dataset.zip` contains `dataset_comillas2.json`. `Comiset23_Real_Environment_Dataset.zip` contains `Comiset23_Real_Environment_Dataset.json`. Each JSON file has one Elasticsearch record per line, with `_index`, `_id`, and `_source`. Event fields are inside `_source`.

## Commands and fields

Sysmon process-creation records contain commands. The identifying fields are `source_name=Microsoft-Windows-Sysmon` and `event_id=1`. The JSON files also contain other Windows event types.

| Field | Meaning |
| --- | --- |
| `_index`, `_id` | Together identify a JSON record. |
| `CommandLine` | Full command line in Sysmon process events. |
| `ProcessCommandLine` | Command text included in other Windows event types. |
| `event_original_message` | Original Windows event text, including command and session details supplied by the event provider. |
| `event_original_time` | Original event timestamp. |
| `@timestamp` | Timestamp attached to the event in the processed logs. |
| `RuleName` | Rule annotation attached to the event; `-` indicates no rule name. |
| `rule_technique_id`, `rule_technique_name` | ATT&CK technique ID and name, such as `T1553.004` and `Install Root Certificate`. |
| `LogonGuid`, `LogonId`, `TerminalSessionId` | Windows login and terminal session identifiers in Sysmon records. |
| `host_name` | Machine name, used with numeric session identifiers to distinguish sessions on different machines. |

Numeric login IDs are local to a machine and can repeat after a restart.

## Labels

EBDS assigns ATT&CK annotations to individual events by matching public and author-written detection rules. A rule match identifies the behavior that triggered the rule. Both the ordinary-use data and red-team data contain rule matches, and the red-team data includes normal activity. The release supplies rule and technique annotations. Commands have no separate malicious/benign field; unmatched events have no attack annotation.

Sources: [dataset](https://zenodo.org/records/15375146), [paper, section 4.3](https://doi.org/10.1016/j.dib.2025.111723), [full paper XML](https://www.ebi.ac.uk/europepmc/webservices/rest/PMC12266566/fullTextXML), [Sysmon event reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

## Ingestion

Run `./datasets/comiset/ingest`. Both ZIP members are streamed as JSONL; the uncompressed files total approximately 1.1 TB and are never extracted. `CommandLine` and `ProcessCommandLine` carry observed commands, including process observations from providers other than Sysmon. An available executable field supplies `pgm`. The release's additional backslash escaping is removed before Windows argument parsing.

`record_id` contains archive/member path, Elasticsearch `_index:_id`, source line number and command ordinal. All commands receive `label=unknown` and `group_id=NULL`: detection-rule annotations describe matched behavior and do not establish malicious intent, including in the REAL collection.

`session_id` uses dataset, machine and nonzero `LogonGuid`; otherwise it uses archive scope, machine, original-event date and logon/terminal-session ID. Parent process ID/GUID, then user, supplies the fallback. `--max-records N` bounds the JSONL rows scanned; `--limit N` bounds commands stored, which may require scanning many more records.
