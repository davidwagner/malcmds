# Linux-APT Dataset 2024

Linux logs from controlled attacks and background system activity collected through Wazuh from October 2023 to January 2024. The data includes system and authentication logs, configuration checks, file-change alerts, and other host events.

## Files

- `source/combine.csv` combines the 17 original CSV files of Wazuh alerts. Each row is a log record.
- `source/Processed Version.xlsx` is an Excel workbook: a spreadsheet file containing sheets of rows and columns. Its `combined` sheet contains a processed copy of the logs with fewer fields, a binary malicious/normal label, and ATT&CK tactics and techniques in separate columns. Its purpose is to supply the authors' labels alongside the original logs in `combine.csv`.
- `local_rules.xml` defines custom Wazuh rules used to identify suspicious activity and assign attack annotations.

## Commands and fields

Command records include sudo events, identified by `_source.decoder.name=sudo`. Their command appears in `_source.data.command` and after `COMMAND=` in `_source.full_log`. Other system log records can contain command text in `_source.full_log`.

| CSV column | Meaning |
| --- | --- |
| `_index`, `_id` | Together identify a record. |
| `_source.id` | Wazuh alert identifier. |
| `_source.data.command` | Command and arguments for records containing a command. |
| `_source.full_log` | Original log message, including the command and arguments for command records. |
| `_source.decoder.name`, `_source.decoder.parent` | Identify the log format Wazuh used to interpret the message. |
| `_source.timestamp`, `_source.@timestamp` | Alert timestamps. Values such as `Oct 1, 2023 @ 00:49:18.889` contain no timezone suffix. |
| `_source.predecoder.timestamp` | Timestamp from the original system log message. |
| `_source.rule.id`, `_source.rule.description`, `_source.rule.level` | Matching Wazuh rule, its description, and severity. |
| `_source.rule.mitre.id`, `_source.rule.mitre.tactic`, `_source.rule.mitre.technique` | ATT&CK annotations assigned by the rule. |
| `_source.agent.name` | Machine name used to associate a CSV record with its label in the workbook. |

The CSV has no general login-session identifier.

## Labels and their connection to commands

The workbook column `Malicious / General` uses `1` for suspicious/malicious records and `0` for general/normal records. These labels come from the Wazuh rules' ATT&CK annotations and apply to individual log records.

The relevant workbook headers are `timestamp`, `agent\.name`, `full_log`, `rule\.description`, `rule\.mitre\.tactic`, `rule\.mitre\.technique`, and `rule\.mitre\.id`. The backslashes are part of the column names.

The workbook omits the raw event IDs. Its `timestamp`, `agent\.name`, `full_log`, and `rule\.description` correspond to the CSV's `_source.timestamp`, `_source.agent.name`, `_source.full_log`, and `_source.rule.description`. Those values connect the binary labels to the command records in the CSV. Workbook sheet and row number identify an individual processed record; repeated combinations of the matching fields can correspond to multiple raw records.

Sources: [Mendeley version 2](https://data.mendeley.com/datasets/5x68fv63sh/2), [original CSV files and local rules](https://zenodo.org/records/10685642), [paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC11220842/).
