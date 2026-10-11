# Windows-APT 2025

Windows-APT 2025 records 36 APT-inspired attack scenarios run with Caldera on Windows 10. Wazuh collected Windows and Sysmon events, including process launches, plus process inventory observations. The collection includes attacks and ordinary background activity.

## Mapping to the database

The reader takes commands from `source/combined.csv`. It uses Windows `commandLine` and `image` fields, or inventory `cmd` and `args`. Windows quoting is parsed into `pgm` and `args`, after decoding the CSV's additional escaping. These are process arguments, so `shell_input` is NULL and `other_tokens` is empty. An inventory executable beginning with `/` is recorded as Linux.

- `record_id` combines the source index, event ID and parsed-command position; missing IDs fall back to the CSV row.
- `session_id` combines `windows-apt-2025:`, computer and logon GUID. Missing/all-zero GUIDs fall back to observation day plus logon ID, process session, parent PID or source row.
- `group_id` is always NULL.

## Labels

The reader labels specifically matched collection and defense commands `benign`: Wazuh account checks and their linked `net1.exe` helpers, Defender's recorded `svchost.exe` launches, and VMware's default lifecycle scripts and linked `ipconfig.exe` helpers. Matches use the actual parent program, command and, for helpers, the parent's process GUID on the same computer. Merely being a child of one of these programs is insufficient.

Other command events follow the policy in [issue #115](https://github.com/davidwagner/malcmds/issues/115):

1. Inspect the complete visible operation and the documented UAC-bypass parent context. Specific command decisions take priority over rule and tag defaults, including an explicit `unknown` decision.
2. Use the rule's entry in `RULE_DEFAULTS` when present. A mapped `unknown` ends the decision.
3. For an absent rule, use exact ATT&CK IDs from `TAG_DEFAULTS`. Any malicious tag gives `malicious`; a nonempty list of only benign tags gives `benign`; other combinations give `unknown`.

`malicious` means visible attack behavior, identifiable attack preparation, or a verified attack-related parent relationship. It includes authorized attack exercises. `benign` means the observed operation is routine, harmless, or restores an ordinary setting. `unknown` means the command is ambiguous or its relevant payload is unavailable. Inventory observations remain `unknown`.

For example, SAM extraction and Temp-directory system-process impersonators are malicious. Ordinary account queries, the observed local log export, and restoration of RDP authentication are benign. Enabling Guest, changing RDP to port 4489, and invoking unavailable scripts are unknown. Specific benign or unknown decisions survive conflicting broad tags.

A shell launched by `fodhelper`, or an auto-elevated utility launched after the observed `ms-settings` registry hijack, receives a malicious event label before considering a harmless-looking child operation. Other parent names alone do not establish maliciousness. Compound shell commands are malicious when an identifiable attack operation is visible, benign when all operations are understood and benign, and unknown otherwise.

Encoded PowerShell is decoded as data for inspection; undecodable payloads are unknown. The stored command arguments retain the source encoding. Recognizers cover the observed syntax and conservatively retain unknown decisions for unsupported shell expressions. The tables describe this collection: they are best-effort judgments, not general classifications of ATT&CK techniques.

The scenario manifest describes the exercises but has no event IDs or run times that join individual commands to scenarios. These labels are derived by the reader, not a publisher-supplied per-command truth column. The rules are in [`scripts/_ingest_misc.py`](../../scripts/_ingest_misc.py) and [`scripts/_ingest_windows_apt_labels.py`](../../scripts/_ingest_windows_apt_labels.py).

## Ingestion

Run `./ingest` from this directory to append to the root `cmds.duckdb`. For a separate sample, run `./ingest --db ../../tmp/windows-apt.duckdb --limit 100`. Use a fresh database when evaluating changed labels; a completed import is skipped on later runs.

Sources: [Mendeley release](https://data.mendeley.com/datasets/b8fmtzvpy8/3), [publisher paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC12950481/). See the shared [database schema](../../schema.md) for column definitions.
