# Windows-APT 2025

Windows-APT 2025 records 36 APT-inspired attack scenarios run with Caldera on Windows 10. Wazuh collected Windows and Sysmon events, including process launches, plus process inventory observations. The collection includes attacks and ordinary background activity.

## Mapping to the database

The reader takes commands from `source/combined.csv`. It uses Windows `commandLine` and `image` fields, or inventory `cmd` and `args`. Windows quoting is parsed into `pgm` and `args`, after decoding the CSV's additional escaping. These are process arguments, so `shell_input` is NULL and `other_tokens` is empty. An inventory executable beginning with `/` is recorded as Linux.

- `record_id` combines the source index, event ID and parsed-command position; missing IDs fall back to the CSV row.
- `session_id` combines `windows-apt-2025:`, computer and logon GUID. Missing/all-zero GUIDs fall back to observation day plus logon ID, process session, parent PID or source row.
- `group_id` is always NULL.

## Labels

The reader labels specifically matched collection and defense commands `benign`: Wazuh account checks and their linked `net1.exe` helpers, Defender's recorded `svchost.exe` launches, and VMware's default lifecycle scripts and linked `ipconfig.exe` helpers. Matches use the actual parent program, command and, for helpers, the parent's process GUID on the same computer. Merely being a child of one of these programs is insufficient.

For other command-line events, an ATT&CK technique ID or Wazuh rule 92031, 92039, 92052 or 92066 gives a best-effort `malicious` label. Remaining commands, including inventory observations, are `unknown`. Alert tags alone are imperfect evidence: Wazuh's own `net user administrator` check can carry T1087 and is handled by the benign rule above.

The scenario manifest describes the exercises but has no event IDs or run times that join individual commands to scenarios. These labels are derived by the reader, not a publisher-supplied per-command truth column. The rules are in [`scripts/_ingest_misc.py`](../../scripts/_ingest_misc.py) and [`scripts/_ingest_windows_apt_labels.py`](../../scripts/_ingest_windows_apt_labels.py).

## Ingestion

Run `./ingest` from this directory to append to the root `cmds.duckdb`. For a separate sample, run `./ingest --db ../../tmp/windows-apt.duckdb --limit 100`. Use a fresh database when evaluating changed labels; a completed import is skipped on later runs.

Sources: [Mendeley release](https://data.mendeley.com/datasets/b8fmtzvpy8/3), [publisher paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC12950481/). See the shared [database schema](../../schema.md) for column definitions.
