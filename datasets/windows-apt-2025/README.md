# Windows-APT 2025

Run `./fetch` with Python 3.10+ and curl. It downloads the pinned Mendeley **version 3**
files below into `source/`, checks published hashes, reuses completed files and
resumes partial transfers. The publisher supplies uncompressed CSV files.

This is a **Windows** laboratory dataset: Caldera emulated 36 APT-inspired
scenarios on Windows 10 hosts; Sysmon and Windows event logs were collected by
Wazuh. Events include process creation, logons, network activity, registry/file
changes and other alerts. Commands primarily describe process launches, not all
text typed into an existing shell. It is licensed CC BY 4.0.

## Downloaded files

- `source/combined.csv` (247,934,817 bytes): the merged log collection. Date-range
  CSV shards are redundant and are omitted.
- `source/scenario_manifest.csv`: scenario names, threat-group associations,
  simulated tactics/techniques and expected artifacts.
- `source/validation_summary.csv`: per-scenario repeated-run success and review
  summaries.
- `source/checksums.sha256` and `source/README.md`: publisher checksums and guide.
  The upstream guide mentions example scripts that are absent from the inspected
  v3 file listing.

The combined file is UTF-8 CSV with a BOM, literal dotted headers, CSV-escaped
raw messages, and many empty fields. Use a CSV parser (`utf-8-sig` handles the
BOM), not a line splitter.

## Relevant schema

The following literal columns were verified in the combined CSV header.

| Purpose | Columns and interpretation |
| --- | --- |
| Command | `_source.data.win.eventdata.commandLine`; executable `_source.data.win.eventdata.image`; parent fields `_source.data.win.eventdata.parentCommandLine` and `.parentImage`. `_source.full_log` and `_source.data.win.system.message` retain source event text. |
| Process-event filter | `_source.data.win.system.providerName` = `Microsoft-Windows-Sysmon` with `_source.data.win.system.eventID` = `1` identifies Sysmon process creation. Other providers use different event IDs; do not filter ID 1 alone. |
| Inventory alternative | `_source.data.process.cmd`, `.args`, `.name`, `.pid`, `.ppid`, `.start_time` are present for inventory-like process records; verify `_source.data.type` and raw event before treating them as launches. |
| Time | `_source.data.win.eventdata.utcTime`, `_source.data.win.system.systemTime`; collection/export times `_source.timestamp` and `_source.@timestamp`. |
| Record ID | `_index` plus `_id`; `_source.id` is the Wazuh alert ID. `_source.data.win.system.eventRecordID` must be scoped to computer/channel/log lifetime. |
| Process identity | `_source.data.win.eventdata.processGuid`, `.parentProcessGuid`, `.processId`, `.parentProcessId`; scope PIDs to host/time. |
| Host/user | `_source.agent.id`, `_source.agent.name`, `_source.data.win.system.computer`, `_source.data.win.eventdata.user`. |
| Session | `_source.data.win.eventdata.logonId`, `.logonGuid`, `.terminalSessionId`; security events also expose `.subjectLogonId` and `.targetLogonId`. Availability depends on event type. Scope IDs to host and boot/logon lifetime; terminal session, logon and process are different identifiers. |
| ATT&CK/rule | `_source.rule.mitre.id`, `.tactic`, `.technique`; `_source.rule.id`, `.description`, `.level`. |

Here `.field` in a table row continues the full prefix immediately preceding it.
A nonempty `_source.data.sca.check.command` is a configuration-check definition,
not necessarily a user command. The broad merged schema also has Linux-style
columns; their presence alone does not establish a Linux command corpus.

## Labels and scenario context

There is **no dedicated binary malicious/benign column in the inspected combined
header**. Wazuh rules supply per-alert ATT&CK mappings. Deriving a binary label
from those mappings produces detection-rule labels: absence of a match is not
proof of benign execution. Background events can occur during attack scenarios.

Both metadata CSVs spell their join column **`Scenrario_ID`**. The manifest has
`Scenario_Name`, `Mitre_Groups`, `Simiulated Tactics` (also misspelled),
`Simulated Techniques` and `Expected_artifacts`. Validation has `Total_runs`,
`Avg_success_ratio`, `Secondary_reviewed` and `Validation_checks`, among others.
These describe **scenarios**, not individual command verdicts. No scenario ID or
execution-window join appears in the inspected log header, and the manifest has
no run start/end timestamps. Do not assign a scenario merely because an event
shares one of its ATT&CK techniques, or interpret a scenario ID as a login session.

Sources: [Mendeley v3](https://data.mendeley.com/datasets/b8fmtzvpy8/3),
[publisher paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC12950481/), and the
upstream guide/metadata downloaded by `fetch`. File listings, metadata and CSV
headers were inspected directly; the full merged CSV was not downloaded during
preparation.
