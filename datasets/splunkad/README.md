# Splunk Attack Data: command-bearing host telemetry

Run `./fetch` with Python 3.10+ and curl. It downloads a pinned selection from
`splunk/attack_data` commit
`a28608b53aa3d8222052e8f3ada59e2d9a4adfff`, preserving repository paths under
`source/`. The shared downloader resolves Git LFS pointers to actual files,
checks Git/SHA-256 integrity, resumes partial files and reuses completed files.
Compressed source files are kept compressed. `FETCH_LIST=1 ./fetch` lists the
selection without downloading payloads (small repository metadata may be fetched).

The collection contains **Windows and Unix/Linux commands**, with some macOS or
ESXi telemetry in host scenarios. Splunk and contributors run attack simulations,
including Atomic Red Team and Attack Range exercises, and export security logs.
These are chiefly process launches and interpreter/script telemetry, not a
representative population of human shell histories. Collection dates and tools
vary by scenario. The repository license is Apache-2.0.

## What is downloaded

The explicit path inventory embedded in `fetch` is a reproducible snapshot:
2,615 files totaling 11,610,397,120 bytes (about 10.8 GiB), including 1,586
Git LFS payloads. These totals come from the pinned Git tree and LFS pointers.
Selection uses the upstream YAML `sourcetype`/`source` descriptors for Windows
host event logs, Sysmon for Linux, auditd, osquery, Linux authentication/syslog,
ESXi, CrowdStrike sensor logs, Exchange management and Isovalent process logs.
It also includes legacy host files recognized by source-specific names, and
additional log prefixes containing command/argument or script-block fields.
Associated scenario YAML/Markdown files, environment descriptions and the
upstream README/license are retained. Cloud-only and network-only files are
omitted unless their inspected records contain command text.

This is a selection of command-relevant **files**, not a row-level command
extraction. A selected Sysmon file can also contain file, registry, image-load or
network events. Conversely, prefix inspection cannot establish every field
appearing later in a heterogeneous unclassified file. The inventory does not
claim complete command coverage of every unclassified upstream file.

Most payloads are raw `.log` files: concatenated Windows XML events, rendered
Windows event text, Linux audit/syslog lines, or newline-delimited JSON. Some
files have Splunk-export wrappers. Do not assume a single JSON schema, one event
per physical line, or that a `.log` suffix implies syslog.

## Relevant schema by source

| Source | Command/event selection | Identity, time and session context |
| --- | --- | --- |
| Windows or Linux Sysmon | Provider/channel identifies Sysmon; Event ID 1 is process creation. XML `EventData/Data` attributes name `CommandLine`, `Image`, `ParentCommandLine`, `ParentImage`; rendered/JSON equivalents vary. | `UtcTime`, `System/TimeCreated/@SystemTime`, `System/EventRecordID`, `Computer`, `ProcessGuid`, `ParentProcessGuid`, PIDs; Windows `User`, `LogonId`, `LogonGuid` when present. |
| Windows Security | Event ID 4688 process creation: `CommandLine`, `NewProcessName`, `NewProcessId`, `ProcessId` (creator PID), `ParentProcessName` on supported event versions. | `TimeCreated`, `EventRecordID`, computer; `SubjectUserName`, `SubjectLogonId`, `TargetLogonId` where present. Empty command lines reflect capture configuration, not empty executed commands. |
| PowerShell | Operational 4104: `ScriptBlockText`, `ScriptBlockId`, `MessageNumber`, `MessageTotal`; reconstruct multi-part blocks. Module/pipeline events can contain `Payload` and context. | Event time/record ID; script-block, runspace or pipeline IDs when present. A script-block ID is not a login session, and logged script text need not be a separate OS process. |
| Linux auditd | `type=EXECVE`: `argc`, `a0`, `a1`, ...; `PROCTITLE`: encoded `proctitle` or rendered `argc`/argument fields. Related `SYSCALL` records provide `exe`, `comm`, `pid`, `ppid`. | `msg=audit(time:serial)` groups records for one event; host scopes the serial. Timestamp rendering varies (epoch or human date). `auid`, `uid`, `ses`, `tty` where present associate login identity/session. |
| osquery | Inspect query `name` and `columns`, e.g. `cmdline`, `path`, `name`, `pid`, `parent`; snapshots differ from event tables. | Host/decorations, `unixTime`/`calendarTime`, query-specific identifiers. No universal session key. |
| Other endpoint/syslog sources | Source-specific process command-line/argument fields or embedded command text. Use the scenario descriptor's source/sourcetype and inspect each format before parsing. | Preserve original timestamp, hostname, user, source file and event offset; identifiers vary by product. |

A verified Windows Security sample uses XML `EventID=4688`, `CommandLine`,
`SubjectLogonId` and `EventRecordID`. A verified audit sample contains two linked
`EXECVE`/`PROCTITLE` records with `argc` and `a0` through `a4`. These samples show
why command strings and argument vectors need different parsers.

Windows event record IDs need computer/channel/log-lifetime scope. PIDs can be
reused. Audit `ses`, Windows logon IDs and parent process relationships express
different associations; none proves that every command sharing it is malicious.

## Labels

Scenario YAML files provide `id`, `date`, `description`, `environment`,
`mitre_technique`, and a `datasets` list with `name`, `path`, `source`,
`sourcetype`. Their ATT&CK annotations and emulation descriptions apply to the
**scenario or log collection**, not a universal per-command binary label.
Descriptions sometimes report test success or uncertainty. The files can contain
background events and unrelated commands. Keep these annotations as provenance;
do not label every event malicious solely because its enclosing scenario is an
attack simulation. Likewise, an unmatched event is not established benign.

Sources: [repository and collection instructions](https://github.com/splunk/attack_data),
[pinned snapshot](https://github.com/splunk/attack_data/tree/a28608b53aa3d8222052e8f3ada59e2d9a4adfff),
[scenario catalog](https://research.splunk.com/attack_data/).
The repository tree, scenario descriptors and representative payload prefixes
were inspected directly; the complete selected corpus was not downloaded.
