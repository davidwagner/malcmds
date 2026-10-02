# ATLASv2

Windows endpoint logs from two Windows 7 32-bit virtual machines used as researchers' primary workstations in July 2022. Four benign days precede a day of ten attack scenarios (four single-host and six multi-host), with benign activity continuing during attacks. Collection combines Sysmon, Microsoft Security auditing/ETW, Carbon Black Cloud, Firefox and DNS telemetry. Process records describe launches and endpoint activity, rather than every shell input. The Kali attacker machine's shell history is not a released command stream.

Run `./fetch` with Python 3.10+ and curl. It downloads:

- `atlasv2.tar.gz`: the publisher's 12,208,351,555-byte compressed dataset. Command-bearing logs cannot be separately downloaded from this single gzip archive.
- `reapr/atlasv2/*.labels` and `*.seeds`, plus the dataset and methodology READMEs: REAPr labels, pinned to commit `32babb5613f7d8c4c9f7ab0a0e602da64521f149`.
- `atlasv2_attack_igraphs.tar.gz`: the authors' serialized attack graphs, 21,011,377 bytes, for interpreting the labels.

The Box archives are verified against their published byte counts and SHA-1 hashes. Files remain compressed; completed files are skipped and partial downloads resumed. `FETCH_LIST=1 ./fetch` lists the selection without fetching payloads.

Inside the main archive, `atlasv2/data/{benign,attack}/{h1,h2}/` separates collection period and host. `sysmon/*.xml` and `msft-security/*.xml` are Windows Event Viewer XML exports. `cbc-edr/*.jsonl`, `cbc-edr-alerts/*.jsonl`, `ngav/*.jsonl` and `ngav-alerts/*.jsonl` hold Carbon Black telemetry/alerts. `firefox/` and `dns/` contain text logs. Attack files are organized by `s1`–`s4` and `m1`–`m6`; only multi-host attacks have host-2 counterparts. Multiple sensors may describe the same process launch.

For command extraction, start with Sysmon XML. Its standard process-creation schema is:

| XML location or field | Use |
| --- | --- |
| `System/Provider`, `System/EventID` | Microsoft Sysmon, event 1 identifies process creation. Event IDs from other providers have different meanings. |
| `EventData/Data[@Name='CommandLine']`, `Image` | Full command and executable. Named Data entries, not positional columns. |
| `ProcessGuid`, `ProcessId`, `ParentProcessGuid`, `ParentProcessId`, `ParentCommandLine` | Process identity and ancestry. |
| `System/EventRecordID`, `System/Computer` | Record ID, scoped to the machine and channel. |
| `UtcTime`, `System/TimeCreated/@SystemTime` | Execution/event timestamps. |
| `User`, `LogonGuid`, `LogonId`, `TerminalSessionId` | Account and session correlation where present; scope session numbers to host and lifetime. |

Use the Windows event XML namespace when parsing. The inspected Microsoft Security sample also has `System/EventRecordID`, `System/Computer`, ISO UTC `TimeCreated`, `SubjectLogonId`, and process identifiers. Event 4688 is process creation, but Windows 7 Security auditing does not provide the modern command-line coverage of Sysmon. Security events such as file access are not command launches. Carbon Black JSONL offers additional process context; its exact command-field inventory was not sampled during this verification, so the extraction fields above specifically describe Sysmon rather than an assumed common JSON schema.

REAPr labels are **process labels** derived from provenance tracing and manually checked attack root/impact nodes. The inspected comma-separated `.labels` header is `attack, process_name, process_id, process_uuid, label`; trim whitespace. The first file inspected uses `label=attack`. The methodology distinguishes malicious, contaminated and benign processes; preserve the actual values in each release rather than assuming a universal binary encoding. `.seeds` files identify tracing seeds, and the serialized graphs provide correlation context. The `process_uuid` values in these labels belong to the graph/telemetry representation and must not be equated blindly with Sysmon `ProcessGuid`; establish the mapping through host, scenario and process lifetime. PID alone is insufficient. The benign directory gives a collection-level designation; the attack directory contains both kinds of activity. Antivirus alarms are detector outputs, not ground truth. Labels do not declare every command in a login session malicious.

Sources: [dataset repository, layout and Box links](https://bitbucket.org/sts-lab/atlasv2), [author paper](https://arxiv.org/abs/2401.01341), [REAPr methodology](https://bitbucket.org/sts-lab/reapr-ground-truth), [Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). No explicit dataset redistribution license was identified in the inspected source README. Box metadata, initial archive bytes, Microsoft Security XML and a REAPr label file were checked on 2026-10-02; a full archive download was not performed.
