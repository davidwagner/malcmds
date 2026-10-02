# AVIATOR

AVIATOR contains eight controlled attack scenarios based on MITRE emulation plans for APT29, OilRig, Sandworm and Wizard Spider, including extensions into industrial-control environments. It includes **Windows and Linux** host logging: the released collection scripts configure Windows Sysmon, Security and PowerShell logs, ETW tracing, and Linux auditd on Ubuntu Server 22. The Sandworm scripts explicitly start Linux collection. These provide process executions and PowerShell script content, rather than complete interactive shell transcripts.

Run `./fetch` with Python 3.10+ and curl. It downloads two archives and never extracts or executes their contents:

- `10.35097-8s5b0u5yqgfs2y0d.tar`: the published RADAR BagIt archive, 109,261,265,408 bytes, verified with publisher MD5 `4d03f85f6d65b6e3849646fac4b5d734`. Its payload is already ZIP-compressed. The individual-file download service returned HTTP 500 during verification, so the working complete archive is used. This includes other telemetry alongside the command-bearing logs.
- `aviator-ground-truth-and-tools.tar.gz`: the small GitLab source archive at commit `4a8a815ee723ee7c6dec871409be67fef272da6b`, including `ground_truth/`, `logging_conf/` and `log_shipping/`. A fixed byte count and SHA-256 verify this archive.

Completed downloads are skipped and interrupted downloads resumed. `FETCH_LIST=1 ./fetch` lists these URLs without transferring payloads. RADAR can temporarily return HTTP 429; the downloader retries and otherwise exits unsuccessfully, preserving partial data for a later run.

The large tar has a `10.35097-8s5b0u5yqgfs2y0d/data/dataset/` payload directory. Its 16 ZIP files use `ex_` and `ra_` prefixes with suffixes `APT29`, `APT29-1`, `APT29-2`, `Oilrig`, `Oilrig_ext`, `Sandworm-1`, `Sandworm_ext`, and `WizardSpider`. The export/raw collections can represent overlapping events. An inspected `ex_Sandworm-1.zip` contains XML event exports and text trace summaries, including `Sandworm-1/alpc_<date>_<host>_sandworm_scenario1.xml`. A text trace summary reports collection statistics, not commands. The logging configuration names Windows files `sysmon_audit_<tag>.evtx`, `msft_security_audit_<tag>.evtx`, and `powershell_audit_<tag>.evtx`; Linux audit files use `auditd_<date>_<tag>.log`. Match the sensor as well as the suffix when selecting records.

Relevant extraction schema depends on the stream:

| Stream | Command selection, identity, time and session information |
| --- | --- |
| Sysmon EVTX / exported XML | Provider Microsoft-Windows-Sysmon, event 1. Named `EventData` fields `CommandLine`, `Image`, `ProcessGuid`, `ProcessId`, `ParentProcessGuid`, `ParentProcessId`, `ParentCommandLine`, `UtcTime`, `User`, `LogonGuid`, `LogonId`, `TerminalSessionId`, where recorded. |
| Windows Security | Provider Microsoft-Windows-Security-Auditing, event 4688. `NewProcessName`, `CommandLine` when enabled, `NewProcessId`, and `SubjectLogonId`; fields depend on event version. |
| PowerShell Operational | Event 4104: `ScriptBlockText`, `ScriptBlockId`, `MessageNumber`, `MessageTotal`, and `Path`. Reassemble fragments by host and script-block ID in message order. Script blocks are not separate process launches, and an ID is not a login-session ID. |
| Windows event envelope | `System/Computer`, `System/EventRecordID`, `System/TimeCreated/@SystemTime`, `System/Execution/@ProcessID` and `ThreadID`. Scope record IDs to host/channel; an ETW trace need not carry all event-log fields. The inspected XML includes an explicit timestamp offset. |
| Linux auditd | `type=EXECVE` argument fields `argc,a0,a1,...`, `PROCTITLE` when present, and companion `SYSCALL` fields `exe,pid,ppid,auid,uid,ses`. Join records using the shared `msg=audit(epoch:serial)` identifier, scoped to host. Decode audit encodings before rebuilding argv. `ses` is an audit login-session identifier when set. |

The field names above describe the configured sensor formats. Only the initial XML export and collection/configuration files were sampled here; coverage and missing fields must be checked per archive. The supplied Winlogbeat configurations also support ingestion into Elasticsearch; they do not make every archived file JSON.

Ground truth is published in `ground_truth/{apt29,oilrig,oilrig_ext,sandworm,sandworm_ext,wizard_spider}/*.sh` in the source archive. These are **emulation procedures**, containing attack steps, commands, MITRE technique IDs, host roles and collection start/stop instructions. They are not row-by-row command labels and should not be executed to read the dataset. Match procedure actions to observed hosts, times and process/script relationships when deriving labels. Filenames and scenario tags distinguish runs; `normal_operation` is the collection script's benign tag. An attack run can include benign operations, and a command appearing in a scenario script is not proof that every occurrence of that text in telemetry is malicious. No comprehensive event-ID-to-label table was found in the source repository.

Sources: [RADAR record and CC BY 4.0 license](https://radar.kit.edu/radar/en/dataset/8s5b0u5yqgfs2y0d), [publisher source, ground truth and logging configuration](https://gitlab.kit.edu/kit/iai/rsa/aviator), [paper record](https://publikationen.bibliothek.kit.edu/1000178581). Metadata, complete source archive and selected payload bytes checked on 2026-10-02. The 109 GB dataset was not fully downloaded for verification.
