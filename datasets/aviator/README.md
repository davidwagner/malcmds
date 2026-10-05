# AVIATOR

Windows and Linux logs from eight controlled attack scenarios based on MITRE emulation plans for APT29, OilRig, Sandworm, and Wizard Spider. Some scenarios extend into industrial-control systems. Windows logs include Sysmon, Security, PowerShell, and ETW events; Linux logs include auditd records from Ubuntu Server 22.

The scenario files are named `APT29`, `APT29-1`, `APT29-2`, `Oilrig`, `Oilrig_ext`, `Sandworm-1`, `Sandworm_ext`, and `WizardSpider`. ZIP files with `ex_` and `ra_` prefixes contain exported and raw logs, respectively. Both versions can contain the same events. Windows files include `sysmon_audit_<tag>.evtx`, `msft_security_audit_<tag>.evtx`, and `powershell_audit_<tag>.evtx`. Linux audit files use `auditd_<date>_<tag>.log`.

## Commands and fields

| Records | Command fields |
| --- | --- |
| Sysmon event 1 | `CommandLine` is the full command; `Image` is the executable path. |
| Windows Security event 4688 | `NewProcessName` is the executable path; `CommandLine` contains the command when command-line logging is enabled. |
| PowerShell Operational event 4104 | `ScriptBlockText` contains PowerShell code. `ScriptBlockId` identifies the script block, and `MessageNumber` and `MessageTotal` give the order and count of fragments when code spans several records. |
| Linux audit `EXECVE` | `argc` is the argument count; `a0`, `a1`, and subsequent fields hold the program and ordered arguments. |
| Linux audit `PROCTITLE` | `proctitle` contains program arguments, often encoded as hexadecimal with NUL characters between arguments. |

Windows events have `System/EventRecordID`, `System/Computer`, and `System/Channel`; together they identify a record within a run. `System/TimeCreated/@SystemTime` is the event timestamp, and Sysmon `UtcTime` is the UTC process-creation time. Sysmon `LogonGuid`, `LogonId`, and `TerminalSessionId`, and Security `SubjectLogonId`, provide session identifiers when included. Numeric session identifiers are local to the machine and can repeat after a restart. PowerShell fragments belong to the same script block when their machine and `ScriptBlockId` match.

Linux audit records share `msg=audit(epoch:serial)` across one event. It contains the Unix timestamp and event number. Run, host, and this identifier connect the command arguments with companion audit records. The companion `SYSCALL` record's `ses` field is the audit login session number; `4294967295` means unset. Run, host, and `ses` identify the session. File path and line number identify individual audit records.

## Labels

`ground_truth/{apt29,oilrig,oilrig_ext,sandworm,sandworm_ext,wizard_spider}/*.sh` contains the attack procedures. These scripts list attack commands, MITRE ATT&CK technique IDs, the machines involved, and the order of attack steps. The scenario names and run tags connect procedures to their logs. `normal_operation` identifies benign collection runs; attack runs include ordinary activity as well.

Command labels are derived by matching procedure steps to the corresponding commands, machines, and times in the logs. The release provides these procedures as its attack ground truth and has no per-event benign/malicious label table.

Sources: [RADAR dataset](https://radar.kit.edu/radar/en/dataset/8s5b0u5yqgfs2y0d), [attack procedures and logging configuration](https://gitlab.kit.edu/kit/iai/rsa/aviator), [paper](https://publikationen.bibliothek.kit.edu/1000178581).

## Ingestion

Run `./datasets/aviator/ingest`. The reader opens the uncompressed RADAR tar and reads `ex_*.zip` members without extracting them. Exported XML is the canonical representation of the corresponding raw EVTX; `ra_*.zip` is not ingested again. Sysmon, Security and other event fields containing an observed command line are read, along with Linux audit logs. Audit EXECVE arguments are joined with SYSCALL/PROCTITLE by audit event ID. PowerShell `HostApplication` is an invocation; script-block code and industrial-device diagnostic CSV messages are not process argument lists.

`record_id` contains both archive paths, the log member, event record ID or audit event ID, source ordinal, and command ordinal. `normal_operation` files are `benign`; other files are `malicious-group`, with `group_id=aviator:<scenario ZIP name without ex_>`. The attack procedures establish these run-level labels; individual command matches are not guessed from command-name similarity.

Windows `session_id` uses dataset, computer and nonzero `LogonGuid`. Its fallback combines scenario ZIP, computer, event date and logon ID, then parent process or user. Linux uses dataset, source log, host and audit `ses`, with parent PID as fallback. `--sample-files N --seed S` selects scenario ZIPs.
