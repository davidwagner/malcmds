# OTRF Security Datasets

Source: [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets),
revision `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`.

Run `./fetch`, then `./ingest`. Fetch retrieves the complete pinned 558 MB
repository archive, including capture metadata and all released capture files.
The standard `--db`, `--limit`, `--max-records` and `--sample-files` options apply.
The importer inspects the release's 113 capture metadata documents, all host
ZIP/tar exports and standalone host logs, including captures without metadata.
Network traces and cloud-service audit events contribute no row unless they
contain a local command invocation.

Windows Security 4688 and Sysmon process-creation records are alternative
observations of a launch. The importer merges them only within the same capture
and host, with matching process ID and executable, and creation timestamps
within 10 milliseconds. This covers the published Dumpert pair, whose exporter
timestamps differ by two milliseconds. Repeated Sysmon process GUIDs are also
merged. Different captures, later PID reuse and separate executions remain
separate. No deduplication is based on command text alone.
Matching successful AUOMS and Linux Sysmon exports use the same launch check;
failed attempts remain separate.

Linux audit records use the shared audit parser with exec-only filtering and a
bounded event join that also preserves failed targets without released arguments.
Non-exec proctitle observations produce no row. Azure exports need an additional decoding step for JSON/XML embedded
inside event fields. Some published Sysmon syslog payloads are truncated at
2,048 bytes: complete XML fields before the truncation remain usable; an
unfinished field is discarded. Failed AUOMS exec records identify the attempted
image in `name`, while `exe` and `proctitle` describe the caller. The attempted
path becomes the program; unavailable arguments are left empty. Successful
AUOMS `cmdline` retains its embedded quoting. Command strings from process
telemetry leave `shell_input` null and `other_tokens` empty.

Attack mappings identify the capture group. Commands explicitly submitted in
the metadata's adversary terminal transcript (including plain command lines
without prompts), known attack-tool launches, and
their identified process descendants receive malicious labels. Process ancestry
uses host-scoped GUIDs or the most recent recorded PID lifetime and creation
time. Ordinary browser launches and routine browser helper invocations remain
benign even when their parent is associated with the attack. Other rows in an
attack capture retain `malicious-group`; captures without attack attribution
remain unknown. Only group-labeled rows have a group ID.

Sessions use native logon/audit-session identifiers or a process GUID, scoped
by capture and host. Missing identifiers use the shared per-record fallback.
The existing Linux OS value also covers comparable Unix process records.

Two metadata links contain filename discrepancies in this pinned revision:
`cmd_copy_ntds_from_volume_shadow_copy.zip` refers to the released
`cmd_dumping_ntds_dit_file_volume_shadow_copy.zip`; the network link ending in
`empire_dcom_shellwindows_stager.zip` refers to
`empire_dcom_shellwindows.zip`. These corrections only associate existing
release files with their metadata.

`test_ingest_lade_otrf.py` exercises authentic duplicated Dumpert events through
the complete archive-to-DuckDB workflow and checks that PID reuse and separate
capture identities preserve distinct executions.
