# Splunk Boss of the SOC, version 3

BOTS v3 contains Windows and Unix/Linux logs from a fictional organization, assembled for a security investigation competition. It includes ordinary activity and attacks. The download stores events in Splunk's native indexed format.

## Mapping to the database

Commands come from Windows process events, WinHostMon and osquery process records, Bash and package history, sudo messages, and joined Linux audit events. Repeated observations of an identified process are combined, preferring its creation event. Unidentified process snapshots, including the release's `ps` listings, are omitted.

Process arguments become `pgm` and `args`. Bash history also retains its full input in `shell_input` and remaining shell syntax in `other_tokens`.

- `record_id` identifies the archive, native bucket, exported event position and command within the event. Audit records also retain their native event identifier.
- `session_id` starts with `splunk-bots:` and uses the available source identity: host and Windows logon ID; host, user and parent process for osquery; host and history path for shell history; host, process ID and start time for WinHostMon; or the Linux audit session and source, with parent process as fallback.
- `group_id` is always NULL.

## Labels

The release has no per-command truth column. The reader derives best-effort `malicious` labels from:

- Matched FYODOR-L Frothly inventory exploit launches, using process event type, host, time, executable, endpoint and payload arguments.
- The confirmed FYODOR-L registry-backed PowerShell payload and its `Updater` scheduled task, using the recorded command and event/process identity.
- Literal, case-insensitive indicator strings in the command's own program or arguments, from the 16-entry list in the pinned [`bots_rich.py`](https://github.com/kmkholm/moe-mamba-soc-triage/blob/44ef4e047c5dbff13f52bc3856b8060f0524f192/src/data/bots_rich.py). Parent-process text and other commands sharing a history line do not transfer a match.

Commands without a match remain `unknown`. Indicator matches are imperfect: inspecting `hdoor.exe` also matches. Conversely, the recorded `/tmp/colonel` and `colonelnew` attack activity is absent from the list. Neither all PowerShell commands nor all activity on FYODOR-L receives an attack label.

The rules are in [`scripts/_ingest_bots.py`](../../scripts/_ingest_bots.py) and [`scripts/_ingest_bots_iocs.py`](../../scripts/_ingest_bots_iocs.py).

## Ingestion

Run `./ingest` from this directory. It reads the archive through Splunk's offline `exporttool`, using `SPLUNK_HOME` when provided or downloading and verifying the pinned tool otherwise. Exports are cached under `../../tmp/ingest/`.

Use `--db ../../tmp/bots.duckdb --sample-files 1 --seed 83 --max-records 100000` for a separate bounded import. Use a fresh database when evaluating changed labels; a completed import is skipped on later runs.

Source: [official BOTS v3 release](https://github.com/splunk/botsv3). See the shared [database schema](../../schema.md) for column definitions.
