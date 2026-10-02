# Splunk Boss of the SOC, version 3

Run `./fetch` with Python 3.10+ and curl. It retrieves the official
`botsv3_data_set.tgz` (335,251,397 bytes), verifies the publisher's MD5
`d7ccca99a01cff070dff3c139cdc10eb`, resumes partial transfers and skips completed
files. The archive stays compressed. This directory implements **BOTS v3**, the
release linked in the supplied research report; it does not fetch v1 or v2.

BOTS is security incident/CTF material containing **Windows and Unix/Linux**
activity from a constructed environment. It mixes ordinary background activity
and incident evidence across host, application, cloud and network sources. Host
telemetry includes Sysmon process launches, Linux audit records, shell history
and process inventory. The release is CC0-1.0.

## Format and access

The download is a **pre-indexed Splunk app**, not a CSV/JSON export. The inspected
archive prefix contains `botsv3_data_set/default/{props,transforms,indexes}.conf`
and index buckets under `botsv3_data_set/var/lib/splunk/botsv3/db/`, including
`.tsidx`, source metadata and compressed raw-data storage. The publisher supplies
one mixed-source archive; command-bearing sources cannot be downloaded as
separate public files.

Fetching requires no Splunk installation. To inspect/export events later, follow
the upstream installation instructions and search `index=botsv3 earliest=0`.
The original Splunk/app versions and required add-ons are documented upstream;
field extraction can differ with installed add-ons. The fetcher does not install
or configure Splunk. Its archive contains app configurations and data, not an
independently labeled command table.

## Command-bearing records

These source types appear in the publisher inventory. Field names below describe
the source formats and expected extractions; the indexed event payloads were not
fully exported or counted during preparation.

| Source type | Selection and command information | Time, IDs and session context |
| --- | --- | --- |
| `xmlwineventlog:microsoft-windows-sysmon/operational` | Sysmon Event ID 1 process creation: XML `EventData/Data[@Name='CommandLine']`, `Image`, `ParentCommandLine`, `ParentImage`; extracted names typically `CommandLine`, `Image`, `EventCode`. | XML `System/TimeCreated/@SystemTime`, `UtcTime`, `EventRecordID`, `ProcessGuid`, `ParentProcessGuid`, `ProcessId`; `LogonGuid`/`LogonId` where present. Scope record IDs and logons to host/channel/lifetime. |
| `wineventlog` | Windows event logs: distinguish provider/channel and process creation events such as Security 4688. Command-line availability depends on audit settings and event version. | Source event time, computer, event record number, subject/target logon IDs where present. |
| `linux_audit` | Match `type=EXECVE` argument records (`argc`, `a0`, `a1`, ...); `PROCTITLE` can contain encoded arguments. Join related `SYSCALL` records for `exe`, `comm`, PID/PPID and identity. | `msg=audit(timestamp:serial)` joins records for one audit event; host scopes the serial. `ses` is audit session, `auid` login UID, `uid` effective context where recorded. |
| `bash_history` | Shell input is in the raw history record; preserve shell operators and quoting. It can include built-ins and commands that failed. History collection is not proof every command completed. | Preserve Splunk host/source and any original history timestamps. History ordering alone does not supply a unique login session or reliable execution time. |
| `osquery:results`, `ps`, `top`, `perfmonmk:process` | Process snapshots may expose arguments depending on the query/output. For osquery, inspect `name` and `columns` (e.g. process `cmdline`, `path`, `name`, PID). A snapshot is not one new execution per row. | Query time, host and PID can associate snapshots; no universal login-session key. |

Splunk adds `_time`, `host`, `source`, `sourcetype` and `_raw`. Preserve these when
exporting. `_cd` is a useful bucket/event locator within a particular index
instance; it is not a portable global dataset ID. Retain original OS event IDs
where available and assign a reproducible export record ID otherwise. A parent
process link does not by itself establish a login session.

## Labels

The public v3 release does not publish a universal per-command malicious/benign
label file. CTF incident questions and investigator conclusions provide scenario
context, not a binary label for every background event or session. The archive's
lookup configuration includes indicators such as ransomware extensions and DDNS
providers; these are enrichment, not authoritative per-event ground truth. The
fetcher downloads the entire app, retaining any bundled lookups. Deriving labels
requires documented incident reconstruction; unselected events are not thereby
proven benign.

Sources: [official release, checksum, source inventory and installation guide](https://github.com/splunk/botsv3),
[official archive](https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz).
The archive size, HTTP range support, app configurations and initial index
structure were inspected directly without downloading the full archive.
