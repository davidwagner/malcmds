# DARPA Transparent Computing E3 — THEIA

**Unix commands (Linux).** THEIA uses custom Linux provenance instrumentation (`SOURCE_LINUX_THEIA`), including kernel-level tracking, and exports Common Data Model records. Commands describe process metadata and execution activity. These files are not raw auditd text logs. The engagement combines scripted benign activity and controlled red-team intrusions. Logged process activity does not guarantee recovery of the original shell input: shell expansion, redirection, built-ins and argument quoting may be lost.

## Download and files

Run `./fetch` with Python 3.10+ and curl. No credentials, pip installation, or manual interaction are required. `FETCH_LIST=1 ./fetch` prints the pinned selection without network access. `./fetch --metadata-only` downloads only schemas, reports, operational logs, release notes and any checksum list.

- `data/`: 4 gzip-compressed tar archives (`*.bin.tar.gz`) containing Avro binary streams. Compressed telemetry totals 1.99 GB (decimal). The alternative `*.json.tar.gz` exports duplicate the telemetry and are omitted.
- `schema/CDM18.avdl`, `schema/TCCDMDatum.avsc`, and schema PDF documentation: matching CDM18 definitions for decoding the binary records.
- `ground_truth/TC_Ground_Truth_Report_E3_Update.pdf`; `source/operational_event_log.md` and `source/README-E3.md`.

Selected recording topics:

- `ta1-theia-e3-official-1r`
- `ta1-theia-e3-official-3`
- `ta1-theia-e3-official-5m`
- `ta1-theia-e3-official-6r`

The original files mix process, file, network and other records; there is no separate command-only stream. Keep the mixed records to resolve event/subject references. Downloads remain compressed and are not extracted or executed. Transfers resume from `.part`; verified completed files are skipped using receipts. E3 payload lengths come from Drive; the release folder supplies no archive checksum manifest. Support files have pinned SHA-256 hashes. Drive quotas and unavailable files cause a nonzero failure; rerun after the service recovers.

The inventory in `../_tc_manifest.tsv` was checked on 2026-10-02 using complete embedded Drive folder listings. The normal folder page can show only 50 entries. This fetcher uses pinned file IDs and does not depend on that truncated listing. It downloads every listed binary topic for this collector, plus the engagement-wide support files.

## Command extraction

Read **`Subject.cmdLine`**, preserving event properties and referenced entities. Derived E3 process tables inspected in the supplied investigation contain `/bin/sh -e /proc/self/fd/9`; published raw-event examples corroborate command content. Some strings are process names or titles, and some subjects describe already-running processes. Use execution events to distinguish a launch from a process inventory or repeated metadata. The selected topics are the release's corrected `1r`, `3`, `5m`, and `6r` streams.

## Relevant CDM18 fields

Decode the Avro `TCCDMDatum.datum` union to distinguish Subject, Event, Host, Principal and object records. Avro JSON exports qualify branch names with `com.bbn.tc.schema.avro.cdm18` and wrap nullable strings/maps as `{"string": "..."}` / `{"map": {...}}`; binary readers usually unwrap them.

| Field | Use |
| --- | --- |
| `Subject.cmdLine`, `Subject.type` | Optional command string; distinguish process and thread subjects. A populated string can be a name or process title. |
| `Subject.uuid`, `cid`, `parentSubject` | Subject UUID, PID/TID, and parent UUID. Prefer UUIDs over PID-only joins. |
| `Subject.localPrincipal` | Reference to the owning principal/account; not a login identifier. |
| `Subject.startTimestampNanos` | Process/thread start time in Unix epoch nanoseconds. |
| `Event.uuid`, `sequence`, `threadId` | Event identity and per-execution-context ordering information. |
| `Event.type`, `name` | CDM operation such as `EVENT_EXECUTE` / `EVENT_FORK`, and collector-specific operation name. |
| `Event.subject`, `predicateObject`, `predicateObject2` | Actor and related entity UUIDs; targets may themselves be subjects. |
| `Event.predicateObjectPath`, `predicateObject2Path` | Optional target paths; paths alone do not supply arguments. |
| `Event.timestampNanos` | Event timestamp in Unix epoch nanoseconds. |
| `Subject.properties`, `Event.properties` | Collector-specific strings, including command properties described above; preserve exact key capitalization. |
| `Event.parameters` | Optional typed values; they are not necessarily process arguments. Do not interpret arbitrary API parameters as commands. |
| `Subject.hostId`, `Event.hostId`, outer `source` | Host and instrumentation source; keep source filename/topic too. |

`StartMarker.sessionNumber` / `EndMarker.sessionNumber` identify recording/system restarts. These are **not login or attacker sessions**. There is no portable login-session field in these schemas. Process ancestry, principal identity, flows and host/time context can support session reconstruction, with its uncertainty retained. Normalize UUID representations before joining. Do not count repeated subject metadata as distinct executions.

## Labels and limitations

The TA5.1 red team constructed the ground-truth report from the controlled attacks. It describes actions, hosts, timing and indicators at attack/scenario granularity. It is external to the CDM records; the schema has no universal malicious/benign command flag. The operational log adds test-range context.

Constructing command labels requires a documented match from report actions to host, time, subject/event identity and related objects. The reports can describe indicators absent from recorded telemetry. Benign activity continues during attacks, so an attack-time window is not a command-level malicious label; an unmatched event is not automatically confirmed benign. The official release is public domain and comes with prototype-data quality caveats.

Sources: [official E3 release notes](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README-E3.md), [official release files](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK), [CDM18 schema](https://drive.google.com/file/d/1zVKApkZwuPsk3y8BnR1bWTqze929y1qp/view), and [CDM design paper](https://www.usenix.org/system/files/tapp2020-paper-khoury.pdf). Collector-specific command examples and sampling limitations above come from the supplied *DARPA TC command lines: E3/E5 follow-up* report (2026-10-02); its bounded samples establish argument presence, not full-corpus coverage. The full telemetry was not downloaded for this verification.

Collector reference: [THEIA contributor project description](https://www.evandowning.com/pages/projects.html).
