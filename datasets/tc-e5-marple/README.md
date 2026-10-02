# DARPA Transparent Computing E5 — MARPLE

**Windows commands.** MARPLE is a Windows provenance collector (`SOURCE_WINDOWS_MARPLE`). The release contains normalized process and event records. The underlying Windows collection API is not established by the release documentation; it should not be assumed to be Sysmon. Commands describe processes and execution activity. The engagement combines scripted benign activity and controlled red-team intrusions. Logged process activity does not guarantee recovery of the original shell input: shell expansion, redirection, built-ins and argument quoting may be lost.

## Download and files

Run `./fetch` with Python 3.10+ and curl. No credentials, pip installation, or manual interaction are required. `FETCH_LIST=1 ./fetch` prints the pinned selection without network access. `./fetch --metadata-only` downloads only schemas, reports, operational logs, release notes and any checksum list.

- `data/`: 55 gzip-compressed Avro binary files (`*.bin.gz` and `*.bin.N.gz`). Every numbered chunk and initial unnumbered file present in the release is included. Duplicate JSON representations are excluded; all binary filenames match the published `bins.md5sum`.
- `schema/CDM20.avdl`, `schema/TCCDMDatum.avsc`, and schema PDF documentation: matching CDM20 definitions for decoding the binary records.
- `ground_truth/TA51_Final_report_E5.pdf` and its `.docx` version; `source/Engagement-5-Event-Log.md`, `source/README.md`, and `source/bins.md5sum`. These are the actual Drive filenames, which differ from the ground-truth filename mentioned in the release README.

Selected recording topics:

- `ta1-marple-1-e5-official-1`
- `ta1-marple-2-e5-official-1`
- `ta1-marple-3-e5-official-1`

The original files mix process, file, network and other records; there is no separate command-only stream. Keep the mixed records to resolve event/subject references. Downloads remain compressed and are not extracted or executed. Transfers resume from `.part`; verified completed files are skipped using receipts. E5 telemetry is verified against publisher MD5 hashes pinned from `bins.md5sum`; support files have pinned SHA-256 hashes. Sizes are also checked where the listing exposed them. MD5 is used for transfer integrity, not as a security signature. Drive quotas and unavailable files cause a nonzero failure; rerun after the service recovers.

The inventory in `../_tc_manifest.tsv` was checked on 2026-10-02 using complete embedded Drive folder listings. The normal folder page can show only 50 entries. This fetcher uses pinned file IDs and does not depend on that truncated listing. It downloads every listed binary topic for this collector, plus the engagement-wide support files.

## Command extraction

Read **`Subject.cmdLine`** and correlate execution events with their referenced subjects. The supplied investigation decoded `scp  -r C:\Users\admin\Pictures admin@128.55.12.119:./backup/` in `ta1-marple-1-e5-official-1.bin.1.gz`; the next `EVENT_EXECUTE` references that subject through `predicateObject`. Its two sampled prefixes contained 2,779 subjects, of which 2,190 had null commands.

**Classify the actual `datum` union branch.** Those Subject and Event examples incorrectly carry outer `type=RECORD_HOST`, and their envelope host UUID is all zero. Do not discard them based on that outer type or assume the host field identifies the recording. Preserve filename/topic, collector instance, `source`, and recording session alongside UUIDs. MARPLE is present in this public E5 release; there is no corresponding MARPLE directory in the official public E3 release.

## Relevant CDM20 fields

Decode the Avro `TCCDMDatum.datum` union to distinguish Subject, Event, Host, Principal and object records. Avro JSON exports qualify branch names with `com.bbn.tc.schema.avro.cdm20` and wrap nullable strings/maps as `{"string": "..."}` / `{"map": {...}}`; binary readers usually unwrap them.

| Field | Use |
| --- | --- |
| `Subject.cmdLine`, `Subject.type` | Optional command string; distinguish process and thread subjects. A populated string can be a name or process title. |
| `Subject.uuid`, `cid`, `parentSubject` | Subject UUID, PID/TID, and parent UUID. Prefer UUIDs over PID-only joins. |
| `Subject.localPrincipal` | Reference to the owning principal/account; not a login identifier. |
| `Subject.startTimestampNanos` | Process/thread start time in Unix epoch nanoseconds (nullable). |
| `Event.uuid`, `sequence`, `threadId` | Event identity and per-execution-context ordering information. |
| `Event.type`, `names` | CDM operation such as `EVENT_EXECUTE` / `EVENT_FORK`, and collector-specific operation names. |
| `Event.subject`, `predicateObject`, `predicateObject2` | Actor and related entity UUIDs; targets may themselves be subjects. |
| `Event.predicateObjectPath`, `predicateObject2Path` | Optional target paths; paths alone do not supply arguments. |
| `Event.timestampNanos` | Event timestamp in Unix epoch nanoseconds. |
| `Subject.properties`, `Event.properties` | Collector-specific strings, including command properties described above; preserve exact key capitalization. |
| `Event.parameters` | Optional typed values; they are not necessarily process arguments. Do not interpret arbitrary API parameters as commands. |
| outer `TCCDMDatum.hostId`, outer `source` | Host and instrumentation source; keep source filename/topic too. |

Outer `TCCDMDatum.sessionNumber` identifies recording/system restarts; retain it together with host and source. These are **not login or attacker sessions**. There is no portable login-session field in these schemas. Process ancestry, principal identity, flows and host/time context can support session reconstruction, with its uncertainty retained. Normalize UUID representations before joining. Do not count repeated subject metadata as distinct executions.

## Labels and limitations

The TA5.1 red team constructed the ground-truth report from the controlled attacks. It describes actions, hosts, timing and indicators at attack/scenario granularity. It is external to the CDM records; the schema has no universal malicious/benign command flag. The operational log adds test-range context.

Constructing command labels requires a documented match from report actions to host, time, subject/event identity and related objects. The reports can describe indicators absent from recorded telemetry. Benign activity continues during attacks, so an attack-time window is not a command-level malicious label; an unmatched event is not automatically confirmed benign. The official release is public domain and comes with prototype-data quality caveats.

The E5 release notes mention STARC annotations, but the public `Data/starc` folder was empty when checked on 2026-10-02. No downloadable STARC labels are included or implied. The PDF and DOCX attack reports are the available official ground truth in this selection.

Sources: [official E5 release notes](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README.md), [official release files](https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf), [CDM20 schema](https://drive.google.com/file/d/12_rZEiaPLQmFfnu0YUeMFMcqHxJWAg_D/view), and [CDM design paper](https://www.usenix.org/system/files/tapp2020-paper-khoury.pdf). Collector-specific command examples and sampling limitations above come from the supplied *DARPA TC command lines: E3/E5 follow-up* report (2026-10-02); its bounded samples establish argument presence, not full-corpus coverage. The full telemetry was not downloaded for this verification.
