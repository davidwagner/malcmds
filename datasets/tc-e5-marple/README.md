# DARPA Transparent Computing E5 — MARPLE

MARPLE records Windows activity from DARPA's E5 exercise in May 2019, including scripted benign activity and red-team attacks. Its Avro files use Common Data Model version 20 (CDM20).

## Mapping to the database

The reader takes command lines from process `Subject` records and execution/process events. The inner Avro record identifies its type; some outer records are mislabeled `RECORD_HOST`. Program names and arguments are parsed using Windows quoting. These are process observations, so `shell_input` is NULL and `other_tokens` is empty. Repeated observations of the same process creation are combined; distinct executions remain separate.

- `record_id` combines host, record type, source UUID and a suffix distinguishing observations. Source UUIDs allow lookup in the original files.
- `session_id` combines dataset, host and collector session, followed by a native Windows session ID when present. Otherwise it uses the parent process UUID, falling back to the process UUID. A collector session is not a login session.
- Zero/missing host UUIDs use the filename's producer prefix. Filenames also distinguish `marple-1`, `marple-2` and `marple-3` for labeling.

## Labels

MARPLE-2 and MARPLE-3 commands are `benign`. MARPLE-1 commands are `benign` outside these two reported attacks, in US Eastern daylight time (UTC−04:00):

- May 9, 2019, 13:57–14:02.
- May 17, 2019, 13:00–13:29.

The full ending minute is included. Within these intervals, commands keep the existing attack labels: `malicious` when matched to direct annotations, or `malicious-group` for membership in the attack episode. An ordinary background command can belong to such a group when its individual role is unresolved. `group_id` is `dataset:host:episode:first-last`, with Unix-nanosecond endpoints; all other labels have NULL `group_id`.

Unrecognized filename instances and missing timestamps remain `unknown`. A browser launch before an attack stays benign even if that process is compromised later. For example, `firefox.exe` on MARPLE-1 at May 9 13:56:59 is benign; at 13:57:00 the attack rules apply.

These are best-effort labels based on the official report's two attacks on MARPLE-1. They accept the report's uncertainty about its unexplained May 13 Mimikatz alert. Intervals are in [`scripts/_tc_attacks.json`](../../scripts/_tc_attacks.json); [`TCAnnotations.label()`](../../scripts/_tc_labels.py) applies them.

## Ingestion

Run `./ingest` from this directory. For a separate bounded import, use `./ingest --db ../../tmp/marple.duckdb --sample-files 1 --seed 3 --max-records 200000`. Use a fresh database when evaluating changed labels; a completed import is skipped on later runs.

Sources: [official release notes](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README.md), [official E5 report, sections 4.4, 10.8 and 11.2.6](https://drive.google.com/file/d/1cc3C5JW-Kn-VdXqeBGwvHBKSdR_YmSGj/view). See the shared [database schema](../../schema.md) for column definitions.
