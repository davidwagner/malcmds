# DARPA Operationally Transparent Cyber (OpTC)

OpTC contains Windows 10 activity from 500 computers in an enterprise attack exercise in September 2019. Ordinary activity continued while a red team attacked the environment. The JSON event files contain process creation, file access, network connections and other activity. Process-creation records contain command lines.

## Files and command fields

- `ecar/benign/` contains benign activity, grouped by date and computer.
- `ecar/evaluation/` contains both benign activity and red-team attacks, grouped by date and computer.
- `ecar/short/` contains events with missing data.
- `source/OpTCRedTeamGroundTruth.pdf` describes the attacks, including times, computers, commands and other actions.
- `source/ecar.md` describes the JSON fields. `source/errata.md` describes errors in the data.

| Field | Meaning |
| --- | --- |
| `object`, `action` | `object=PROCESS` and `action=CREATE` identify process-creation records. |
| `id` | Unique event ID. |
| `properties.command_line` | Full command line. |
| `properties.image_path` | Observed process image; on OPEN records it can describe the accessor rather than the command's process. |
| `timestamp` / `timestamp_ms` | Event time: actual streams use ISO-8601 strings with offsets; the schema documents epoch milliseconds. |
| `hostname` | Computer where the event occurred; used with time and attack details to associate commands with the attacks in the PDF. |
| `objectID`, `actorID` | IDs of the object affected by the event and the process performing the action. These connect process creation to the later actions described in the attack report. |

## Labels

The `benign` files contain benign activity. The `evaluation` files mix attacks with ordinary activity. The attack PDF identifies malicious actions by their time, computer and details, including commands and the processes involved. Those details connect the attack descriptions to individual events. The JSON records have no malicious/benign field or login-session ID.

Sources: [official release](https://github.com/FiveDirections/OpTC-data), [eCAR schema](https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md), [errata](https://github.com/FiveDirections/OpTC-data/blob/master/errata.md), [endpoint data](https://drive.google.com/drive/folders/1NwaCWRyr_coyPbF2SvScbani5O9MXp7_).

## Ingestion

`./ingest` streams every completed `ecar/**/*.json.gz` file. It reads PROCESS
records with `properties.command_line`, including CREATE, OPEN, and TERMINATE:
OPEN and TERMINATE can supply a command whose creation is outside the capture.
Non-process events and records containing only an image name are excluded.
For speed, a line is JSON-decoded only if it contains `"PROCESS"` or a `\u00`
escape (which could spell `PROCESS`); 85-95% of lines are skipped this way.
Files are parsed in parallel (`--workers`); see `../README.md`.
Actual files use ISO-8601 timestamps with `-04:00`; the reader also supports the
numeric epoch-millisecond fields documented by the eCAR schema.

Windows command lines use CRT argument parsing. On CREATE/TERMINATE, the observed
image path is preferred when it matches the command's executable. On OPEN,
`image_path` can describe the accessor while `command_line` describes the target,
so the command's argv[0] supplies `pgm`. Device paths are preserved when used.

- `record_id`: event `id` UUID plus normalized-command index; if UUID is missing,
  relative gzip path plus one-based line number and command index. Duplicate
  source IDs across files collapse; different event UUIDs remain separate.
- `label`: reviewed event decisions from Nikulshin and Talhi take precedence.
  Reviewed benign process corrections and the ordinary benign launch of an
  event-only process follow. Remaining valid process or exact event matches,
  then Inria host/PID lifetime matches, produce `malicious`. Commands with no
  individual match retain the benign partition, reported host/time
  `malicious-group`, or `unknown` fallback. A PROCESS CREATE uses the child's
  `objectID`, not its parent's `actorID`. OPEN observations do not borrow the
  accessor's PID label for the target's command.
- `group_id`: `optc:<attack>:<host>:<start>/<end>:America_New_York` for attack
  intervals, otherwise NULL. These label the host/time group, not every process
  in that interval as individually malicious.
- `session_id`: host plus native login ID when supplied. CREATE events otherwise
  use host, principal and parent `actorID`, grouping sibling commands under the
  same parent. Other observations use host and target process `objectID`.
  Missing process IDs fall back to host, principal, date and parent PID. All
  session IDs start with `optc`.

Use `--sample-files N --max-records N --seed N` for a reproducible bounded scan;
`--max-records` applies to each selected gzip stream. The 152 completed local
files inspected include 149 benign, two evaluation, and one short stream.

Validation used one original file from each partition selected with seed 23,
scanning 100,000 records per file. These produced 10,152 benign, 1,396 evaluation,
and 21,870 short-stream commands. Repeated CLI ingestion preserved identical
rows. Real OPEN records also verified that a target `svchost.exe` command keeps
its arguments when `image_path` names the accessor `MsMpEng.exe`.

### Published process and event labels

`./fetch` downloads two pinned releases before fetching eCAR data:

- [Nikulshin and Talhi](https://github.com/AT03380/optc-labels), revision
  `64c9f9b2e1a15bf3c2789d89d93dc0724cb0d4fa`: reviewed `tasks/tasks.zip`
  and generated `labels/malicious.zip`, saved under `labels/reviewed/`.
- [Majorczyk, Pilastre and Dijoud](https://gitlab.inria.fr/fmajorcz/a_new_hope_for_darpa_optc/-/tree/main/labelling/host/ground_truths),
  revision `644f41fb0a955e471f34bed016fb2bfd9c74dc04`: the three
  `ground_truth_sc*_new.csv` files and per-host event exports, saved under
  `labels/inria/original/`. These describe the original eCAR data fetched here;
  corrected-data labels are excluded because they refer to a different version.

The reviewed release distinguishes an entire malicious process from a malicious
individual event of an otherwise benign process. For example, its RPCSS network
connection is malicious, while the service's ordinary startup remains benign.
FLOW events do not produce COMMANDS rows. An actual execution event with a valid
reviewed malicious decision still receives that decision. Invalid correlations
are excluded from the generated malicious export; they do not veto independent
reviewed or Inria evidence. Valid explicit benign decisions take precedence over
inferred positive evidence. The implementation reads the tasks directly, following
[the label definitions](https://github.com/AT03380/optc-labels/blob/main/supplementary/labels.md)
and [errata](https://github.com/AT03380/optc-labels/blob/main/supplementary/errata.md).

PID intervals use a preliminary pass over the selected source records to find
later process creations and explicit host starts/reboots. A new creation closes
the previous lifetime, including an `Infinity` interval, before the new process
can inherit its label. This pass also prevents source-file order or worker count
from changing labels. CSV starts are rounded to seconds; the first creation in
that second belongs to the interval, and subsequent creations end it. Known
reboots also end intervals. Missing telemetry cannot establish an unobserved
reuse or reboot. `--max-records` bounds this preliminary pass per file;
`--limit` limits stored commands but still requires the lifetime pass.

All lookups are temporary. COMMANDS columns and database tables are unchanged,
and `group_id` is NULL for every label except `malicious-group`. Installations
without label artifacts retain the previous fallback labels; rerun `./fetch`
to install the published labels. A generated malicious export without its
reviewed tasks fails explicitly because invalid correlations cannot be removed.

Offline tests contain unchanged published excerpts for encoded PowerShell,
RPCSS startup and its FLOW task, an invalid correlation also present in the
positive export, an explicit benign correction, and an Inria-only execution.
They run through the real database writer and compare serial and parallel rows.
Additional constructed timelines check PID reuse within one second, reboots,
host normalization and the distinction between accessor and target PIDs.

Validation with both complete `23Sep19-red/AIA-201-225` streams and all pinned
label files retained 1,643,389 command observations. Before this change, 48,746
were `malicious-group` and 1,594,643 were `unknown`. With the published labels,
3,038 are `malicious`, 9,254 are `benign`, 38,531 remain `malicious-group`, and
1,592,566 remain `unknown`. Of the 3,038 positive observations, 123 were previously
unknown. These are observation counts: measuring distinct recovered executions
requires the separate duplicate-execution correction. This validation does not
claim full-dataset execution totals. The offline regression tests run in
`.github/workflows/optc-labels-tests.yml`, including checks that dependency
changes preserve compressed Arrow streams, database types, and final labels.
