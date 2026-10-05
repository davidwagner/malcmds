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
- `label`: `benign` for the publisher's benign partition. Other records on a
  report-named host during an explicitly listed attack interval are
  `malicious-group`; other evaluation/short records are `unknown`. Intervals
  span the first and last listed activities or explicit shutdowns in the
  day 1/2/3 logs of `OpTCRedTeamGroundTruth.pdf`, including overnight agents.
  The report omits a timezone; comparing its clocks using the observed eCAR
  `-04:00` offset (America/New_York on these dates) is an inference. The isolated
  day-three WMI check-in covers its reported second only. An interval's end is
  the last supported observation, not a claim that all persistence ended then.
  `_ingest_optc.ATTACK_WINDOWS` lists every included host and interval.
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
