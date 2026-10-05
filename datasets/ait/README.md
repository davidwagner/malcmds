# AIT Log Data Set v2.1

Linux/Unix logs from enterprise test networks with ordinary user activity and scripted attacks. The eight networks are fox, harrison, russellmitchell, santos, shaw, wardbeck, wheeler, and wilson. Each has system logs, authentication logs, service logs, and attack labels.

## Commands and fields

`gather/<host>/logs/audit/audit.log` contains Linux audit records. Records from the same audit event share `msg=audit(seconds.fraction:serial)`. Authentication logs in `gather/<host>/logs/auth.log*` also contain sudo commands and login events.

| Field or record | Meaning |
| --- | --- |
| `type=USER_CMD`, `cmd=` | Command text, sometimes encoded as hexadecimal. |
| `type=PROCTITLE`, `proctitle=` | Program and arguments, often encoded as hexadecimal with NUL characters between arguments. |
| `type=EXECVE`, `argc`, `a0`, `a1`, … | Argument count and ordered arguments in audit logs that include execution records. |
| `msg=audit(seconds.fraction:serial)` | Unix timestamp and audit event number. Network name, host, timestamp, and event number together identify the event and connect its audit records. |
| `ses` | Login session number. Network name, host, and `ses` identify the session; `4294967295` means the session number is unset. |
| Log path and line number | Identify an individual record within a network's logs. |

## Labels

Files in `labels/<host>/logs/...` correspond to files in `gather/<host>/logs/...`. Each label file contains one JSON object per line:

| Field | Meaning |
| --- | --- |
| `line` | One-based line number in the corresponding log file. |
| `labels` | Attack steps associated with that line. |
| `rules` | Rules that assigned the labels. |

The publisher labels lines matching attack rules with the attack-step names and treats unmatched lines as normal. Several audit records can belong to one event; their shared audit event identifier connects the command text to labels on companion records.

`dataset.yaml` gives the start and end of the experiment. `gather/attacker_0/logs/attacks.log` contains timestamps and attack-step names. The rules and label-processing code are in `rules/` and `processing/`.

Source: [publisher description, label examples, and files](https://zenodo.org/records/19483937).

## Ingestion

Run `./ingest` to append commands to the root `cmds.duckdb`. Repeated runs preserve one row per source command. For a reproducible sample, use `./ingest --db ../../tmp/sample.duckdb --sample-files 2 --seed 83 --limit 100`.

Audit records are joined by their timestamp/serial within a network archive and host. EXECVE arguments take precedence over decoded, NUL-separated PROCTITLE, followed by USER_CMD. Sudo COMMAND records in authentication logs are also included; sudo's `COMMAND=list` is normalized to `sudo -l` ([vendor example](https://access.redhat.com/solutions/7106892)). Arguments from executed processes are preserved without shell expansion.

`record_id` is archive + audit member + audit event ID, or archive + authentication member + one-based line + normalized-command index. `label` is malicious when any joined audit line has an attack annotation, otherwise benign, following the publisher's normal-event convention. Authentication records use their own line annotations. `group_id` is NULL. `session_id` is `ait:` + network archive + host + audit `ses`; unset sessions use parent PID (or PID/event ID). Authentication commands use host + calendar day + sudo user + TTY.

A complete validation run emitted 2,822 commands (41 malicious and 2,781 benign). A real-data end-to-end test imports 50 commands twice and checks identical stored rows, identifiers, labels and typed argument lists.
