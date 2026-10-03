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
