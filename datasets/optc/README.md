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
| `properties.image_path` | Path of the program executed. |
| `timestamp` / `timestamp_ms` | Event time in milliseconds since the Unix epoch. The schema example calls this field `timestamp`; the field description calls it `timestamp_ms`. |
| `hostname` | Computer where the event occurred; used with time and attack details to associate commands with the attacks in the PDF. |
| `objectID`, `actorID` | IDs of the object affected by the event and the process performing the action. These connect process creation to the later actions described in the attack report. |

## Labels

The `benign` files contain benign activity. The `evaluation` files mix attacks with ordinary activity. The attack PDF identifies malicious actions by their time, computer and details, including commands and the processes involved. Those details connect the attack descriptions to individual events. The JSON records have no malicious/benign field or login-session ID.

Sources: [official release](https://github.com/FiveDirections/OpTC-data), [eCAR schema](https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md), [errata](https://github.com/FiveDirections/OpTC-data/blob/master/errata.md), [endpoint data](https://drive.google.com/drive/folders/1NwaCWRyr_coyPbF2SvScbani5O9MXp7_).
