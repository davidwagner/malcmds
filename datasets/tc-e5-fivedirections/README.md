# DARPA Transparent Computing E5 — FiveDirections

FiveDirections records Windows activity. This dataset contains activity from DARPA Transparent Computing engagement E5, including scripted benign activity and red-team attacks. The files contain process, execution, file and network records in Avro format using Common Data Model version 20 (CDM20).

## Commands and fields

Commands appear in `Subject.cmdLine` and `Event.properties.CommandLine`. Process creation events with `Event.type = EVENT_FORK` can contain the command and link to its Subject through `Event.predicateObject`. An example is `C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s WdiSystemHost`.

| Field | Meaning |
| --- | --- |
| `Event.uuid` | Unique event ID. |
| `Event.type` | Operation recorded by the event, such as `EVENT_EXECUTE` or `EVENT_FORK`. |
| `Event.timestampNanos` | Event time, in nanoseconds since the Unix epoch. |
| `Subject.uuid` | Unique Subject ID, used to associate the command with events. |
| `Subject.cmdLine` | Command line, including arguments, or the process name or title. |
| `Subject.startTimestampNanos` | Start time, in nanoseconds since the Unix epoch. |
| `Event.subject` | UUID of the Subject performing the operation; joins to `Subject.uuid`. |
| `Event.predicateObject` | UUID of the target of the operation. When the target is a Subject, it joins to `Subject.uuid` for its command. |
| `Event.properties.CommandLine` | Command line attached to an event, including process creation events. |
| `TCCDMDatum.hostId` | Computer ID used to match a record to an attack on that computer. |

The CDM schema has no common field for a login or connection session ID.

## Malicious and benign activity

`ground_truth/TA51_Final_report_E5.pdf` and its `.docx` version describe the red-team attacks: actions, affected computers, times, commands and file or network details. Commands are associated with an attack by matching these details to the event time, computer and command. The dataset contains both benign and malicious activity, and individual commands have no malicious/benign field.

## Sources

- [official E5 release notes](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README.md)
- [official release files](https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf)
- [CDM20 schema](https://drive.google.com/file/d/12_rZEiaPLQmFfnu0YUeMFMcqHxJWAg_D/view)
- [CDM design paper](https://www.usenix.org/system/files/tapp2020-paper-khoury.pdf)
