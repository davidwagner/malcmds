# DARPA Transparent Computing E3 — THEIA

THEIA records Linux activity with kernel instrumentation. This dataset contains activity from DARPA Transparent Computing engagement E3, including scripted benign activity and red-team attacks. The files contain process, execution, file and network records in Avro format using Common Data Model version 18 (CDM18).

## Commands and fields

Commands appear in `Subject.cmdLine`. An example is `/bin/sh -e /proc/self/fd/9`. Events refer to these Subject records by UUID. The command field also contains process names and titles.

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
| `Event.hostId` | Computer ID used to match an event to an attack on that computer. |

The CDM schema has no common field for a login or connection session ID.

## Malicious and benign activity

`ground_truth/TC_Ground_Truth_Report_E3_Update.pdf` describes the red-team attacks: actions, affected computers, times, commands and file or network details. Commands are associated with an attack by matching these details to the event time, computer and command. The dataset contains both benign and malicious activity, and individual commands have no malicious/benign field.

## Sources

- [official E3 release notes](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README-E3.md)
- [official release files](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK)
- [CDM18 schema](https://drive.google.com/file/d/1zVKApkZwuPsk3y8BnR1bWTqze929y1qp/view)
- [CDM design paper](https://www.usenix.org/system/files/tapp2020-paper-khoury.pdf)
- [THEIA contributor project description](https://www.evandowning.com/pages/projects.html)
