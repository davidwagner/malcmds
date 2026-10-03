# DARPA Transparent Computing E5 — TRACE

TRACE records Linux activity using Linux Audit, `/proc`, netfilter and BEEP. This dataset contains activity from DARPA Transparent Computing engagement E5, including scripted benign activity and red-team attacks. The files contain process, execution, file and network records in Avro format using Common Data Model version 20 (CDM20).

## Commands and fields

Commands appear in `Subject.cmdLine`. An example is `/usr/bin/pulseaudio --start --log-target=syslog`. An `EVENT_EXECUTE` event links the old Subject through `Event.subject` to the new Subject through `Event.predicateObject`. The new Subject contains the command being started.

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
| `TCCDMDatum.hostId` | Computer ID used to match a record to an attack on that computer. |

The CDM schema has no common field for a login or connection session ID.

## Malicious and benign activity

`ground_truth/TA51_Final_report_E5.pdf` and its `.docx` version describe the red-team attacks: actions, affected computers, times, commands and file or network details. Commands are associated with an attack by matching these details to the event time, computer and command. The dataset contains both benign and malicious activity, and individual commands have no malicious/benign field.

## Sources

- [official E5 release notes](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README.md)
- [official release files](https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf)
- [CDM20 schema](https://drive.google.com/file/d/12_rZEiaPLQmFfnu0YUeMFMcqHxJWAg_D/view)
- [CDM design paper](https://www.usenix.org/system/files/tapp2020-paper-khoury.pdf)
- [TRACE provenance analysis](https://www.ndss-symposium.org/wp-content/uploads/prism2026-23.pdf)
