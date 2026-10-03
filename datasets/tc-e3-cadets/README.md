# DARPA Transparent Computing E3 — CADETS

CADETS records FreeBSD activity with DTrace. This dataset contains activity from DARPA Transparent Computing engagement E3, including scripted benign activity and red-team attacks. The files contain process, execution, file and network records in Avro format using Common Data Model version 18 (CDM18).

## Commands and fields

Commands appear in `Event.properties.cmdLine` on events whose `Event.type` is `EVENT_EXECUTE`. Examples include `nohup ./kafka.sh`, `/usr/bin/env bash ./kafka.sh` and `/usr/bin/vmstat -m`.

| Field | Meaning |
| --- | --- |
| `Event.uuid` | Unique event ID. |
| `Event.type` | Operation recorded by the event, such as `EVENT_EXECUTE` or `EVENT_FORK`. |
| `Event.timestampNanos` | Event time, in nanoseconds since the Unix epoch. |
| `Event.properties.cmdLine` | Command line, including arguments. |
| `Event.predicateObjectPath` | Path of the program executed. |
| `Event.hostId` | Computer ID used to match an event to an attack on that computer. |

The CDM schema has no common field for a login or connection session ID.

## Malicious and benign activity

`ground_truth/TC_Ground_Truth_Report_E3_Update.pdf` describes the red-team attacks: actions, affected computers, times, commands and file or network details. Commands are associated with an attack by matching these details to the event time, computer and command. The dataset contains both benign and malicious activity, and individual commands have no malicious/benign field.

## Sources

- [official E3 release notes](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README-E3.md)
- [official release files](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK)
- [CDM18 schema](https://drive.google.com/file/d/1zVKApkZwuPsk3y8BnR1bWTqze929y1qp/view)
- [CDM design paper](https://www.usenix.org/system/files/tapp2020-paper-khoury.pdf)
