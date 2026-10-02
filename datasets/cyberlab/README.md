# CyberLab honeynet

Run `./fetch` with Python 3 and curl. It downloads all 293 daily
`cyberlab_YYYY-MM-DD.json.gz` files in
[Zenodo record 3687527](https://zenodo.org/records/3687527), totaling
10,021,059,633 bytes. Files stay gzip compressed. There is no separate
command-only export or label file. Completed files are verified and skipped;
partial files can resume through the shared downloader. License: CC BY 4.0.

The collection covers incoming SSH/Telnet activity on a distributed Cowrie
honeynet in 2019–2020. Commands target Unix/Linux. Early sessions use an
emulated shell. Starting in November 2019, `sensor == "ubuntu_basic_pool"`
identifies sessions backed by real Ubuntu instances. Preserve that distinction
when studying operating-system execution. The logs capture remote input and
connection events, not kernel process launches or Windows commands.

## Format and extraction

Inspected daily files are JSON arrays. Each array element is an object mapping
one session ID to an array of event objects. A file is **not JSONL**. Its date
corresponds to the UTC start day of connections. Stream the JSON when processing
large days.

| Field | Use |
| --- | --- |
| `eventid` | Event category, not a unique row ID. |
| `message` | Command-bearing text; extraction depends on event type below. |
| `timestamp` | UTC ISO 8601 event timestamp. |
| `session_id` | Link events in a connection; also the containing object's key. |
| `sensor`, `dst_host_identifier`, `dst_ip_identifier` | Honeypot context and real-Ubuntu filter; values may be null. |
| `src_ip_identifier`, `src_port` | Pseudonymized source and connection context. |
| `username`, `password` | Present for relevant login events; can be associated with subsequent command events in that session. |

Actual payload checks matter here: the sampled export does **not** include
Cowrie's usual `input` field. On 2019-05-13, accepted commands use
`cowrie.command.success` with `message` beginning `Command found: `; failures
use `cowrie.command.failed`. On 2020-01-05, commands use
`cowrie.command.input` and `message` beginning `CMD: `, including 148 command
events from `ubuntu_basic_pool`. Remove only the matching event-specific prefix
and retain the rest literally. Inspect other event variants before extracting;
non-command messages and forwarded TCP data are not shell commands.

No globally unique event ID was found. A stable derived key is filename,
session-object position, session ID, and event position. Scope session IDs by
file/sensor/host to avoid assuming global uniqueness.

## Label interpretation

There is no explicit per-command benign/malicious annotation or independent
benign baseline. The publisher groups honeypot connections as attack sessions;
that gives collection-level or session-level adversarial provenance. Routine
commands within those sessions can be attacker actions, but their text is not
inherently malicious. Cowrie `success` and `failed` describe command handling,
not security labels. Session IDs permit grouping and splitting data without
mixing one session between training and evaluation.

Sources: [dataset description and file inventory](https://zenodo.org/records/3687527),
[Cowrie event reference](https://docs.cowrie.org/en/latest/OUTPUT.html).
Two compressed daily files were inspected on 2026-10-02; historical export
fields take precedence over the current Cowrie reference.
