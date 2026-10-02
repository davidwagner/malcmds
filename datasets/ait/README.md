# AIT Log Data Set v2.1

Run `./fetch` with Python 3 and curl. It retrieves the eight `*_no-pcaps.zip`
archives from [Zenodo record 19483937](https://zenodo.org/records/19483937):
fox, harrison, russellmitchell, santos, shaw, wardbeck, wheeler, and wilson.
The selection totals 6,444,190,699 bytes. ZIPs remain compressed; they bundle
command-bearing host logs, other logs, and labels. Packet captures and duplicate
full-size archives are excluded. Completed downloads are verified and skipped;
partial downloads can resume through the shared downloader.

The data describe Linux/Unix enterprise testbeds with simulated ordinary users
and scripted attacks. Audit, authentication, service, and attacker logs capture
actual system activity. These are heterogeneous logs, not a complete shell
history or complete process-launch feed. License: CC BY-NC-SA 4.0.

## Files and command fields

Within each ZIP, `gather/<host>/logs/audit/audit.log` is Linux audit text.
`gather/<host>/logs/auth.log*` can supplement it with sudo command and login
messages. Keep archive, member path, and original line number as a record key.

| Field or record | Use |
| --- | --- |
| `type=USER_CMD`, nested `cmd=` | Logged command, sometimes hex encoded; `cwd` and terminal context may accompany it. |
| `type=PROCTITLE`, `proctitle=` | Process argument bytes, often hex with NUL separators. These are arguments observed during an audit event, not necessarily a new process launch. |
| `type=SYSCALL`, `comm`, `exe`, `pid`, `ppid` | Process identity/context; `comm` alone is not a full command. |
| `msg=audit(seconds.fraction:serial)` | Epoch timestamp and audit-event serial; join same-event records within a host and run. |
| `ses`, `auid`, `uid` | Audit session, original login user, current user; `4294967295` means unset. Scope session IDs by host/run; they are not global attacker IDs. |

**Coverage check:** ranged inspection of all seven audit files in
`russellmitchell_no-pcaps.zip` found no `EXECVE` records, 24 `PROCTITLE` records,
and one `USER_CMD` record. The latter records `cat /etc/shadow` as hex.
This archive therefore provides sparse command evidence. Do not assume every
execution has an argv record, or generalize this count to the other archives.
If another archive includes `EXECVE`, its `argc` and `a0`, `a1`, etc. can supply
arguments; join them to the associated audit event.

## Labels and timing

`labels/<host>/logs/...` mirrors `gather/<host>/logs/...`. Label files are JSONL:
`line` identifies the original log line (one based), `labels` names attack steps,
and `rules` identifies the rules that assigned them. These are automated
scenario-derived event labels, with rules and processing code included in
`rules/` and `processing/`. The publisher defines unmatched lines as normal;
this is ground truth for the simulation, not an independent verdict on every
possible command. Join labels before filtering or rewriting logs. Decide and
record how labels on multiple audit records become one command label.

Use the simulation interval in `dataset.yaml` (the landing page calls it
`dataset.yml`) to exclude setup/teardown activity. `gather/attacker_0/logs/attacks.log`
provides timestamped attack-step names, rather than literal command strings.
Session membership alone does not imply that every command is malicious.

Source: [publisher description, labels example, and files](https://zenodo.org/records/19483937).
Archive layout and the command-coverage check were verified on 2026-10-02 using
HTTP range requests, without downloading the complete collection.
