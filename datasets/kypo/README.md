# KYPO / Masaryk shell commands, version 4

Run `./fetch` with Python 3 and curl. It downloads only `data.zip` (411,710
bytes) from [Zenodo record 8136017](https://zenodo.org/records/8136017).
`toolset.zip` contains analysis tools and is excluded. The ZIP stays compressed;
repeat runs verify and skip it. The publisher's MD5 is
`a11b58d28a4c7d16482e84ed9540e238`. License: CC BY 4.0.

These are human-entered Linux Bash and Metasploit console commands from
cybersecurity training, collected by a host logging toolset. This is shell and
console input, including mistakes, rather than a kernel process-launch feed.
There are no Windows command traces. Training tasks include offensive actions;
they do not constitute an ordinary-user benign baseline.

## Files and fields

`data.zip` has 267 `.json` files under training-name and training-instance
directories, for example
`House of cards/2019-08-15 KYPO Summer School/sandbox-396-useractions.json`.
Despite the extension, each file contains newline-delimited JSON objects.

| Field | Use |
| --- | --- |
| `cmd` | Full entered command string; absent in some records. |
| `cmd_type` | `bash-command` or `msf-command`; select Bash for shell-only research. |
| `timestamp_str` | ISO 8601 UTC time, normally with fractional seconds and `Z`. |
| `pool_id`, `sandbox_id` | Training infrastructure identifiers for grouping related records. |
| `hostname`, `ip` | Host context inside the training. |
| `username`, `wd` | User and working directory, generally on Bash records. |
| `tags` | Present on the 19 inspected rows missing `cmd`; not a maliciousness label. |

There is no explicit unique command ID or shell/login-session ID. Use archive
member path and line number as a stable row key. Combine training-instance
path, pool, sandbox, and host for participant/environment context; sandbox IDs
alone can recur, and this grouping is broader than one login session.

## Labels and size discrepancy

The archive contains no per-command benign/malicious labels and no separate
intrusion ground truth. A training directory or a host named `attacker` records
exercise context, not a validated security label for each command.

The publisher reports 21,459 records from 275 trainees. Direct inspection of the
checksum-matching v4 ZIP on 2026-10-02 counted 21,108 nonempty JSON records:
16,083 `bash-command` and 5,025 `msf-command`; 21,089 have `cmd`.
Preserve this metadata/payload discrepancy rather than silently assuming the
published total. The original paper describes an earlier, smaller version.

Sources: [v4 dataset and version history](https://zenodo.org/records/8136017),
[collection toolset](https://zenodo.org/records/5126693),
[dataset paper](https://doi.org/10.1016/j.dib.2021.107398).
