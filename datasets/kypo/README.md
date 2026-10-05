# KYPO / Masaryk shell commands, version 4

Human-entered Linux Bash and Metasploit console commands from cybersecurity training. The commands include offensive exercises and typing mistakes.

`data.zip` contains 267 JSON files grouped by training name and training instance, such as `House of cards/2019-08-15 KYPO Summer School/sandbox-396-useractions.json`. Each file has one JSON object per line. There are 21,108 records: 16,083 Bash records and 5,025 Metasploit records. Of these, 21,089 contain a `cmd` field.

## Commands and fields

| Field | Meaning |
| --- | --- |
| `cmd` | Full command entered by the trainee. Records containing this field contain commands. |
| `cmd_type` | `bash-command` for Bash input or `msf-command` for Metasploit console input. |
| `timestamp_str` | UTC timestamp in ISO 8601 format, usually with fractional seconds and a `Z` suffix. |

File path and line number identify each record. The dataset has no command ID or shell/login-session ID.

## Labels

The dataset has no per-command malicious/benign labels or separate attack-label file. Training directories identify the exercises, which include offensive tasks.

Sources: [version 4 dataset](https://zenodo.org/records/8136017), [collection toolset](https://zenodo.org/records/5126693), [paper](https://doi.org/10.1016/j.dib.2021.107398).

## Ingestion

Run `./ingest` to append commands to the root `cmds.duckdb`. Repeated runs preserve one row per source command. For a reproducible sample, use `./ingest --db ../../tmp/sample.duckdb --sample-files 2 --seed 83 --limit 100`.

The reader streams every useractions JSON member in data.zip, including Bash and Metasploit console records containing cmd. Bash input is parsed as shell syntax. Metasploit input is tokenized as a console command, preserving commands such as use and set.

`record_id` is archive + member path + one-based line + normalized-command index. `session_id` is `kypo:` + member path + hostname + username, grouping the recorded activity of a trainee on a host within one training instance. Labels are unknown and `group_id` is NULL because the training exercises supply no malicious/benign annotations.

A complete validation run emitted 21,250 normalized commands. A real-data end-to-end test imports 50 commands twice and checks identical stored rows, identifiers, labels and typed argument lists.
