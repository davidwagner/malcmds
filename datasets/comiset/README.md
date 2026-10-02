# COMISET

Windows endpoint events from normal university computer-lab use (REAL, July
2022) and a controlled red-team lab (LAB, November 2022). Sysmon and other
Windows event providers were collected with Winlogbeat and processed by the
authors' EBDS/Elastic pipeline. The command-bearing process events describe
process launches, including background programs; they are not shell history.
Names of people and machines were anonymized.

## Download

Run `./fetch` with Python 3.10+ and curl. It downloads both ZIPs from the fixed
[Zenodo release](https://zenodo.org/records/15375146), validates its MD5 checksums,
and leaves them compressed. Completed files are skipped; `.part` files resume.
`FETCH_LIST=1 ./fetch` prints the selection without downloading the archives.

| Download | Bytes | Member containing events |
| --- | ---: | --- |
| `Comiset23_Lab_Environment_Dataset.zip` | 4,912,643,312 | `dataset_comillas2.json` |
| `Comiset23_Real_Environment_Dataset.zip` | 31,701,737,521 | `Comiset23_Real_Environment_Dataset.json` |

There is no separate command-only file or label download. The JSON members mix
many event types. Archive headers and initial records were inspected with HTTP
range reads; the entire 36.6 GB release was not downloaded. The files start with
a ZIP spanning marker and use ZIP64 sizes; use a ZIP64-capable reader.

## Relevant schema

The inspected members contain **newline-delimited JSON**, one Elasticsearch
hit per line, with `_index`, `_id`, and `_source`. Read event fields from
`_source`, retaining `(_index, _id)` as the source record key. `_score` is an
Elasticsearch search score, not a maliciousness label.

| Information | Fields and interpretation |
| --- | --- |
| Event selection | Observed `_source.source_name`, `log_name`, `event_id`, `task`. For Sysmon process creation, require provider `Microsoft-Windows-Sysmon` and event ID `1` (normalize string/integer), then require nonempty command text. Other providers reuse event IDs. |
| Command text | The paper documents `CommandLine` and `ParentCommandLine`. `ProcessCommandLine` also appears in the inspected REAL prefix on other event types; do not count these as additional process launches without checking the provider/event. |
| Process identity and context | The paper documents `Process_guid`, `Process_parent_guid`, `Process_id`, `Process_parent_id`, `Process_name`, `Process_path`, `Current_Directory`, `User_account`. Actual prefixes confirm lowercase normalized keys such as `process_id`, `host_name`, `user_name`, `user_domain`; inspect each event type for exact capitalization. These prefixes did not reach the Sysmon process-creation portion. |
| Record identity | Outer `_id` plus `_index`; `_source.record_number` is local to the host/event channel. A PID alone is reusable and is not a unique event ID. |
| Time | Observed `_source.event_original_time`, `@timestamp`, `etl_processed_time`; `z_elastic_ecs.event.created` records collection context. Preserve the original UTC ISO-8601 timestamp and distinguish collection/processing times. |
| Labels | Paper-documented `Rule_technique_id`, `Rule_technique_name`, `RuleName` are rule-derived ATT&CK annotations. Field presence and normalization vary with event type. |
| Session linkage | No universal login-session field is established by the paper or inspected prefixes. If raw Sysmon records retain `LogonGuid`/`LogonId`, combine with host identity. `etl_host_agent_ephemeral_uid` identifies a collector instance, **not** a user's shell/login session. Process GUID/parent GUID links give ancestry, not proof of shared attacker control. |

The paper's field list uses capitalization that differs from observed payload
keys, so it should not be copied verbatim as a parser specification. The raw
`event_original_message` can preserve provider-specific details absent from the
normalized fields.

## Labels and limitations

EBDS assigns ATT&CK annotations by matching event patterns against public and
author-written rules. Their granularity is the event. These are detection-rule
outputs, not independent analyst verdicts on every command. REAL contains rule
matches despite being collected during ordinary use; LAB also contains normal
activity. Neither partition name supplies a reliable binary label for every
row. Retain the rule/technique and partition separately, and treat unmatched
records as unlabeled unless adopting an explicit weak-label policy.

Sources: [dataset and license (CC BY 4.0)](https://zenodo.org/records/15375146),
[author paper, especially §4.3](https://doi.org/10.1016/j.dib.2025.111723),
[open full-text XML](https://www.ebi.ac.uk/europepmc/webservices/rest/PMC12266566/fullTextXML),
[Sysmon event semantics](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
