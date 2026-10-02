# Linux-APT Dataset 2024

Run `./fetch` with Python 3.10+ and curl. It downloads Mendeley version 2 into
`source/` and the original Zenodo `local_rules.xml` rules file. Completed files
are reused; partial transfers are resumed by the shared downloader. Source
checksums are verified. The XLSX remains compressed in its original format.

This is **Linux** telemetry from controlled attacks and background system
activity, collected through Wazuh from October 2023 to January 2024. It includes
system/authentication logs, configuration assessment, file integrity alerts and
other host events. It is not a complete shell history or an exhaustive process
creation audit. The release is CC BY 4.0.

## Files and command fields

- `source/combine.csv` (208,367,684 bytes) merges the 17 original date shards;
  the fetcher omits those redundant shards. This is a wide CSV export of Wazuh
  alerts, with literal dotted column names, quoting and sparse fields.
- `source/Processed Version.xlsx` (13,870,934 bytes) contains a reduced,
  processed view with binary labels and separated ATT&CK annotations.
- `local_rules.xml` describes the custom Wazuh rules used by the collection.

Fields verified in the raw CSV header:

| Purpose | Columns and interpretation |
| --- | --- |
| Command | `_source.data.command` where populated; `_source.full_log` retains the original event text, including command/arguments for relevant records. |
| Event selection | `_source.decoder.name`, `_source.decoder.parent`, `_source.location`, `_source.rule.groups`, `_source.rule.id`, `_source.rule.description`. Select actual execution/sudo or comparable command records after examining their decoder and raw text. |
| Time | `_source.timestamp` and `_source.@timestamp`, with display-formatted timestamps such as `Oct 1, 2023 @ 00:49:18.889`; `_source.predecoder.timestamp` may retain source-log time. Do not assume an unstated timezone. |
| Record identity | `_index` with `_id` identifies the exported search hit; `_source.id` is also present. Preserve the source file and row number for traceability. |
| Host/user | `_source.agent.id`, `_source.agent.name`, `_source.agent.ip`, `_source.data.srcuser`, `_source.data.dstuser`, `_source.data.uid`. |
| Command context | `_source.data.tty`, `_source.data.pwd` where populated. No general login-session identifier appears in this CSV header; a host/user/TTY combination is not a unique authenticated session. |
| Annotation | `_source.rule.mitre.id`, `_source.rule.mitre.tactic`, `_source.rule.mitre.technique`, plus rule ID, description and level. |

Do not turn `_source.data.sca.check.command` into an observed user command: it is
configuration-assessment check metadata. Likewise, a command mentioned in a
signature, rule description or remediation is not evidence of execution.
Arguments in raw source logs may be incomplete; retain provenance per record.

## Labels and joins

The workbook's literal headers include `timestamp`, `agent\.name`, `full_log`,
`rule\.description`, `rule\.mitre\.tactic`, `rule\.mitre\.technique`,
`rule\.mitre\.id`, and **`Malicious / General`**. The publisher defines `1` as
suspicious/malicious and `0` as general/normal. These are **log-record labels**
derived from ATT&CK/TTP tagging by Wazuh rules, rather than independently
adjudicated labels for each command or session. An untagged record should not be
treated as proven benign.

The processed workbook drops raw event IDs. Match to the raw CSV using available
time, host, full-log and rule information, and retain ambiguous matches rather
than relying on row order. The paper reports different raw/processed row counts
(122,565 versus 125,899); this is another reason not to assume one-to-one rows.

Sources: [Mendeley v2](https://data.mendeley.com/datasets/5x68fv63sh/2),
[original shards and local rules](https://zenodo.org/records/10685642), and
[collection paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC11220842/).
The CSV header and workbook header were inspected directly; the full raw CSV was
not downloaded during preparation.
