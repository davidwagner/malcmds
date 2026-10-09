# ACME4

Source: [LLNL ACME4](https://gdo168.llnl.gov/data/ACME4/). `./fetch` downloads the complete current gold `process_uber_summary.parquet` and the released graph-process summary. The top-level process summary is the publisher's convenient copy of gold; train/test copies would duplicate it.

Run `./fetch`, then `./ingest --db /path/to/commands.duckdb`. One output is emitted per process hash after merging repeated observations. `process_path`, then `filename` or `process_name`, supplies the executable. The `args` field is argument-only; `-k unistacksvcgroup` keeps its leading `-k`. Process telemetry has no submitted shell input, omitted shell tokens, or inferred login session.

Reviewed graph hits and `red_team=1` identify attack processes. A process known only through `bad_user` is `malicious-group`, grouped by host and account. Explicit `red_team=0` background becomes benign. Ordinary desktop launches and normal browser helpers become benign when the invocation supports that reading; known attack tools do not become benign merely because they have no arguments. Other unannotated processes remain unknown. Sigma, MITRE, and LOLBAS matches alone are insufficient because the publisher documents false positives.
