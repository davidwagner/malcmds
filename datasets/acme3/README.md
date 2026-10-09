# ACME3

Source: [LLNL ACME3](https://gdo168.llnl.gov/data/ACME3/), the complete published `process_uber_summary.parquet` covering the collection, rather than its shorter workshop extract.

Run `./fetch`, then `./ingest --db /path/to/commands.duckdb`. The summary includes the reviewed graph labels and rule summaries; downloading raw sensor events would duplicate its process observations. There is one output per `pid_hash`, with repeated summary rows combined. `process_path`, then `filename` or `process_name`, supplies the executable. `args` contains arguments only, so its first token is retained. These Windows process observations have no submitted shell input or recovered login session.

Reviewed graph hits identify malicious processes. Ordinary desktop launches and normal browser helper invocations are benign even inside an attack group. Empty arguments alone do not make an executable benign. Sigma, MITRE, and LOLBAS name/rule hits alone do not establish malicious behavior: the publisher documents substantial false positives. Unannotated processes remain unknown. The shared importer gives processes without sessions a distinct per-record fallback.
