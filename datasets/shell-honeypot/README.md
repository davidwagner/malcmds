# Shell Honeypot Attack Dataset

The [Shell Honeypot Attack Dataset](https://github.com/zyw-286/shell-attack-evolution-dataset)
contains Cowrie SSH/Telnet inputs from 2021–2022 and 2024, cleaned attacker-IP
groups, and command annotations. `./fetch` downloads the complete repository at
revision `d5f7fe120ebd921e04026b6348c3ec5d399c5df6`. `./ingest` reads all raw
captures and both cleaned session files, without executing any captured input.

Raw command events include native Cowrie input, `INPUT_COMD:` input, plain
`tshark` input, and decoded byte-literal command wrappers. Process echoes are
excluded. Raw commands supply connection IDs when available. Connect/close events
bound recovered endpoint-based connections. Response events are excluded.
Cleaned groups fill gaps in the released raw captures: each matching raw
occurrence suppresses only one cleaned occurrence with the same period, source
IP and input text. Repeated commands remain separate. Overlapping raw samples
are matched by endpoints, timestamp, text and multiplicity.

The cleaned `session_id` describes an attacker-IP group and is stored as the
malicious `group_id`. It is never treated as a login session. Commands without a
recoverable connection receive the writer's dataset-qualified per-record session.
A positive published severity annotation on a single command identifies it as
malicious; other attack inputs retain their group label. Severity zero does not
mean benign. Unique-command and replay-response tables provide annotations only.

Shell input is split using the shared static Bash parser. Each row preserves the
complete input and source tokens outside its own program and arguments.
