# Command-bearing datasets

Each directory contains an executable `fetch` and a README explaining command
fields, identifiers, timestamps, session linkage, and the meaning of any labels.
Run a single dataset from its directory with `./fetch`, or run `./fetchall` here
to download every selection. Fetchers also work from another working directory.

Requires Python 3.10+ and curl. Dataset-specific requirements are documented in
the corresponding README. No credentials or interactive prompts are used for
public downloads. External hosts can still impose quotas or become unavailable;
a failure returns a nonzero status. `fetchall` continues to the other datasets
and reports every failed dataset at the end.

Use `FETCH_LIST=1 ./fetchall` to inspect selections before transferring the large
payloads. This may retrieve small source metadata and inventories. Total data
volume is substantial, especially OpTC; this repository contains downloaders,
not the datasets themselves.

Downloads stay compressed in their original formats. Files fetched through the
shared helper are written to `.part`, checked against published sizes/checksums
when available, then renamed to their final names. Completed files have small
`.download.json` receipts recording source and file size/mtime, so unchanged
files can be skipped without rescanning terabytes. Partial downloads resume
where the host supports ranges, otherwise restart. Publisher metadata is cached
in `.fetch-metadata`; delete that cache only when intentionally refreshing an
inventory. GitHub selections use pinned commits or a cached resolved commit.

Payloads, caches and partial downloads inside dataset directories are ignored
by Git. Fetchers never run commands found in the datasets. Fetching does not
extract or normalize commands: retain original records and label provenance
when building a derived corpus. A rule match, an attack scenario, a honeypot
session, and a confirmed malicious command express different evidence.
