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

## DARPA Transparent Computing E3/E5

Nine `tc-*` directories cover E3 CADETS, FiveDirections, THEIA and TRACE, plus
E5 CADETS, FiveDirections, MARPLE, THEIA and TRACE. To fetch only these, run:

```sh
./fetchall tc-*
```

`fetchall` accepts one or more dataset directory names; without arguments it
runs all dataset fetchers, including TC. Unknown names fail before any download.
A TC fetcher also accepts `--metadata-only` to retrieve schemas, ground truth,
operational logs, release notes and checksum lists without the large telemetry.

TC uses the checked-in `_tc_manifest.tsv` inventory, verified on 2026-10-02:
12 E3 binary tar.gz archives and 1,190 E5 binary gzip files. Binary streams retain
both process metadata and execution events; duplicate JSON exports are excluded.
Support files are repeated in each dataset so its download is self-contained.
The `dataset` column uses `e3`/`e5` for engagement-wide support and `tc-*` for
collector-specific files; `path` is relative to that dataset directory. Empty
`size` means no pinned byte length; empty `checksum` means no published checksum
(E3 telemetry). Every E5 binary file has a publisher MD5 checksum. Metadata has
SHA-256 hashes of the retrieved release files. Public Drive IDs are in `url`.

The complete Drive inventories were read through `embeddedfolderview`, then E5
binary filenames were checked against each collector's `bins.md5sum`. Ordinary
Drive folder pages can show only 50 entries. All checksum-listed E5 binary files
are present in the pinned inventory. The E5 STARC folder was empty, so the
fetchers include the actual TA5.1 PDF/DOCX reports and do not promise STARC labels.
Release notes are pinned to DARPA repository commit
`244ae2401032ce92ac3b72f49b8039cae67d60d6`.
