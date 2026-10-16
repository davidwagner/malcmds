# Shell Honeypot Attack Dataset

The [upstream release](https://github.com/zyw-286/shell-attack-evolution-dataset/tree/d5f7fe120ebd921e04026b6348c3ec5d399c5df6)
contains Cowrie SSH/Telnet events and earlier command lists. Run `./fetch`, then
`./ingest --db /path/to/observations.duckdb`. Fetch pins revision
`d5f7fe120ebd921e04026b6348c3ec5d399c5df6` and checks archive SHA-256
`266ed2e6c0923e56f317bf880b7294698cfc5792538cc8f58dbdfda68a9c0c11`.
Captured commands are parsed as text and never executed.

## Observation sources

The importer reads `2024/cowrie/*.json` events and every list position in
`dataset/sessions/2021_2022.jsonl`. It excludes derived 2024 lists, raw samples,
unique-command tables, and replay turns from observation rows. This avoids
counting different published views of the same commands more than once.
Repeated strings at different source positions remain separate observations.

Earlier command lists group by source IP. They have no command timestamps or
connection identifiers. An inactivity threshold cannot split those lists into
login sessions. Each occurrence therefore receives its own
`shell-honeypot:record:<record_id>` session, shared by its parsed children.
Empty inputs still produce shell rows. Acquiring complete earlier raw logs
would permit better grouping; those logs must replace the earlier derived
source as a whole to avoid unmatchable duplicates.

## Connection reconstruction

For 2024, events from all days are sorted by structured endpoints, time, path,
and numeric line position. String and integer ports are normalized. Separate
source ports remain separate even when the IP is shared. Protocol comes from
event metadata, so SSH/Telnet on ports such as 443 are supported.

SSH connect events start intervals; closes and disconnects end them. A new
connect always starts a new interval, even when its endpoints or native ID
repeat. Native IDs found in connect messages are qualified by collection,
deployment, and connect record. Standard Cowrie inputs with a native session
ID preserve that grouping directly. Missing endpoints or timestamps in
transformed inputs receive per-record fallback sessions.

Telnet and orphan SSH commands use estimated sessions. More than **60 minutes**
without relevant activity ends an estimated session. Successful Telnet login
after a command also starts a new session. Repeated logins before the first
command remain together. Commands, logins, connects, and closes count as
activity; processing/debug messages do not. Explicit SSH intervals take
precedence over inactivity. SSH logins without a matching active tuple are
counted as orphan metadata. Different connections may still reuse a Telnet
tuple within an hour when login information is absent.

Session assignment reads all selected source events before applying `--limit`
or `--max-records`. These flags limit emitted shell observations; they do not
truncate source files before reconstructing sessions. A custom archive gets
its digest in inferred session IDs, so partial collections cannot silently
claim the same inferred IDs as the pinned release. All source files are read
also when the shared `--sample-files` option is supplied; its presence marks
the run incomplete, as with other shared sampling flags.

## Shell reconstruction and behavior labels

Literal input strings are preserved verbatim, with parsed process children.
Recognized `command  found [ ... ]` wrappers are decoded with `ast.literal_eval`
and strict UTF-8. In fragment-only connections, both recognized and failed
command fragments become best-effort shell observations. Their audit entries
retain the original message and mark the reconstruction: lost quoting and
operators cannot be recovered. This follows the updated design in
[issue #154](https://github.com/davidwagner/malcmds/issues/154).

For connections containing both literal inputs and fragments, the importer
retains literal inputs and records ambiguous fragments as omitted. It never
counts `command.process` messages as additional observations. Isolated failed
messages remain in the audit when no fragment input establishes that format.
Malformed records and unsupported protocols are counted and skipped.

The small catalogue in `scripts/_shell_honeypot_labels.py` labels behavior.
Narrow routine queries are benign. Explicit SSH-key installation, security
control disabling, and matching download-and-execute sequences are malicious.
Uncovered or incomplete syntax stays unknown. Redirections and substitutions
are checked before benign classification. Compound inputs become malicious
when a recognized harmful component is present; unrelated process children
retain their own labels. All `group_id` values are NULL.

KISS reviews the rules and frequent unknown inputs. Replay severity assists
that review but never determines a label. An unsuccessful harmful command can
have score zero. The importer retains all exact-text curated references and
scores, including disagreements. Replay turn indices never link an annotation
to an original command occurrence.

## Audit and reproduction

Each import writes three files beside `release.tar.gz`:

- `import-manifest.json`: revision, actual archive hash, source paths and sizes,
  session threshold, inferred-ID scope, and output limits.
- `import-audit.jsonl`: source record IDs, connection methods, label rules,
  exact-text replay references, reconstruction limitations, and rejected rows.
  Bulk processing/debug messages are counted by event type in the summary.
- `import-summary.json`: emitted rows, label counts and unknown rates by
  period/protocol, most frequent unknown strings, omission reasons, session
  counts, and Telnet comparisons at 5, 15, 30, and 60 minutes.

These files describe the reader's output. Check the shared writer's `INGESTED`
table for successful database completion. A completed dataset is skipped on
retry. An interrupted or bounded import is replaced in both tables on retry.
Use a fresh database for a complete rebuild or to compare catalogue versions.
Audit files are replaced by the next actual import; retain copies when
comparing runs. The main schema is unchanged.

## Measured pinned release

The complete import produced **685,248 shell rows** and **1,429,196 process
rows**, with unique record IDs and matching parent/child session IDs. Of the
shell rows, 519,466 are SSH, 97,888 are Telnet, and 67,894 are earlier derived
occurrences. SSH includes four failed-command fragments reconstructed in
fragment-only connections. Every row uses Linux as the collection-level OS
estimate. Neither table contains `malicious-group` labels or non-NULL groups.

| Collection | Benign shell rows | Malicious shell rows | Unknown shell rows | Unknown shell rate | Unknown process rate | Unknown distinct-input rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2024 SSH | 358,425 | 75,766 | 85,275 | 16.42% | 57.92% | 98.29% |
| 2024 Telnet | 19 | 0 | 97,869 | 99.98% | 99.73% | 99.84% |
| 2021–2022, protocol unavailable | 42,581 | 3,007 | 22,306 | 32.85% | 42.90% | 99.65% |

The initial catalogue left 35.46% of SSH and 84.59% of earlier shell rows
unknown. KISS reviewed the frequent uncovered inputs and added the repeated
SSH-key installation and exact read-only query rules, giving the rates above.
This improves occurrence coverage but covers few distinct command strings.
The residual unknown rate is substantial, especially for Telnet; this
implementation does **not** establish a low acceptable unknown threshold.

The leading SSH unknown is `cd ~; chattr -ia .ssh; lockr -ia .ssh` (75,674
occurrences): it changes file protection, but `lockr` has unresolved semantics
and the input alone does not install a key. Telnet is dominated by `system`
(15,169), `enable` (15,166), `sh` (15,165), `shell` (15,161), and `ping; sh`
(13,968). Their behavior depends on the device shell or further interaction.
The earlier source also includes `Enter new UNIX password: ` (2,423), whose
status as submitted input cannot be recovered from the derived list. These
remain unknown instead of inheriting a label from attacker association.

There are 409,025 SSH sessions with observations (332,878 singletons), and
67,894 earlier fallback sessions. Telnet sensitivity, counted on input events:

| Idle interval | Sessions | Singletons |
| --- | ---: | ---: |
| 5 minutes | 15,205 | 18 |
| 15 minutes | 15,204 | 18 |
| 30 minutes | 15,204 | 18 |
| 60 minutes | 15,203 | 18 |

Only 4,814 of 10,215 Telnet intervals containing successful-login metadata
also contain input on the exact tuple. There are 353,783 orphan SSH login
events. These counts explain why login messages cannot reliably repair
missing endpoint matches. The importer omits 130,778 failed-command messages
from literal-input connections and 612 isolated failed fragments. It counts
1,143,697 processing messages and 807,529 key-exchange messages as metadata.
No mixed-format fragment omissions occurred in this pinned run.

Replay auditing reproduces 438 changed texts at matching replay-turn indices
and 30 exact command strings with conflicting severity scores. Empty shell
rows remain present: 39 SSH, 2,198 Telnet, and 154 earlier occurrences.
