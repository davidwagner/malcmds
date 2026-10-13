# tldr-pages

This dataset supplies authored shell examples from [tldr-pages/tldr](https://github.com/tldr-pages/tldr), with concrete arguments replacing template placeholders. Both complete submissions and derived program invocations receive `benign`, with no group ID. This is the collection's labeling policy for instructional examples; it does not establish whether an operation is appropriate on a particular machine.

`./fetch` downloads commit `6baf5eaa78b6181f4adc2176788d670389b33658` (2018-12-26) as an archive and verifies its size and SHA-256. This deliberately uses a historical snapshot: it provides 767 English common pages, 292 Linux pages and 82 Windows pages, with a manageable set of substitution rules that can be inspected. It does not represent current tldr coverage. All three directories are read; common pages are interpreted as Linux shell examples. This snapshot's Windows pages use cmd.exe syntax. The separate Microsoft documentation dataset supplies PowerShell examples.

The archive includes the upstream `LICENSE.md`: page content is licensed under Creative Commons Attribution 4.0. Source attribution is tldr-pages contributors, at the pinned repository revision above. The test fixture copies a small selection of those pages unchanged.

Run `./ingest --db ../../cmds.duckdb` after fetching. Standard ingestion options (`--limit`, `--max-records`, `--sample-files`, `--seed`) are supplied by the shared runner. The importer never executes an example. It passes Linux text to the Bash parser and Windows text to the existing cmd parser.

## Substitution and extraction

`pools.json` contains reusable concrete paths, users, hostnames, addresses, ports, passwords, and messages. `rules.json` contains an exact lookup for each placeholder form in the selected corpus, plus source-local overrides. Unknown forms fail with their document and line number. No model or name-based guessing runs during ingestion.

The generation seed is **0**, and each template yields **three variants**. The generator derives a separate SHA-256 seed from the JSON array `[seed, example_id, variant_number]`; sampling and ingestion limits therefore do not change the selected values. An example without template fields yields once. Duplicate generated strings retain distinct occurrence IDs, just as duplicate source examples do.

Rules distinguish argument values from shell fragments such as command lists. Argument rendering respects existing quotes and adds quotes when needed. Pools include directory names containing spaces. Repeated placeholders reuse their value. Related source and destination paths share a pool index, preserving the filename while selecting distinct directories. Extension rules and document-specific values cover programs requiring particular source languages, media formats, devices, numeric ranges, or enumerated options. For example, `color` receives two hexadecimal digits, `eventcreate` receives an ID between 1 and 1000, and the RAID creation example uses two distinct disk devices for a two-disk mirror.

Explicit source-local rules also resolve notation outside braces, such as `[PATH...]` and `start/stop/restart/reload`. They repair a few upstream missing delimiters and malformed template braces. These corrections are checked in as complete replacement templates. Commands already containing concrete arguments are retained unchanged except where the source uses such documented syntax notation or a listed typo correction.

Backtick-only Markdown lines supply complete examples. Pipelines, redirects, quoted arguments, and command lists remain together. Source-local exclusion rules omit editor keystrokes, SQL/client commands, debugger input, and other interactive application input. For example, `less file` is shell input; pressing `q` inside less is not. Full extraction reads all selected pages and rejects unresolved `{{...}}` markup.

Record IDs use `platform/page.md:source_line:variant`; derived commands append their invocation index. Every input has its own fallback session, `tldr-pages:record:<record_id>`. No descriptions or substitution metadata are stored in the database.
