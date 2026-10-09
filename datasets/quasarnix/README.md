# QuasarNix

[QuasarNix](https://huggingface.co/datasets/dtrizna/QuasarNix) publishes Linux
reverse-shell commands, adversarial variants, and NL2Bash background commands.
`./fetch` downloads all five JSON files at revision
`76269c612ef971a195de90cf80e57fd0973f828e`, verifying their published SHA-256 hashes.
`./ingest` reads the complete release into the shared DuckDB database.

Each source string is parsed as shell input without running it. Every resulting
command keeps the full original input and the source tokens outside its own
program and arguments. Filename, array index and command index identify each
occurrence, including repeated strings. No login session is inferred; the writer
uses its dataset-qualified per-record fallback.

Recognizable reverse-shell operations are malicious. A Python invocation that
only prints literal strings is benign. Preparation and ambiguous additions to a
positive string use that string's malicious group. All NL2Bash background
commands are benign. Invalid JSON escapes and embedded control characters in
the released background file are recovered locally before parsing; the command
text is otherwise retained.
