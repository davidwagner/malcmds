A duckdb-native database with a main table, COMMANDS, which has one row per command line listed in one of the datasets.  Each row has the following columns:
- `pgm` - the program being executed (full path to executable; or if it's not available, one of argv[0] or first word of the command line or proctitle)
- `pgm_base` - `pgm`, but with leading directory components removed (e.g., if `pgm` = `/a/b/c/d`, then `pgm_base` = `d`)
- `args` - the arguments to the command (argv[1..]), as a list of strings (LIST(VARCHAR))
- `shell_input` - for datasets that record full shell input, this is the entire line typed into the command shell; NULL if the dataset doesn't record full shell input (e.g., if it only records kernel execve calls)
- `other_tokens` - list of other words/tokens from `shell_input` that aren't included in `args` or `pgm` (LIST(VARCHAR)), or an empty list if there is no full shell input
- `dataset` - the original dataset this command line appeared in came from, e.g., `optc`
- `record_id` - an identifier of the specific record/entry within the dataset (e.g., might be a UUID, a combination of a filename and line number, or other id that can be used to find the source record in the original dataset)
- `label` - `malicious`, `benign`, `unknown`, or `malicious-group` (`malicious-group` means that it is one command in an entire label group/session/connection, and the session/group/connection is believed to be malicious; it's not known whether this particular command is malicious or benign, but likely some/many of the commands in the session are malicious; i.e., individual commands are not labelled but a group of commands has been labelled as malicious, and this is one command in that group) (ENUM)
- `group_id` - a unique identifier for the label group (session/connection/time range) this command is part of, if `label` = `malicious-group`; otherwise NULL
- `session_id` - a unique identifier for the login session / SSH connection / etc. this command is part of
- `os` - `windows` or `linux` (inferred best-effort) (ENUM)

For uniformity, the `pgm`, `pgm_base`, `args` columns in this table are intended to simulate what an in-kernel audit log would/could see. Some datasets record command lines typed into the shell or sent over the network; those should be parsed and normalized into this format to populate `pgm`, `pgm_base`, `args`. For example, if a dataset contains a line typed into a shell, which might contain multiple commands (`cd ..; ls docs > /dev/null`), that will be expanded into multiple rows in this table (`cd ..` and `ls docs`) and only program names/args will be preserved. If the dataset does record full command lines typed into a shell, then the full line should be recorded in `shell_input` and `other_tokens` populated; otherwise those are NULL and the empty list.

All entries should be populated in a best-effort fashion. Don't document all the caveats about why they might be imperfect. Don't document the evidence for them. We don't try to preserve anything from the original dataset beyond the information above. We're trying to keep things simple for the consumer of this data.

Also, the table INGESTED will record which datasets have been fully ingested into COMMANDS.  It has two columns:
- `dataset` - the original dataset this command line appeared in came from, e.g., `optc`
- `ingested` - boolean, true if the `ingest` script has finished fully ingesting the database and adding it all to COMMANDS
