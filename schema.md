A duckdb database with a main table, COMMANDS, which has one row per command line listed in one of the datasets.  Each row has the following columns:
- `pgm` - the program being executed (full path to executable; or if it's not available, one of argv[0] or proctitle or first word of the command line)
- `pgm_base` - `pgm`, but with leading directory components removed (e.g., if `pgm` = `/a/b/c/d`, then `pgm_base` = `d`)
- `args` - the arguments to the command (argv[1..]), as a list of strings (LIST(VARCHAR))
- `dataset` - the original dataset this command line appeared in came from, e.g., `optc`
- `record_id` - an identifier of the specific record/entry within the dataset (e.g., might be a UUID, a combination of a filename and line number, or other id that can be used to find the source record in the original dataset)
- `label` - `malicious`, `benign`, `unknown`, or `malicious-session` (the latter means that it is one command in an entire session/group/connection, and the session/group/connection is believed to be malicious; it's not known whether this particular command is malicious or benign, but likely some/many of the commands in the session are malicious)
- `session_id` - a unique identifier for the session/group/connection this command is part of, if `label` = `malicious-session`; otherwise NULL

All entries should be populated in a best-effort fashion. Don't document all the caveats about why they might be imperfect. Original datasets might have different formats (shell command lines, kernel audit logs of processes executed and their arguments, etc.), but we are going to normalize them and parse them into this format, in a best-effort fashion. Don't try to preserve everything from the original dataset. If a dataset contains a line typed into a shell, which might contain multiple commands (`cd ..; ls`), that will be expanded into multiple rows in this table.
