# Datasets containing Unix/Microsoft commands

Download all datasets with `./fetchall`.
Then, run `./ingest-all` to populate `../cmds.duckdb`.

# Contents

One directory per dataset.  Each directory contains:
- README.md - description of the dataset
- `fetch` - a script to download the dataset
- `ingest` - a script to parse the dataset and add to `../cmds.duckdb`

# Download/fetch

Run `./fetch` from within a dataset directory to download
just that dataset.

If `fetch` or `fetchall` fails or is terminated partway through,
simply re-run it. If you've already downloaded the dataset,
`fetch` does nothing.  Once a file is downloaded, `fetch` creates
`*.download.json` to help avoid the need to re-download it.

Some datasets download from Google Drive, which imposes rate
limits. To avoid this, log into your Google account from your
web browser, and set the environment variable
`FETCH_GOOGLE_BROWSER` to `firefox` [default], `chrome`,
`safari`, etc. This will authenticate to Google when downloading.
Run `python _google.py check` to make sure it is working.
Otherwise, run `fetchall` once a day until everything has
been downloaded.

## Ingest commands

Run `./ingest-all` or a dataset's `./ingest` to populate `../cmds.duckdb`.

It is safe to run `./ingest-all` or `./ingest` multiple times.
A `(dataset, record_id)` primary key prevents duplicate insertion
when rerunning these scripts.

For datasets containing shell input, `ingest` uses a Bash syntax
parser to split compound commands, remove redirections and assignments
preceding commands, and remove shell quoting.  Substitution commands
are extracted too. 
