# Datasets containing Unix/Microsoft commands

This directory contains a variety of public datasets,
which contain Unix/Microsoft commands.

To use this, first download all datasets:
see Download/fetch below.
Then, run `../scripts/ingestall` to populate `../cmds.duckdb`.

The commands below assume your working directory is `datasets/`, unless
a dataset directory is specified. Shared scripts and their requirements are
in `../scripts/`; tests and their fixtures are in `../tests/`.

# Contents

One directory per dataset.  Each directory contains:
- README.md - description of the dataset
- `fetch` - a script to download the dataset
- `ingest` - a script to parse the dataset and add to `cmds.duckdb` at the repository root

# Download/fetch

To download all datasets, run

```
while ! ../scripts/fetchall; do sleep 1200; done
```

until it completes without errors.

To make this go quicker, log into your Google account
from your web browser, and set the environment variable
`FETCH_GOOGLE_BROWSER` to `firefox` [default], `chrome`,
or `safari`. This will authenticate to Google when downloading.
Run `python ../scripts/_google.py check` to make sure it is working.
Then, run the `fetchall` command above. This helps avoid
some rate limits with Google Drive.

Even using your Google account, it may take several days
before the download completes successfully, as some datasets
are enormous and run into Google and Zenodo's rate limits.

To download a single dataset, run `./fetch` from within
a dataset directory.

If `fetch` or `fetchall` fails or is terminated partway through,
simply re-run it. It will continue from where it left off.
If you've already downloaded the dataset, `fetch` does nothing.
Once a file is downloaded, `fetch` creates `*.download.json`
to help avoid the need to re-download it.

## Ingest commands

Run `../scripts/ingestall` to populate `../cmds.duckdb`.

Or, if you want only a single dataset, run `./ingest` from
the dataset directory.

It is safe to run `../scripts/ingestall` or `./ingest` multiple times.
The scripts will prevent duplicates.

For datasets containing shell input, `ingest` uses a Bash syntax
parser to split compound commands, remove redirections and assignments
preceding commands, remove shell quoting, extract substitution commands,
and normalize to simulate what a kernel logger would observe.
