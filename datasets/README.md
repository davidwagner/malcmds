# Datasets containing Unix/Microsoft commands

Download all datasets with `./fetchall`.

One directory per dataset.  Each directory contains:
- README.md - description of the dataset
- `fetch` - a script to download the dataset

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
