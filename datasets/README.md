# Datasets containing Unix/Microsoft commands

Download all datasets with `./fetchall`.

One directory per dataset.  Each directory contains:
- README.md - description of the dataset
- `fetch` - a script to download the dataset

If `fetch` fails or is terminated partway through, simply re-run
it.  If you've already downloaded the dataset, `fetch` does nothing.
Once a file is downloaded, `fetch` creates `*.download.json` to
help avoid the need to re-download it.
