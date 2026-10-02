"""Fetch pinned DARPA TC originals and support files using the shared downloader."""

import argparse
import csv
from pathlib import Path

from _fetch import download


def fetch(engagement, collector):
    """Download one collector's binary streams, schemas, and attack ground truth."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--metadata-only",
        action="store_true",
        help="download only schemas, ground truth, release notes, and checksum lists",
    )
    args = parser.parse_args()
    dataset = f"tc-{engagement}-{collector}"
    manifest = Path(__file__).with_name("_tc_manifest.tsv")
    with manifest.open() as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            if row["dataset"] not in (engagement, dataset):
                continue
            if args.metadata_only and row["path"].startswith("data/"):
                continue
            download(
                row["url"],
                row["path"],
                size=int(row["size"]) if row["size"] else None,
                checksum=row["checksum"] or None,
            )
