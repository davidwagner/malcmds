"""Best-effort BOTS command labels from the pinned bots_rich.py indicators."""

import re
from collections.abc import Iterable, Iterator

from _ingest import Command

# Source: https://github.com/kmkholm/moe-mamba-soc-triage/blob/
# 44ef4e047c5dbff13f52bc3856b8060f0524f192/src/data/bots_rich.py
# Keep its literal, case-insensitive substring policy. Match only the command's
# program and arguments: other fields may describe a different process.
IOCS = (
    "45.77.53.176", "104.207.83.63", "139.198.18.205", "35.153.154.221",
    "209.107.196.112", "82.102.18.111", "botsv3.ministerofmayhem.com",
    "hdoor.exe", "iexeplorer.exe", "definitelydontinvestigatethisfile.sh",
    "frothly-brewery-financial-planning-fy2019-draft.xlsm",
    "586ef56f4d8963dd546163ac31c865d7", "akiajogcdxj5nw5pxupa",
    "frothlywebcode", "hyunki1984@naver.com", "yunki1984@naver.com",
)
IOC_RE = re.compile("|".join(re.escape(value) for value in IOCS), re.IGNORECASE)


def label_ioc_commands(commands: Iterable[Command]) -> Iterator[Command]:
    """Mark unknown commands with an IOC malicious, preserving existing labels.

    This heuristic can flag harmless inspection of an indicator. Its absence
    does not establish benign activity, so unmatched commands stay unknown.
    """
    for command in commands:
        if command.label == "unknown" and IOC_RE.search(" ".join([command.pgm, *command.args])):
            command.label = "malicious"
        yield command
