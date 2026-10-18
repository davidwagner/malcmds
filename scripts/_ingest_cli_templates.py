"""Concrete values for the inspected CLI Commands Explained placeholders."""

import json
import random
import re
from functools import cache
from pathlib import Path

from _ingest_tldr import _render

DATA = Path(__file__).resolve().parents[1] / 'datasets/cli-commands-explained/templates.json'


@cache
def _configuration():
    config = json.loads(DATA.read_text(encoding='utf-8'))
    tokens = set(config['placeholders'])
    for overrides in config['overrides'].values():
        tokens.update(overrides)
    # Match whole nested spellings before their inner placeholders.
    pattern = re.compile('|'.join(re.escape(token) for token in sorted(sorted(tokens), key=len, reverse=True)))
    return config, pattern


def fill_templates(text: str, occurrence: str, seed: int = 0) -> str:
    """Fill known placeholders before parsing, retaining literal shell syntax.

    Each occurrence and placeholder has its own seeded selection. Repeated
    placeholders share a value, and sampling or reingestion cannot change it.
    Exact source-row overrides distinguish ambiguous names from literal tags.
    Argument values use the existing tldr quote-aware renderer; explicitly
    marked fragments supply command options or globs. Nothing is executed.
    """
    config, pattern = _configuration()
    rules = config['placeholders'] | config['overrides'].get(occurrence, {})
    parts = []
    end = 0
    for match in pattern.finditer(text):
        token = match[0]
        pool_name = rules.get(token)
        parts.append(text[end:match.start()])
        if pool_name is None:
            parts.append(token)
        else:
            pool = config['pools'][pool_name]
            rng = random.Random(f'{seed}:{occurrence}:{token}')
            value = rng.choice(pool['values'])
            parts.append(_render(value, text[:match.start()], 'bash', pool['kind']))
        end = match.end()
    parts.append(text[end:])
    return ''.join(parts)
