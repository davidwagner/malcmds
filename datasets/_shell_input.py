"""Assemble recorded Bash input without running any part of it."""

import re
import shlex
import subprocess
from functools import lru_cache


@lru_cache(maxsize=4096)
def syntax_result(text):
    """Return Bash's syntax-only result in an environment without startup hooks."""
    try:
        result = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-n"], input=text,
            text=True, capture_output=True, timeout=2, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (subprocess.TimeoutExpired, ValueError):
        return False, ""
    return result.returncode == 0, result.stderr


def heredoc_spans(text):
    """Locate here-document operators, delimiters and uninterpreted bodies.

    Quoted words and escaped operators are skipped. Body delimiters are matched
    in order, with tab stripping only for <<-. Spans retain source positions.
    """
    spans = []
    offset = 0
    quote = None
    while offset < len(text):
        end = text.find("\n", offset)
        end = len(text) if end < 0 else end
        pending = []
        i = offset
        while i < end:
            char = text[i]
            if char == "\\" and quote != "'":
                i += 2
                continue
            if quote:
                if char == quote:
                    quote = None
                i += 1
                continue
            if char in "'\"":
                quote = char
                i += 1
                continue
            if char == "#" and (i == offset or text[i - 1].isspace()):
                break
            if text.startswith("((", i):
                # Arithmetic uses << as a shift, including inside $((...)).
                depth = 2
                i += 2
                while i < len(text) and depth:
                    if text[i] == "\\":
                        i += 2
                        continue
                    if text[i] == "(":
                        depth += 1
                    elif text[i] == ")":
                        depth -= 1
                    i += 1
                end = max(end, i)
                continue
            if text.startswith("<<<", i):
                i += 3
                continue
            if not text.startswith("<<", i):
                i += 1
                continue
            start = i
            i += 2
            tabs = text[i:i + 1] == "-"
            if tabs:
                i += 1
            op_end = i
            while i < end and text[i].isspace():
                i += 1
            word_start = i
            word_quote = None
            while i < end:
                char = text[i]
                if char == "\\" and word_quote != "'":
                    i += 2
                    continue
                if word_quote:
                    if char == word_quote:
                        word_quote = None
                elif char in "'\"":
                    word_quote = char
                elif char.isspace() or char in ";|&<>()":
                    break
                i += 1
            try:
                words = shlex.split(text[word_start:i])
            except ValueError:
                return spans, False
            if not words:
                return spans, False
            descriptor = start
            while descriptor > offset and text[descriptor - 1].isdigit():
                descriptor -= 1
            if descriptor < start and (descriptor == offset or text[descriptor - 1].isspace()):
                spans.append((descriptor, start))
            spans.extend([(start, op_end), (word_start, i)])
            pending.append((words[0], tabs))
        offset = end + 1
        for delimiter, tabs in pending:
            body_start = offset
            while offset <= len(text):
                end = text.find("\n", offset)
                end = len(text) if end < 0 else end
                line = text[offset:end]
                if (line.lstrip("\t") if tabs else line) == delimiter:
                    if body_start < offset:
                        spans.append((body_start, offset))
                    spans.append((offset, end))
                    offset = end + 1
                    break
                offset = end + 1
            else:
                return spans, False
    return spans, True


def complete_inputs(parts):
    """Yield source fragment indexes and complete inputs, resuming after bad input."""
    index = 0
    while index < len(parts):
        text = parts[index]
        end = index + 1
        while (len(text) - len(text.rstrip("\\"))) % 2 and end < len(parts):
            text += "\n" + parts[end]
            end += 1
        _, complete = heredoc_spans(text)
        while not complete and end < len(parts):
            text += "\n" + parts[end]
            end += 1
            _, complete = heredoc_spans(text)
        if not complete:
            return
        # Only incomplete quotes/compound statements need additional fragments.
        # A rejected standalone construct must not consume the next input.
        try:
            shlex.split(text)
            incomplete_quote = False
        except ValueError:
            incomplete_quote = True
        if (incomplete_quote or "$(" in text or "`" in text
                or re.match(r"\s*(?:if|for|while|case)\b", text)):
            valid, error = syntax_result(text)
            if not valid and ("unexpected end of file" in error or "unexpected EOF" in error):
                candidate = text
                for following in range(end, len(parts)):
                    candidate += "\n" + parts[following]
                    valid, _ = syntax_result(candidate)
                    if valid:
                        text, end = candidate, following + 1
                        break
        yield index, text
        index = end
