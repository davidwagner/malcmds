"""Static extraction of cmd invocations, including FOR and IF command bodies."""

import re


def cmd_tokens(text):
    """Return cmd tokens and character spans, without evaluating shell syntax."""
    tokens = []
    spans = []
    word = []
    word_start = 0
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        if not word:
            word_start = index
        if not quoted and not word:
            redirect = re.match(r"\d*[<>]{1,2}(?:&\d+)?", text[index:])
            if redirect:
                tokens.append(redirect[0])
                spans.append((index, index + len(redirect[0])))
                index += len(redirect[0])
                continue
        if not quoted and char == "%":
            variable = re.match(r"%[A-Za-z_][\w()]*%", text[index:])
            if variable:
                word.append(variable[0])
                index += len(variable[0])
                continue
        if char == "^" and index + 1 < len(text):
            if text[index + 1] in "\r\n":
                index += 2
                if text[index - 1] == "\r" and text[index:index + 1] == "\n":
                    index += 1
                continue
            word.append(text[index:index + 2])
            index += 2
            continue
        if char == '"':
            quoted = not quoted
        if not quoted and (char.isspace() or char in "&|<>()"):
            if word:
                tokens.append("".join(word))
                spans.append((word_start, index))
                word = []
            if char in "&|<>()":
                if char in "&|<>" and index + 1 < len(text) and text[index + 1] == char:
                    char += char
                    index += 1
                tokens.append(char)
                spans.append((index + 1 - len(char), index + 1))
            elif char in "\r\n" and (not tokens or tokens[-1] != "\n"):
                tokens.append("\n")
                spans.append((index, index + 1))
        else:
            word.append(char)
        index += 1
    if word:
        tokens.append("".join(word))
        spans.append((word_start, index))
    return tokens, spans


SEPARATORS = {'&', '&&', '|', '||', '\n'}
REDIRECT = re.compile(r'\d*[<>]{1,2}(?:&\d+)?')


def _for_body(tokens, spans, text, start):
    """Find DO after the parenthesized set, retaining a FOR /F subcommand."""
    opening = start
    while opening < len(tokens) and tokens[opening] != '(':
        opening += 1
    depth = 1
    closing = opening + 1
    while closing < len(tokens) and depth:
        depth += (tokens[closing] == '(') - (tokens[closing] == ')')
        closing += 1
    inner = None
    if '/f' in [token.lower() for token in tokens[start:opening]]:
        content = text[spans[opening][1]:spans[closing - 1][0]].strip() if opening < len(tokens) and not depth else ''
        quote = '`' if any('usebackq' in token.lower() for token in tokens[start:opening]) else "'"
        if len(content) >= 2 and content.startswith(quote) and content.endswith(quote):
            # FOR /F passes this text to a child cmd. Remove one caret layer.
            inner = re.sub(r'\^(.)', r'\1', content[1:-1])
    if closing < len(tokens) and tokens[closing].lower() == 'do':
        return closing + 1, inner
    return len(tokens), inner


def _if_body(tokens, start):
    """Skip the documented IF condition without evaluating its truth value."""
    index = start + 1
    while index < len(tokens) and tokens[index].lower() in {'/i', 'not'}:
        index += 1
    if index == len(tokens):
        return index
    if tokens[index].lower() in {'exist', 'defined', 'errorlevel', 'cmdextversion'}:
        return min(index + 2, len(tokens))
    comparison = re.match(r'(?:(?:"[^"]*")|[^\s=]+)\s*==\s*(?:"[^"]*"|[^\s]+)(?=\s|$)',
                          ' '.join(tokens[index:]))
    if comparison:
        consumed = 0
        while index < len(tokens) and consumed < comparison.end():
            consumed += len(tokens[index]) + 1
            index += 1
        return index
    # EQU/NEQ/LSS/LEQ/GTR/GEQ forms have two operands.
    return min(index + 3, len(tokens))


def cmd_commands(text):
    """Yield static invocations without executing conditions, loops, or variables.

    Each loop body appears once. Both IF branches appear in source order.
    Labels, comments, control words and redirects are excluded from argv.
    """
    tokens, spans = cmd_tokens(text)
    index = 0
    blocks = 0
    while index < len(tokens):
        token = tokens[index]
        name = token.lstrip('@').lower()
        if token in SEPARATORS or token in {'(', ')'} or name == 'else':
            blocks += (token == '(') - (token == ')' and blocks > 0)
            index += 1
            continue
        if name == 'for':
            index, inner = _for_body(tokens, spans, text, index)
            if inner is not None:
                yield from cmd_commands(inner)
            continue
        if name == 'if':
            index = _if_body(tokens, index)
            continue
        if name in {'rem', '::'} or name.startswith(':'):
            while index < len(tokens) and tokens[index] != '\n':
                index += 1
            continue
        indices = []
        redirect = False
        literal_depth = 0
        while index < len(tokens) and tokens[index] not in SEPARATORS:
            if tokens[index] == ')' and literal_depth == 0 and blocks:
                break
            token = tokens[index]
            literal_depth += (token == '(') - (token == ')' and literal_depth > 0)
            if REDIRECT.fullmatch(token):
                redirect = '&' not in token
            elif redirect:
                redirect = False
            else:
                indices.append(index)
            index += 1
        if not indices:
            continue
        words = []
        previous = None
        for position in indices:
            if previous is not None and spans[previous][1] == spans[position][0]:
                words[-1] += tokens[position]
            else:
                words.append(tokens[position])
            previous = position
        argv = [re.sub(r'\^(.)', r'\1', word.replace('"', '')) for word in words]
        argv[0] = argv[0].lstrip('@')
        if argv[0]:
            yield argv[0], argv[1:], [token for i, token in enumerate(tokens)
                                      if i not in indices and token != '\n']
