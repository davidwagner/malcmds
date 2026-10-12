/* Frame AVIATOR XML and select possible commands. Field parsing stays in Python.
 * Input is a NUL-terminated Python bytes object; length excludes its sentinel.
 * Each output triple is (byte offset, byte length, one-based source ordinal).
 */
#include <stddef.h>
#include <string.h>

typedef const char *(*finder)(const char *, size_t, const char *);

static const char *find_text(const char *data, size_t length, const char *needle) {
    (void)length;
    return strstr(data, needle);
}

/* Malformed exports can contain NULs; retain the existing parser's recovery. */
static const char *find_bytes(const char *data, size_t length, const char *needle) {
    size_t size = strlen(needle);
    while (length >= size) {
        const char *match = memchr(data, needle[0], length - size + 1);
        if (!match) return NULL;
        if (!memcmp(match, needle, size)) return match;
        length -= (size_t)(match - data) + 1;
        data = match + 1;
    }
    return NULL;
}

static const char *attribute_entity(const char *start, const char *end) {
    const char *p = start;
    while ((p = memchr(p, '&', (size_t)(end - p)))) {
        const char *q = p;
        while (q > start && q[-1] != '>' && q[-1] != '<') --q;
        if (q > start && q[-1] == '<') return p;
        /* Skip text through the next tag, including long escaped XML payloads.
         * Walking backwards from every entity would be quadratic in that text. */
        p = memchr(p, '<', (size_t)(end - p));
        if (!p) break;
    }
    return end;
}

size_t aviator_scan(const char *data, size_t length, size_t *spans, size_t capacity,
                    size_t *consumed, size_t *records) {
    const char *cursor = data, *limit = data + length;
    const char *markers[] = {"Command", "command", "cmdline", "HostApplication"};
    const char *next[5];
    finder find = memchr(data, 0, length) ? find_bytes : find_text;
    for (int i = 0; i < 4; ++i) {
        next[i] = find(data, length, markers[i]);
        if (!next[i]) next[i] = limit;
    }
    next[4] = attribute_entity(data, limit);
    size_t found = 0;
    *records = 0;
    *consumed = 0;
    while (cursor < limit && found < capacity) {
        const char *start = find(cursor, (size_t)(limit - cursor), "<Event");
        if (!start) {
            *consumed = length > 6 ? length - 6 : 0;
            break;
        }
        if (start + 6 == limit) {
            *consumed = (size_t)(start - data);
            break;
        }
        unsigned char c = (unsigned char)start[6];
        /* Non-ASCII characters may be Unicode whitespace. Let Python's original
         * framer decide, and subtract rejected starts from the source ordinal. */
        if (!(c == '>' || c == ' ' || (c >= 9 && c <= 13) ||
              (c >= 28 && c <= 31) || c >= 128)) {
            cursor = start + 6;
            continue;
        }
        const char *end = find(start, (size_t)(limit - start), "</Event>");
        if (!end) {
            *consumed = (size_t)(start - data);
            break;
        }
        end += 8;
        ++*records;
        int candidate = c >= 128;
        for (int i = 0; i < 5; ++i) {
            if (next[i] < end) {
                candidate = 1;
                next[i] = i == 4 ? attribute_entity(end, limit) :
                    find(end, (size_t)(limit - end), markers[i]);
                if (!next[i]) next[i] = limit;
            }
        }
        if (candidate) {
            spans[found * 3] = (size_t)(start - data);
            spans[found * 3 + 1] = (size_t)(end - start);
            spans[found * 3 + 2] = *records;
            ++found;
        }
        cursor = end;
        *consumed = (size_t)(end - data);
    }
    return found;
}
