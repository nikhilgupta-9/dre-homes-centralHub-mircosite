"""Shared helpers for the scanner (port of src/scanner/util.js plus JS-compat helpers).

The scanner was first written in Node, and a lot of its behaviour is defined by JavaScript
semantics (UTF-16 string indexes, `\\s`, `.`, `$` in regular expressions ...). To give the same
answers, this module translates JS regular expressions to Python ones (`rx`) and keeps text as
UTF-16 code units internally (`to16` / `from16`).
"""
import os
import re
import urllib.parse

# --------------------------------------------------------------------------- errors


class ScanError(Exception):
    """Raised for user-facing problems (bad path, broken zip ...). Message is user-ready."""


# --------------------------------------------------------------------------- constants

# Folders never worth reading (Mac zips carry __MACOSX junk).
SKIP_DIRS = {'node_modules', '.git', '.svn', '.hg', '__MACOSX', '.idea', '.vscode'}

LIMITS = {
    'maxFiles': 100000,
    'maxTextBytes': 2 * 1024 * 1024,  # largest html/php/js we parse
    'maxZipEntries': 200000,
    'maxZipTotalBytes': 2 * 1024 * 1024 * 1024,
    'maxZipFileBytes': 400 * 1024 * 1024,
}

# --------------------------------------------------------------------------- JS regex translation

# Characters JavaScript's \s matches (used for trim() and for translating \s).
JS_WS = ' \t\n\x0b\x0c\r                 　﻿'
_WS_CLASS_BODY = ' \\t\\n\\x0b\\x0c\\r   -     　﻿'
_LT = '\\n\\r  '  # JS line terminators

_RX_CACHE = {}


def _translate(src, multiline, dotall):
    out = []
    i = 0
    n = len(src)
    in_class = False
    while i < n:
        c = src[i]
        if c == '\\':
            nx = src[i + 1] if i + 1 < n else ''
            if nx == 's':
                out.append(_WS_CLASS_BODY if in_class else '[' + _WS_CLASS_BODY + ']')
            elif nx == 'S':
                out.append('\\S' if in_class else '[^' + _WS_CLASS_BODY + ']')
            else:
                out.append(c + nx)
            i += 2
            continue
        if in_class:
            if c == ']':
                in_class = False
                out.append(c)
            elif c in '[&|~':
                out.append('\\' + c)  # avoid Python's nested-set warnings
            else:
                out.append(c)
            i += 1
            continue
        if c == '[':
            in_class = True
            out.append('[')
            i += 1
            if i < n and src[i] == '^':
                out.append('^')
                i += 1
            continue
        if c == '.':
            out.append('(?s:.)' if dotall else '[^' + _LT + ']')
        elif c == '^':
            out.append('(?:(?<=[' + _LT + '])|\\A)' if multiline else '\\A')
        elif c == '$':
            out.append('(?=[' + _LT + ']|\\Z)' if multiline else '\\Z')
        elif c == '(' and src.startswith('(?<', i) and not src.startswith('(?<=', i) and not src.startswith('(?<!', i):
            out.append('(?P<')
            i += 3
            continue
        else:
            out.append(c)
        i += 1
    return ''.join(out)


def rx(src, flags=''):
    """Compile a JavaScript (non-unicode) regular expression source with JS semantics.

    flags: any of 'i' (ignore case), 'm' (multiline), 's' (dotall). 'g' is accepted and ignored
    (use finditer / sub).
    """
    key = (src, flags)
    hit = _RX_CACHE.get(key)
    if hit is not None:
        return hit
    f = re.ASCII
    if 'i' in flags:
        f |= re.IGNORECASE
    pat = re.compile(_translate(src, 'm' in flags, 's' in flags), f)
    _RX_CACHE[key] = pat
    return pat


def js_trim(s):
    return s.strip(JS_WS)


# Mac junk files never worth reading.
SKIP_FILE = rx(r'^(\.DS_Store|Thumbs\.db|\._.*)$')

# --------------------------------------------------------------------------- UTF-16 handling

_ASTRAL = re.compile('[\U00010000-\U0010ffff]')


def _split_astral(m):
    cp = ord(m.group()) - 0x10000
    return chr(0xD800 + (cp >> 10)) + chr(0xDC00 + (cp & 0x3FF))


def to16(s):
    """Represent astral characters as surrogate pairs so indexes/lengths match JavaScript."""
    return _ASTRAL.sub(_split_astral, s)


def from16(s):
    """Inverse of to16 (lone surrogates are kept as they are)."""
    for ch in s:
        if '\ud800' <= ch <= '\udfff':
            return s.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')
    return s


def from16_deep(v):
    """Apply from16 to every string (and dict key) of a JSON-like structure, in place where possible."""
    if isinstance(v, str):
        return from16(v)
    if isinstance(v, list):
        for i, x in enumerate(v):
            v[i] = from16_deep(x)
        return v
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            out[from16(k) if isinstance(k, str) else k] = from16_deep(x)
        v.clear()
        v.update(out)
        return v
    return v


def u16key(s):
    """Sort key giving JavaScript's default string ordering (UTF-16 code units)."""
    return s.encode('utf-16-be', 'surrogatepass')


def js_key_order(d):
    """JS objects list integer-like keys first (ascending), then the rest in insertion order."""
    ints = []
    rest = []
    for k in d:
        if re.match(r'^(0|[1-9][0-9]{0,9})$', k) and int(k) < 4294967295:
            ints.append(k)
        else:
            rest.append(k)
    if not ints:
        return d
    ints.sort(key=int)
    return {k: d[k] for k in ints + rest}


def uniq(seq):
    """Array.from(new Set(seq)): drop duplicates, keep first-seen order."""
    seen = set()
    out = []
    for x in seq:
        key = x if isinstance(x, (str, int, float, bool, type(None))) else id(x)
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def decode_uri_component(s):
    """decodeURIComponent, but tolerant: malformed input is returned unchanged instead of throwing."""
    try:
        return to16(urllib.parse.unquote(s, errors='strict'))
    except Exception:
        return s


def extname(name):
    """Node's path.extname (the last '.' that is not the first character)."""
    i = name.rfind('.')
    if i <= 0:
        return ''
    if name.endswith('..') and i == len(name) - 1 and name.strip('.') == '':
        return ''
    return name[i:]


# --------------------------------------------------------------------------- file helpers


def _fs_sorted(entries):
    # libuv (and so Node) returns directory entries sorted by name; do the same for stable results
    return sorted(entries, key=lambda e: os.fsencode(e.name))


def walk(root, skip_dir_names=None, max_files=None):
    """List every file under root (no symlinks). Paths use forward slashes.

    Returns a list of dicts {rel, size, ext, base}; the list has an extra attribute-like
    flag: use `walk_ex` when you need to know whether it was truncated.
    """
    files, _ = walk_ex(root, skip_dir_names, max_files)
    return files


def walk_ex(root, skip_dir_names=None, max_files=None):
    """Like walk() but returns (files, truncated)."""
    if skip_dir_names is None:
        skip_dir_names = SKIP_DIRS
    if max_files is None:
        max_files = LIMITS['maxFiles']
    out = []
    stack = ['']
    truncated = False
    while stack:
        rel = stack.pop()
        try:
            with os.scandir(os.path.join(root, rel) if rel else root) as it:
                ents = _fs_sorted(list(it))
        except OSError:
            continue
        for e in ents:
            try:
                if e.is_symlink():
                    continue
                child_rel = rel + '/' + e.name if rel else e.name
                if e.is_dir(follow_symlinks=False):
                    if e.name in skip_dir_names:
                        continue
                    stack.append(child_rel)
                elif e.is_file(follow_symlinks=False):
                    if SKIP_FILE.search(e.name):
                        continue
                    if len(out) >= max_files:
                        truncated = True
                        continue
                    try:
                        size = e.stat(follow_symlinks=True).st_size
                    except OSError:
                        continue
                    out.append({'rel': child_rel, 'size': size, 'ext': extname(e.name).lower(), 'base': e.name})
            except OSError:
                continue
    out.sort(key=lambda f: u16key(f['rel']))
    return out, truncated


def read_text(abs_path, max_bytes=None):
    """Read a text file as UTF-16-indexed text, or None when binary / too large / unreadable."""
    if max_bytes is None:
        max_bytes = LIMITS['maxTextBytes']
    try:
        if os.stat(abs_path).st_size > max_bytes:
            return None
        with open(abs_path, 'rb') as fh:
            buf = fh.read()
    except OSError:
        return None
    if b'\x00' in buf:
        return None
    s = buf.decode('utf-8', 'replace')
    if s[:1] == '﻿':
        s = s[1:]
    return to16(s)


def line_at(text, index):
    """1-based line number of a character index."""
    if index > len(text):
        index = len(text)
    return text.count('\n', 0, index) + 1 if index > 0 else 1


def count_newlines(s):
    return s.count('\n')


def resolve_rel(from_rel, target):
    """Posix-style join/normalize that never leaves the site root. Returns None if it escapes."""
    t = target.replace('\\', '/')
    if t.startswith('/'):
        base = []
        t = t[1:]
    else:
        d = from_rel[:from_rel.rindex('/')] if '/' in from_rel else ''
        base = d.split('/') if d else []
    for part in t.split('/'):
        if part == '' or part == '.':
            continue
        if part == '..':
            if not base:
                return None
            base.pop()
        else:
            base.append(part)
    return '/'.join(base)
