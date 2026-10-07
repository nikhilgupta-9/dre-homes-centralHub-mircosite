"""Pure text edits for the injector (port of src/injector/edits.js).

Files are handled as latin1 strings (byte-for-byte), so non-UTF8 pages survive untouched. Every edit is an
INSERTION: the original text is never rewritten, which lets us prove "remove the inserted text => original file"
for every file we touch.  Python 3.9 compatible, stdlib only.
"""
import re

GUARD_BEGIN = '/* SpamGuard:begin */'
GUARD_END = '/* SpamGuard:end */'
SCRIPT_MARK = '<!-- SpamGuard -->'
APPLY_BEGIN = '/* SpamGuard:apply */'
APPLY_END = '/* SpamGuard:apply-end */'
CONTACT_MARK = '<!-- SpamGuard:contact -->'

BOM = '\xEF\xBB\xBF'
# JavaScript's \s on latin1 text (Python's \s would also match \x1c-\x1f and \x85)
_WS = '\t\n\x0b\x0c\r \xa0'
_S = '[' + _WS + ']'
_JS_TRIM = _WS


def js_trim(s):
    return s.strip(_JS_TRIM)


def detect_eol(t):
    return '\r\n' if '\r\n' in t else '\n'


def php_inline(v):
    """PHP literal on one line (for the per-handler success override)."""
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        if isinstance(v, float):
            if v != v or v in (float('inf'), float('-inf')):
                return 'null'
            if v == int(v):
                return str(int(v))
        return str(v)
    if isinstance(v, str):
        s = v.replace('\\', '\\\\').replace("'", "\\'")
        s = re.sub(r'[\r\n]+', ' ', s)
        return "'" + s + "'"
    if isinstance(v, (list, tuple)):
        return '[' + ', '.join(php_inline(x) for x in v) + ']'
    return '[' + ', '.join(php_inline(str(k)) + ' => ' + php_inline(x) for k, x in v.items()) + ']'


def guard_code(rel_to_root, override, namespaced):
    """The text of the guard, ready to be placed after `<?php`."""
    p = (re.sub(r'/+$', '', rel_to_root) + '/' if rel_to_root else '') + 'spamguard/spamguard.php'
    file = "__DIR__ . '/%s'" % p
    arg = php_inline(override) if override else ''
    cls = '\\SpamGuard' if namespaced else 'SpamGuard'
    # is_file(): if the kit folder is ever missing the site keeps working (fail-open), it never crashes.
    return '%s if (is_file(%s)) { require_once %s; %s::guard(%s); } %s' % (GUARD_BEGIN, file, file, cls, arg, GUARD_END)


_RE_OPEN_PHP = re.compile(r'<\?php(?=[' + _WS + r']|\Z)', re.I)
_RE_FILLER = re.compile(r'(?:' + _S + r'+|//[^\r\n]*|#(?!\[)[^\r\n]*|/\*[\s\S]*?\*/)+')
_RE_DECLARE = re.compile(r'declare' + _S + r'*\([^)]*\)' + _S + r'*;', re.I)
_RE_NAMESPACE = re.compile(r'namespace' + _S + r'+[A-Za-z0-9_\\]+' + _S + r'*;', re.I)
_RE_NAMESPACE_ANY = re.compile(r'namespace(?![A-Za-z0-9_])', re.I)


def find_guard_spot(text):
    """Where PHP starts and which leading declare/namespace statements must stay first."""
    bom = 3 if text.startswith(BOM) else 0
    first_tag = text.find('<?', bom)
    if first_tag == -1:
        return {'error': 'no-php'}
    opn = first_tag
    if js_trim(text[bom:opn]) != '':
        return {'error': 'php-not-at-top'}
    m = _RE_OPEN_PHP.match(text, opn)
    if not m:
        return {'error': 'short-open-tag'}
    pos = m.end()
    namespaced = False
    spot = pos
    after = False
    for _ in range(50):
        ws = _RE_FILLER.match(text, pos)
        if ws:
            pos = ws.end()
        d = _RE_DECLARE.match(text, pos)
        if d:
            pos = d.end()
            spot = pos
            after = True
            continue
        d = _RE_NAMESPACE.match(text, pos)
        if d:
            pos = d.end()
            spot = pos
            after = True
            namespaced = True
            continue
        if _RE_NAMESPACE_ANY.match(text, pos):
            return {'error': 'bracketed-namespace'}
        break
    return {'offset': spot, 'afterDirective': after, 'namespaced': namespaced}


def _rest_of_line(text, offset):
    m = re.compile(r'[^\r\n]*').match(text, offset)
    return m.group(0)


_RE_ALREADY_GUARD = re.compile(r'SpamGuard' + _S + r'*::' + _S + r'*guard' + _S + r'*\(')


def plan_guard_edit(text, rel_to_root, override=None):
    """Build the guard insertion. Returns {offset, insert} or {error}."""
    if _RE_ALREADY_GUARD.search(text):
        return {'error': 'already'}
    spot = find_guard_spot(text)
    if spot.get('error'):
        return spot
    eol = detect_eol(text)
    code = guard_code(rel_to_root, override, spot['namespaced'])
    rest = _rest_of_line(text, spot['offset'])
    insert = eol + code if js_trim(rest) == '' else ' ' + code
    return {'offset': spot['offset'], 'insert': insert}


_RE_PHP_TAG = re.compile(r'<\?(?:php(?![A-Za-z0-9_])|=)?|\?>', re.I)


def in_php_at(text, offset):
    """Is `offset` inside a <?php ... ?> region? (naive tag walk, good enough to refuse unsafe spots)"""
    in_php = False
    for m in _RE_PHP_TAG.finditer(text):
        if m.start() >= offset:
            break
        in_php = m.group(0) != '?>'
    return in_php


def plan_script_edit(text, after_line, tag_src):
    """Build the <script> insertion: after the form's last line (or before </body> as a fallback)."""
    if re.search(r'spamguard\.js', text, re.I):
        return {'error': 'already'}
    eol = detect_eol(text)
    tag = '%s<script src="%s" defer></script>' % (SCRIPT_MARK, tag_src)

    def line_end(n):
        idx = -1
        for _ in range(n):
            idx = text.find('\n', idx + 1)
            if idx == -1:
                return len(text)
        return idx + 1

    def place(offset):
        needs_eol = offset > 0 and text[offset - 1] != '\n'
        return {'offset': offset, 'insert': (eol if needs_eol else '') + tag + eol}

    if after_line and after_line > 0:
        off = line_end(int(after_line))
        if not in_php_at(text, off):
            return place(off)
    body = text.lower().rfind('</body>')
    if body != -1 and not in_php_at(text, body):
        return place(body)
    return {'error': 'script-position-unsafe'}


_RE_APPLY_DONE = re.compile(r'sg-apply\.php', re.I)
_RE_STARTS_PHP = re.compile(r'<\?php(?=[' + _WS + r']|\Z)', re.I)
_RE_STARTS_SHORT = re.compile(_S + r'*<\?(?!php(?![A-Za-z0-9_])|=)', re.I)
_RE_STRICT = re.compile(r'declare' + _S + r'*\(' + _S + r'*strict_types', re.I)
_RE_NS_LINE = re.compile(r'(?<![^\r\n])namespace(?![A-Za-z0-9_])', re.I)
_RE_NS_IN_PHP = re.compile(r'<\?php[\s\S]*?(?<![A-Za-z0-9_])namespace' + _S + r'+[A-Za-z0-9_\\]+' + _S + r'*[;{]', re.I)


def plan_apply_edit(text, rel_to_root):
    """Site-wide hook for PHP pages: one require_once at the very top. Fail-open. Returns {offset, insert} or {error}."""
    if _RE_APPLY_DONE.search(text):
        return {'error': 'already'}
    eol = detect_eol(text)
    p = (re.sub(r'/+$', '', rel_to_root) + '/' if rel_to_root else '') + 'spamguard/sg-apply.php'
    file = "__DIR__ . '/%s'" % p
    body = '%s if (is_file(%s)) { require_once %s; } %s' % (APPLY_BEGIN, file, file, APPLY_END)
    bom = 3 if text.startswith(BOM) else 0
    if _RE_STARTS_PHP.match(text, bom):
        spot = find_guard_spot(text)
        if spot.get('error'):
            return spot
        rest = _rest_of_line(text, spot['offset'])
        return {'offset': spot['offset'], 'insert': eol + body if js_trim(rest) == '' else ' ' + body}
    if _RE_STARTS_SHORT.match(text, bom):
        return {'error': 'short-open-tag'}
    # the file starts with HTML (or has PHP only further down): put a tiny PHP block in front of it.
    if _RE_STRICT.search(text):
        return {'error': 'declare-after-html'}
    if _RE_NS_LINE.search(text) and _RE_NS_IN_PHP.search(text):
        return {'error': 'namespace-after-html'}
    return {'offset': bom, 'insert': '<?php %s ?>' % body + eol}


def plan_contact_script_edit(text, src):
    """<script src=".../contact.js"> before the last </body> (outside PHP)."""
    if re.search(r'contact\.js', text, re.I) and re.search(r'spamguard/contact\.js', text, re.I):
        return {'error': 'already'}
    eol = detect_eol(text)
    body = text.lower().rfind('</body>')
    if body == -1:
        return {'error': 'no-body'}
    if in_php_at(text, body):
        return {'error': 'script-position-unsafe'}
    needs_eol = body > 0 and text[body - 1] != '\n'
    return {'offset': body, 'insert': (eol if needs_eol else '') + '%s<script src="%s" defer></script>' % (CONTACT_MARK, src) + eol}


def apply_insertions(text, edits):
    """Apply insertions (never overlapping) from the end of the file to the start, with a round-trip proof."""
    out = text
    for e in sorted(edits, key=lambda e: -e['offset']):
        out = out[:e['offset']] + e['insert'] + out[e['offset']:]
    # Safety proof: taking the inserted text back out gives exactly the original.
    pieces = []
    cursor = 0
    shift = 0
    for e in sorted(edits, key=lambda e: e['offset']):
        at = e['offset'] + shift
        pieces.append(out[cursor:at])
        cursor = at + len(e['insert'])
        shift += len(e['insert'])
    pieces.append(out[cursor:])
    if ''.join(pieces) != text:
        raise RuntimeError('internal: edit verification failed')
    return out


def line_of_offset(text, offset):
    """1-based line number of an offset."""
    return text.count('\n', 0, offset) + 1
