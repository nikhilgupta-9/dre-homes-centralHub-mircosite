"""Find phone numbers and e-mail addresses written in pages. Port of contacts.js."""
from .util import decode_uri_component, js_trim, rx

_BAD_EMAIL_TLD = rx(r'\.(png|jpe?g|gif|svg|webp|css|js|ico|woff2?|ttf)$', 'i')
_EMAIL_RE = rx(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}', 'g')
# Indian mobiles (with/without +91), landlines with STD code, and generic international numbers
_PHONE_RE = rx(r'(?:\+?91[\s\-]?)?(?:[6-9]\d{4}[\s\-]?\d{5}|0\d{2,4}[\s\-]?\d{6,8})|\+\d{1,3}[\s\-]?\d[\d\s\-]{7,13}\d', 'g')
_NON_DIGIT = rx(r'\D', 'g')
_SCRIPT = rx(r'<script\b[\s\S]*?<\/script>', 'gi')
_STYLE = rx(r'<style\b[\s\S]*?<\/style>', 'gi')
_COMMENT = rx(r'<!--[\s\S]*?-->', 'g')
_NOT_NEWLINE = rx(r'[^\n]', 'g')
_SIX_DIGITS = rx(r'\d{6}')
_TEL_LINK = rx(r'''href\s*=\s*["']tel:([^"']+)["']''', 'gi')
_MAILTO_LINK = rx(r'''href\s*=\s*["']mailto:([^"'?]+)''', 'gi')
_HAS_AT = rx(r'@')
_TAG = rx(r'<[^>]*>', 'g')
_NBSP = rx(r'&nbsp;', 'gi')
_REPEATED = rx(r'^(\d)\1+$')


def phone_key(s):
    d = _NON_DIGIT.sub('', s)
    if len(d) == 12 and d.startswith('91'):
        d = d[2:]
    if len(d) == 11 and d.startswith('0'):
        d = d[1:]  # STD / trunk prefix 0 (0141-2345678 == +91 141 2345678)
    return d


def _blank(m):
    return _NOT_NEWLINE.sub('', m.group())


def extract_contacts(rel, html_masked, acc):
    """Find phone numbers and e-mail addresses written in pages, with file/line.

    Needed so the hub can later change "the phone number" in every place at once.
    html_masked: PHP-masked html (same line numbers as the file). acc: from new_contact_acc().
    """
    text = _SCRIPT.sub(_blank, html_masked)
    text = _STYLE.sub(_blank, text)
    text = _COMMENT.sub(_blank, text)
    lines = text.split('\n')

    def add(mp, key, display, line, via):
        it = mp.get(key)
        if it is None:
            it = {'value': display, 'count': 0, 'locations': []}
            mp[key] = it
        it['count'] += 1
        if len(it['locations']) < 25:
            it['locations'].append({'file': rel, 'line': line, 'via': via})

    for i, raw in enumerate(lines):
        if not raw or ('@' not in raw and not _SIX_DIGITS.search(raw)):
            continue
        # links first (tel: / mailto:) so we know HOW the value is written
        for m in _TEL_LINK.finditer(raw):
            dec = decode_uri_component(m.group(1))
            k = phone_key(dec)
            if len(k) >= 7:
                add(acc['phones'], k, js_trim(dec), i + 1, 'tel-link')
        for m in _MAILTO_LINK.finditer(raw):
            e = js_trim(decode_uri_component(m.group(1))).lower()
            if _HAS_AT.search(e) and not _BAD_EMAIL_TLD.search(e):
                add(acc['emails'], e, e, i + 1, 'mailto-link')
        plain = _NBSP.sub(' ', _TAG.sub(' ', raw))
        for m in _EMAIL_RE.finditer(plain):
            e = m.group().lower()
            if not _BAD_EMAIL_TLD.search(e):
                add(acc['emails'], e, e, i + 1, 'text')
        for m in _PHONE_RE.finditer(plain):
            k = phone_key(m.group())
            if 8 <= len(k) <= 13 and not _REPEATED.search(k):
                add(acc['phones'], k, js_trim(m.group()), i + 1, 'text')


def new_contact_acc():
    return {'phones': {}, 'emails': {}}


def finish_contacts(acc):
    def to_list(mp):
        return sorted(mp.values(), key=lambda it: -it['count'])

    return {'phones': to_list(acc['phones']), 'emails': to_list(acc['emails'])}
