"""Link a form to the AJAX call that submits it. Port of ajax.js (heuristics are identical)."""
import re

from .util import line_at, rx

# JS libraries are never form handlers: skip them (cheap, and avoids false matches).
_LIB_FILE = rx(r'(^|[\/.\-_])(jquery|bootstrap|popper|slick|owl|swiper|wow|aos|lightbox|fancybox|isotope|magnific|waypoints|counterup|modernizr|validate|validator|moment|lodash|underscore|angular|react|vue|chart|gsap|three|select2|datatables|tinymce|ckeditor|particles|typed|parallax|jquery-ui|easing|imagesloaded|masonry|sweetalert|toastr|recaptcha|analytics|gtag|fontawesome|polyfill|vendor|vendors|plugins?)(\.|-|_|\/)', 'i')
_MIN_JS = rx(r'\.min\.js$', 'i')


def is_library_js(rel):
    return bool(_MIN_JS.search(rel)) or bool(_LIB_FILE.search(rel))


_Q = '[\'"`]'
_RE_AJAX = rx(r'\$\.ajax\s*\(\s*\{', 'g')
_RE_NEXT_AJAX = rx(r'\$\.ajax\s*\(')
_RE_URL = rx(r'''url\s*:\s*(['"`])([^'"`]+)\1''')
_RE_USES_ACTION = rx(r'''url\s*:\s*[^,}]*(?:attr\s*\(\s*['"]action['"]\s*\)|\.action\b|prop\s*\(\s*['"]action['"])''')
_RE_TYPE = rx(r'''(?:type|method)\s*:\s*['"](\w+)['"]''', 'i')
_RE_DATATYPE = rx(r'''dataType\s*:\s*['"](\w+)['"]''')
_RE_POST = rx(r'''\$\.(post|get)\s*\(\s*(['"`])([^'"`]+)\2''', 'g')
_RE_POST_ACTION = rx(r'''\$\.post\s*\(\s*[^,'"`)]*(?:attr\s*\(\s*['"]action['"]\s*\)|\.action\b)''', 'g')
_RE_FETCH = rx(r'''\bfetch\s*\(\s*(['"`])([^'"`]+)\1([\s\S]{0,300})''', 'g')
_RE_METHOD_POST = rx(r'''method\s*:\s*['"]post['"]''', 'i')
_RE_FETCH_ACTION = rx(r'''\bfetch\s*\(\s*[\w$.]*(?:\.action\b|attr\s*\(\s*['"]action['"]\s*\))''', 'g')
_RE_XHR = rx(r'''\.open\s*\(\s*['"]post['"]\s*,\s*(['"`])([^'"`]+)\1''', 'gi')
_RE_XHR_ACTION = rx(r'''\.open\s*\(\s*['"]post['"]\s*,\s*[\w$.]*(?:\.action\b|attr\s*\(\s*['"]action['"]\s*\))''', 'gi')
_RE_AXIOS = rx(r'''\baxios\.post\s*\(\s*(['"`])([^'"`]+)\1''', 'g')


def find_ajax_calls(js):
    """All AJAX-ish calls in a script: [{index, url|None, usesFormAction, kind, method?, dataType?}]."""
    out = []

    def push(index, url, kind, extra=None):
        d = {'index': index, 'url': url or None, 'usesFormAction': False, 'kind': kind}
        if extra:
            d.update(extra)
        out.append(d)

    for m in _RE_AJAX.finditer(js):
        # options object can be long (data + success handlers): read a window, stop at the next ajax call
        start = m.end()
        body = js[start:start + 2500]
        nxt = _RE_NEXT_AJAX.search(body)
        if nxt:
            body = body[:nxt.start()]
        u = _RE_URL.search(body)
        uses_action = bool(_RE_USES_ACTION.search(body))
        typ = _RE_TYPE.search(body)
        dt = _RE_DATATYPE.search(body)
        push(m.start(), u.group(2) if u else None, 'jquery-ajax', {
            'usesFormAction': uses_action and not u,
            'method': typ.group(1).upper() if typ else None,
            'dataType': (dt.group(1) if dt else None) or None,
        })
    for m in _RE_POST.finditer(js):
        if m.group(1) == 'post':
            push(m.start(), m.group(3), 'jquery-post', {'method': 'POST'})
    for m in _RE_POST_ACTION.finditer(js):
        push(m.start(), None, 'jquery-post', {'usesFormAction': True, 'method': 'POST'})
    for m in _RE_FETCH.finditer(js):
        if _RE_METHOD_POST.search(m.group(3)):
            push(m.start(), m.group(2), 'fetch', {'method': 'POST'})
    for m in _RE_FETCH_ACTION.finditer(js):
        push(m.start(), None, 'fetch', {'usesFormAction': True, 'method': 'POST'})
    for m in _RE_XHR.finditer(js):
        push(m.start(), m.group(2), 'xhr', {'method': 'POST'})
    for m in _RE_XHR_ACTION.finditer(js):
        push(m.start(), None, 'xhr', {'usesFormAction': True, 'method': 'POST'})
    for m in _RE_AXIOS.finditer(js):
        push(m.start(), m.group(2), 'axios', {'method': 'POST'})
    out.sort(key=lambda c: c['index'])
    return out


_RE_HINT_KEYED = rx(r'''\b(?:data|response|res|result|resp|msg|json|d)\.(\w+)\s*(===?|!==?)\s*(['"]?)([\w\- ]+)\3''', 'g')
_RE_HINT_PLAIN = rx(r'''\b(?:data|response|res|result|resp|msg|text|t|d)(?:\.trim\s*\(\s*\))?\s*(===?)\s*(['"])([^'"]{1,30})\2''', 'g')
_RE_HINT_IF = rx(r'''\bif\s*\(\s*(!?)\s*(?:data|response|res|result|resp)\.(success|ok|status|error)\s*\)''', 'g')
_RE_IS_JSON = rx(r'''dataType\s*:\s*['"]json['"]|\.json\s*\(\s*\)|JSON\.parse|\$\.getJSON''')
_RE_IS_TEXT = rx(r'''\.text\s*\(\s*\)|responseText''')


def expected_response(js, frm):
    """What does the page's JS expect back? (feeds the "fake success" answer for spam)"""
    win = js[frm:frm + 1600]
    hints = []
    for m in _RE_HINT_KEYED.finditer(win):
        hints.append({'key': m.group(1), 'op': m.group(2).replace('===', '==').replace('!==', '!='), 'value': m.group(4).strip(' \t\n\x0b\x0c\r\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff')})
    for m in _RE_HINT_PLAIN.finditer(win):
        hints.append({'key': None, 'op': '==', 'value': m.group(3)})
    for m in _RE_HINT_IF.finditer(win):
        hints.append({'key': m.group(2), 'op': 'falsy' if m.group(1) else 'truthy', 'value': None})
    typ = 'unknown'
    if _RE_IS_JSON.search(win) or any(h['key'] for h in hints):
        typ = 'json'
    elif _RE_IS_TEXT.search(win) or any(not h['key'] for h in hints):
        typ = 'text'
    return {'type': typ, 'hints': hints}


_ESC = rx(r'[.*+?^${}()|[\]\\]', 'g')


def esc(s):
    """Escape for use inside a RegExp (same character set as the JS version)."""
    return _ESC.sub(lambda m: '\\' + m.group(), s)


_WS_SPLIT = rx(r'\s+')


def selector_mentions(js, attrs):
    """Places inside `js` where this form is selected by id / class / name."""
    spots = []

    def add(src, flags='g'):
        for m in rx(src, flags).finditer(js):
            spots.append(m.start())

    if attrs.get('id'):
        i = esc(attrs['id'])
        add('[\'"`]#' + i + '[\'"`\\s.:\\[]')
        add('getElementById\\s*\\(\\s*[\'"]' + i + '[\'"]')
        add('forms\\s*\\[\\s*[\'"]' + i + '[\'"]')
    if attrs.get('name'):
        n = esc(attrs['name'])
        add('form\\[name\\s*=\\s*[\'"]?' + n + '[\'"]?\\]|document\\.forms\\.' + n + '\\b')
    for cls in [x for x in _WS_SPLIT.split(attrs.get('class') or '') if x]:
        c = esc(cls)
        add('[\'"`][^\'"`]*\\.' + c + '(?![\\w-])[^\'"`]*[\'"`]')
        add('getElementsByClassName\\s*\\(\\s*[\'"]' + c + '[\'"]')
    return spots


_BIND_1 = rx(r'''\$\(\s*['"]form(?:\[[^\]]*\])?['"]\s*\)\s*\.(?:on\s*\(\s*['"]submit['"]|submit\s*\()''')
_BIND_2 = rx(r'''querySelector(?:All)?\s*\(\s*['"]form(?:\[[^\]]*\])?['"]\s*\)(?:\.forEach\([^)]*)?[\s\S]{0,80}addEventListener\s*\(\s*['"]submit['"]''')
_BIND_3 = rx(r'''document\.forms\s*\[\s*0\s*\]''')


def binds_all_forms(js):
    """Does this script attach a submit handler to every <form> / form[method=post]?"""
    return bool(_BIND_1.search(js)) or bool(_BIND_2.search(js)) or bool(_BIND_3.search(js))


def _calls_of(s):
    c = s.get('_calls')
    if c is None:
        c = s['_calls'] = find_ajax_calls(s['text'])
    return c


def _result(s, c, confidence):
    if s.get('line'):
        line = s['line'] + (line_at(s['text'], c['index']) - 1 if s['kind'] == 'inline' else 0)
    else:
        line = line_at(s['text'], c['index'])
    return {
        'url': c['url'],
        'usesFormAction': c['usesFormAction'],
        'confidence': confidence,
        'file': s['file'],
        'line': line,
        'kind': c['kind'],
        'method': c.get('method') or 'POST',
        'expects': expected_response(s['text'], c['index']),
    }


def link_ajax(form, scripts, general_scripts):
    """Link a form to the AJAX call that submits it.

    scripts: [{file, line, text, kind: 'inline'|'file'}] candidate scripts.
    Returns None or {url, usesFormAction, confidence, file, line, kind, method, expects}.
    """

    def try_scripts(lst, generic):
        for s in lst:
            calls = _calls_of(s)
            if not calls:
                continue
            anchors = ([0] if binds_all_forms(s['text']) else []) if generic else selector_mentions(s['text'], form['attrs'])
            if not anchors:
                continue
            best = None
            for anchor in anchors:
                after = [c for c in calls if c['index'] >= anchor and c['index'] - anchor < 3500]
                cand = after[0] if after else (calls[0] if len(calls) == 1 else None)
                if cand is not None:
                    near = abs(cand['index'] - anchor)
                    if best is None or near < best['near']:
                        best = {'cand': cand, 'near': near}
            if best is None:
                continue
            c = best['cand']
            return _result(s, c, 'medium' if generic else ('high' if best['near'] <= 1500 else 'medium'))
        return None

    # Last resort: the script reads this form's fields by id (e.g. $("input#email")) and makes exactly one POST call.
    def by_fields():
        ids = [i for i in (form.get('fieldIds') or []) if len(i) > 1]
        if len(ids) < 2:
            return None
        for s in scripts:
            calls = _calls_of(s)
            posts = [c for c in calls if (c.get('method') or 'POST') == 'POST']
            if len(posts) != 1:
                continue
            hit = [i for i in ids if rx('#' + esc(i) + '(?![\\w-])').search(s['text']) or rx('getElementById\\s*\\(\\s*[\'"]' + esc(i) + '[\'"]').search(s['text'])]
            if len(hit) < 2:
                continue
            return _result(s, posts[0], 'medium')
        return None

    return try_scripts(scripts, False) or try_scripts(general_scripts, True) or by_fields()
