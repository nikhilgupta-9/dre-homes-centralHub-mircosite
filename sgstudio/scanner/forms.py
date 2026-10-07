"""Find forms, scripts and a light SEO snapshot in one (PHP-masked) HTML view. Port of forms.js."""
from .htmlparse import Element, parse_document, serialize_outer, text_content, walk_elements
from .util import js_trim, rx, uniq

CAPTCHA_HINTS = [
    (rx(r'google\.com\/recaptcha|g-recaptcha', 'i'), 'recaptcha'),
    (rx(r'hcaptcha\.com|h-captcha', 'i'), 'hcaptcha'),
    (rx(r'challenges\.cloudflare\.com\/turnstile|cf-turnstile', 'i'), 'turnstile'),
]

# Third-party form services: the data never touches our PHP, so server-side protection is impossible.
EXTERNAL_SERVICES = [
    (rx(r'formspree\.io', 'i'), 'Formspree'),
    (rx(r'docs\.google\.com\/forms|forms\.gle', 'i'), 'Google Forms'),
    (rx(r'formsubmit\.co', 'i'), 'FormSubmit'),
    (rx(r'getform\.io', 'i'), 'Getform'),
    (rx(r'web3forms\.com', 'i'), 'Web3Forms'),
    (rx(r'list-manage\.com|mailchimp', 'i'), 'Mailchimp'),
    (rx(r'hsforms\.com|hubspot', 'i'), 'HubSpot'),
    (rx(r'hooks\.zapier\.com', 'i'), 'Zapier'),
    (rx(r'formcarry\.com', 'i'), 'Formcarry'),
    (rx(r'usebasin\.com', 'i'), 'Basin'),
    (rx(r'sendinblue|brevo', 'i'), 'Brevo'),
    (rx(r'typeform\.com', 'i'), 'Typeform'),
    (rx(r'wufoo\.com', 'i'), 'Wufoo'),
    (rx(r'jotform\.com', 'i'), 'JotForm'),
    (rx(r'convertkit\.com', 'i'), 'ConvertKit'),
    (rx(r'zoho\.(com|in)', 'i'), 'Zoho'),
    (rx(r'pabbly\.com|make\.com|integromat', 'i'), 'automation webhook'),
]

_PHP_MARK = rx(r'\{\{PHP\}\}')
_WS_RUN = rx(r'\s+')
_CSRF = rx(r'csrf|_token|nonce|authenticity', 'i')
_HONEY = rx(r'honey|trap|hp_?field|bot_?field', 'i')
_SG_FIELD = rx(r'^sg_')
_SG_SCRIPT = rx(r'spamguard\.js', 'i')
_HTML_TAG = rx(r'<html\b', 'i')
_MAIL = rx(r'mail')
_PHONE = rx(r'phone|mobile|\btel\b|whatsapp|contact_?(no|num)')
_SEARCH_ACT = rx(r'search')
_SEARCH_NAME = rx(r'^(q|s|search|query|keyword|keywords)$')


def detect_captcha(s):
    return [name for (pat, name) in CAPTCHA_HINTS if pat.search(s)]


def external_service(url):
    for pat, name in EXTERNAL_SERVICES:
        if pat.search(url):
            return name
    return None


def clean(s):
    """Collapse whitespace, drop {{PHP}} markers (JS: String(s||'').replace(...).replace(/\\s+/g,' ').trim())."""
    s = s or ''
    s = _PHP_MARK.sub('', s)
    s = _WS_RUN.sub(' ', s)
    return js_trim(s)


def classify_form(f):
    """Decide what a form is for. Only enquiry-like forms get protected."""
    types = [x['type'] for x in f['fields']]
    names = [(x.get('name') or '').lower() for x in f['fields']]
    if 'password' in types:
        return 'login'
    vis = f['visibleFields']
    has_email = 'email' in types or any(_MAIL.search(n) for n in names)
    has_phone = 'tel' in types or any(_PHONE.search(n) for n in names)
    has_text = any(x['tag'] == 'textarea' for x in f['fields'])
    act = (f['attrs'].get('action') or '').lower()
    method = f['attrs'].get('method') or 'get'
    if 'search' in types or _SEARCH_ACT.search(act) or (len(vis) <= 2 and any(_SEARCH_NAME.search(n) for n in names) and method == 'get'):
        return 'search'
    if has_email or has_phone or has_text:
        if len(vis) == 1 and has_email and not has_text:
            return 'newsletter'
        if len(vis) == 1 and has_phone and not has_text:
            return 'callback'
        return 'enquiry'
    return 'other'


def _attr(el, name):
    return el.attrs.get(name)


def _is_submit_candidate(el):
    if el.name == 'button':
        t = el.attrs.get('type')
        return t is None or t.lower() == 'submit'
    if el.name == 'input':
        t = el.attrs.get('type')
        return t is not None and t.lower() == 'submit'
    return False


def _meta(metas, n):
    for m in metas:
        if (m.attrs.get('name') or '').lower() == n or (m.attrs.get('property') or '').lower() == n:
            return clean(m.attrs.get('content'))
    return ''


def parse_html(rel, html):
    """Parse one (PHP-masked) HTML view.

    Returns {'forms': [...], 'scripts': {'inline': [...], 'src': [...]}, 'snapshot': {...}}.
    """
    doc = parse_document(html)
    els = list(walk_elements(doc))
    page_captcha = detect_captcha(html)
    has_sg_script = bool(_SG_SCRIPT.search(html))
    forms = []

    for el in els:
        if el.name != 'form':
            continue
        attrs = {
            'id': _attr(el, 'id') or '',
            'name': _attr(el, 'name') or '',
            'class': _attr(el, 'class') or '',
            'action': _attr(el, 'action'),
            'method': (_attr(el, 'method') or 'get').lower(),
            'enctype': (_attr(el, 'enctype') or '').lower(),
            'onsubmit': _attr(el, 'onsubmit') or '',
        }
        fields = []
        sub = [d for d in walk_elements(el)]
        for fe in sub:
            t = fe.name
            if t not in ('input', 'textarea', 'select', 'button'):
                continue
            if t == 'input':
                typ = (fe.attrs.get('type') or 'text').lower()
            elif t == 'button':
                typ = (fe.attrs.get('type') or 'submit').lower()
            else:
                typ = t
            fields.append({
                'tag': t,
                'type': typ,
                'name': fe.attrs.get('name') or '',
                'id': fe.attrs.get('id') or '',
                'required': 'required' in fe.attrs,
                'placeholder': clean(fe.attrs.get('placeholder')),
            })
        visible = [x for x in fields if x['name'] and x['tag'] != 'button' and x['type'] not in ('hidden', 'submit', 'button', 'image', 'reset')]
        submit = None
        for d in sub:
            if _is_submit_candidate(d):
                submit = d
                break
        if submit is None:
            submit_text = ''
        elif submit.name == 'input':
            submit_text = clean(submit.attrs.get('value'))[:40]
        else:
            submit_text = clean(text_content(submit))[:40]
        inner = serialize_outer(el)
        form = {
            'file': rel,
            'line': el.start_line or None,
            'endLine': el.end_line or None,
            'attrs': attrs,
            'fields': fields,
            'visibleFields': [x['name'] for x in visible],
            'submitText': submit_text,
            'captcha': uniq(detect_captcha(inner) + (page_captcha if (len(forms) == 0 and page_captcha) else [])),
            'hasCsrf': any(x['type'] == 'hidden' and _CSRF.search(x['name']) for x in fields),
            'hasHoneypot': any(_HONEY.search(x['name']) for x in fields),
            'hasSgFields': any(_SG_FIELD.search(x['name']) for x in fields),
            'hasFileUpload': any(x['type'] == 'file' for x in fields) or attrs['enctype'] == 'multipart/form-data',
            'dynamicAction': isinstance(attrs['action'], str) and '{{PHP}}' in attrs['action'],
        }
        form['kind'] = classify_form(form)
        forms.append(form)

    # scripts (inline text and src): used to find AJAX submissions
    inline = []
    src = []
    for el in els:
        if el.name != 'script':
            continue
        s = _attr(el, 'src')
        if s:
            src.append(s)
        else:
            text = text_content(el)
            if text and js_trim(text):
                inline.append({'line': el.start_line or None, 'text': text})

    # light SEO / mobile snapshot
    metas = [e for e in els if e.name == 'meta']
    titles = [e for e in els if e.name == 'title']
    title_raw = text_content(titles[0]) if titles else ''
    h1s = [e for e in els if e.name == 'h1']
    imgs = [e for e in els if e.name == 'img']
    body_text = clean(''.join(text_content(e) for e in els if e.name == 'body') or '')
    canon = None
    for e in els:
        if e.name == 'link' and (e.attrs.get('rel') is not None) and e.attrs['rel'].lower() == 'canonical':
            canon = e
            break
    html_el = None
    for e in els:
        if e.name == 'html':
            html_el = e
            break
    snapshot = {
        'title': '' if '{{PHP}}' in title_raw else clean(title_raw),
        'titleDynamic': '{{PHP}}' in title_raw,
        'hasTitleTag': len(titles) > 0,
        'metaDescription': _meta(metas, 'description'),
        'h1Count': len(h1s),
        'h1': clean(text_content(h1s[0])) if h1s else '',
        'canonical': clean(canon.attrs.get('href')) if canon is not None else '',
        'robotsMeta': _meta(metas, 'robots'),
        'lang': clean(html_el.attrs.get('lang')) if html_el is not None else '',
        'viewport': _meta(metas, 'viewport'),
        'ogTitle': _meta(metas, 'og:title'),
        'images': {'total': len(imgs), 'missingAlt': len([e for e in imgs if 'alt' not in e.attrs])},
        'hasJsonLd': any(e.name == 'script' and (e.attrs.get('type') or '').lower() == 'application/ld+json' and 'type' in e.attrs for e in els),
        'wordCount': len(body_text.split(' ')) if body_text else 0,
        'hasHtmlShell': html_el is not None and bool(_HTML_TAG.search(html)),
        'hasSpamGuardScript': has_sg_script,
    }
    return {'forms': forms, 'scripts': {'inline': inline, 'src': src}, 'snapshot': snapshot}
