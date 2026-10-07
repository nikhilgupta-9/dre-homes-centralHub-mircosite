"""Scan one site (port of scanner/index.js). Never executes anything from the site."""
import datetime
import os
import time
import urllib.parse

from . import ajax as _ajax
from .contacts import extract_contacts, finish_contacts, new_contact_acc
from .forms import external_service, parse_html
from .loader import prepare_input
from .php import analyze_php, guess_success_json, js_number, php_generated_forms, split_php
from .plan import plan_form
from .sql import parse_dump
from .util import LIMITS, from16_deep, extname, read_text, resolve_rel, rx, uniq, walk_ex, js_trim

VERSION = '0.2.0'
MARKUP_EXT = {'.html', '.htm', '.shtml', '.php', '.phtml', '.inc'}
PHP_EXT = {'.php', '.phtml', '.inc'}
HTML_EXT = ['.html', '.htm', '.shtml']
NON_PHP_HANDLER = rx(r'\.(asp|aspx|cgi|pl|py|rb|jsp|cfm|html?|shtml)$', 'i')
NOT_A_PAGE_DIR = rx(r'(^|\/)(inc|includes?|lib|libs|classes|class|config|configs|functions|partials|templates?|layouts?|vendor|admin\/inc|src)\/', 'i')
CMS_FORM_PLUGINS = rx(r'^wp-content\/plugins\/(contact-form-7|wpforms(-lite)?|ninja-forms|gravityforms|formidable|forminator|fluentform|everest-forms|weforms|jetpack|elementor|ultimate-addons)')

_P_WP = rx(r'^wp-config(-sample)?\.php$|^wp-content\/|^wp-includes\/')
_P_JOOMLA_A = rx(r'^administrator\/index\.php$')
_P_JOOMLA_B = rx(r'^configuration\.php$')
_P_DRUPAL = rx(r'^core\/lib\/Drupal\.php$|^sites\/default\/')
_P_LARAVEL_A = rx(r'^artisan$')
_P_LARAVEL_B = rx(r'^composer\.json$')
_P_CI = rx(r'^system\/core\/CodeIgniter\.php$')
_P_MAGENTO = rx(r'^app\/Mage\.php$|^app\/etc\/env\.php$')
_P_OPENCART = rx(r'^catalog\/controller\/')


def detect_platform(files):
    def has(pat):
        return any(pat.search(f['rel']) for f in files)

    if has(_P_WP):
        return {'name': 'WordPress', 'cms': True}
    if has(_P_JOOMLA_A) and has(_P_JOOMLA_B):
        return {'name': 'Joomla', 'cms': True}
    if has(_P_DRUPAL):
        return {'name': 'Drupal', 'cms': True}
    if has(_P_LARAVEL_A) and has(_P_LARAVEL_B):
        return {'name': 'Laravel', 'cms': True}
    if has(_P_CI):
        return {'name': 'CodeIgniter', 'cms': True}
    if has(_P_MAGENTO):
        return {'name': 'Magento', 'cms': True}
    if has(_P_OPENCART):
        return {'name': 'OpenCart', 'cms': True}
    if any(f['ext'] in PHP_EXT for f in files):
        return {'name': 'plain PHP', 'cms': False}
    return {'name': 'static HTML', 'cms': False}


EXPOSED = [
    (rx(r'\.sql(\.gz)?$', 'i'), 'database-dump'),
    (rx(r'\.(bak|old|orig|save|swp)$', 'i'), 'backup-copy'),
    (rx(r'(^|\/)\.env(\.[\w-]+)?$', 'i'), 'env-file'),
    (rx(r'\.(zip|tar|tgz|tar\.gz|rar|7z)$', 'i'), 'archive'),
    (rx(r'(^|\/)(phpinfo|info|test|phpmyadmin|adminer)\.php$', 'i'), 'info-script'),
    (rx(r'(^|\/)(error_log|php_errors\.log|debug\.log)$', 'i'), 'log-file'),
    (rx(r'(^|\/)(\.htpasswd|id_rsa|credentials\.json)$', 'i'), 'secret-file'),
]

_HAS_PHP_TAG = rx(r'<\?(?!xml)', 'i')
_SELF_ACTION = rx(r'(\baction\s*=\s*)(["\'])\s*<\?(?:php|=)[^?]*?(?:PHP_SELF|REQUEST_URI|SCRIPT_NAME|__FILE__)[^?]*?\?>\s*\2', 'gi')
_PHP_MARK = rx(r'\{\{PHP\}\}', 'g')
_SCRIPT_STYLE = rx(r'<(script|style)\b[\s\S]*?<\/\1>', 'gi')
_TAG = rx(r'<[^>]*>', 'g')
_WP_SKIP = rx(r'^(wp-admin|wp-includes)\/|^wp-content\/(plugins|uploads|cache|upgrade)\/')
_VENDOR = rx(r'(^|\/)vendor\/')
_SPAMGUARD_DIR = rx(r'(^|\/)spamguard\/')
_LEADING_SLASHES = rx(r'^\/+')
_MAILTO = rx(r'^mailto:', 'i')
_JS_SCHEME = rx(r'^javascript:', 'i')
_ABS_URL = rx(r'^(https?:)?\/\/', 'i')
_QS_REST = rx(r'[?#].*$')
_DIGITS = rx(r'^\d+$')
_BOOL = rx(r'^(true|false)$')
_OKTEXT = rx(r'^(ok|success|sent|1|true|thank.*)$', 'i')
_DOLLAR = rx(r'[$]')
_ENQ_TABLE = rx(r'enquir|inquir|contact|lead|quer|message|submission|request|booking|feedback', 'i')
_SITEMAP = rx(r'^sitemap.*\.xml$', 'i')
_SG_PHP = rx(r'(^|\/)spamguard\/spamguard\.php$')
_SQL_EXT = rx(r'\.sql(\.gz)?$', 'i')
_ID_JUNK = rx(r'[^a-z0-9._-]+', 'g')


def _self_action_repl(m):
    return m.group(1) + m.group(2) + m.group(2) + '\n' * m.group().count('\n')


def normalize_self_action(text):
    """`action="<?php echo $_SERVER['PHP_SELF']; ?>"` is a form posting to itself, not an unknown dynamic action."""
    return _SELF_ACTION.sub(_self_action_repl, text)


def _empty_caps():
    return {
        'readsPost': False, 'sendsMail': False, 'usesDb': False, 'writesFile': False, 'acceptsUpload': False, 'guardCalled': False,
        'mailVia': [], 'mailRecipients': [], 'dbEngines': [], 'insertTables': [], 'verifiesCaptcha': [], 'postFields': [], 'dbNames': [],
        'configFiles': [], 'files': [],
    }


def _merge_caps(into, an, rel):
    for k in ('readsPost', 'sendsMail', 'usesDb', 'writesFile', 'acceptsUpload', 'guardCalled'):
        into[k] = into[k] or an[k]
    into['mailVia'] = uniq(into['mailVia'] + an['mailVia'])
    into['mailRecipients'] = uniq(into['mailRecipients'] + an['mailRecipients'])
    into['dbEngines'] = uniq(into['dbEngines'] + an['dbEngines'])
    into['verifiesCaptcha'] = uniq(into['verifiesCaptcha'] + an['verifiesCaptcha'])
    into['postFields'] = uniq(into['postFields'] + an['postFields'])
    if an['dbName']:
        into['dbNames'] = uniq(into['dbNames'] + [an['dbName']])
    if an['definesDbConnection']:
        into['configFiles'] = uniq(into['configFiles'] + [rel])
    for t in an['insertTables']:
        cur = next((x for x in into['insertTables'] if x['table'] == t['table']), None)
        if cur is None:
            into['insertTables'].append({'table': t['table'], 'columns': list(t['columns'])})
        elif len(t['columns']) > len(cur['columns']):
            cur['columns'] = list(t['columns'])
    into['files'].append(rel)


# --------------------------------------------------------------------------- URL pathname (new URL(s).pathname)

_FORBIDDEN_HOST = set('\x00\t\n\r #/:<>?@[\\]^|%')
_PATH_ENCODE = set(' "#<>?`{}')


def url_pathname(s):
    """Path part of an absolute http(s) URL, like `new URL(s).pathname`. None when the URL is invalid."""
    s = ''.join(ch for ch in s.strip(''.join(chr(i) for i in range(0x21))) if ch not in '\t\n\r')
    low = s.lower()
    if low.startswith('https:'):
        rest = s[6:]
    elif low.startswith('http:'):
        rest = s[5:]
    else:
        return None
    # special schemes accept any mix of / and \ after the scheme
    i = 0
    while i < len(rest) and rest[i] in '/\\':
        i += 1
    rest = rest[i:]
    end = len(rest)
    for j, ch in enumerate(rest):
        if ch in '/\\?#':
            end = j
            break
    authority = rest[:end]
    after = rest[end:]
    if '@' in authority:
        authority = authority[authority.rindex('@') + 1:]
    host = authority
    if host.startswith('['):
        close = host.find(']')
        if close < 0:
            return None
        port = host[close + 1:]
        host = host[:close + 1]
        if port and not (port.startswith(':') and (port[1:] == '' or port[1:].isdigit() and port[1:].isascii() and int(port[1:]) <= 65535)):
            return None
    else:
        if ':' in host:
            host, port = host.split(':', 1)
            if port != '' and not (port.isdigit() and port.isascii() and int(port) <= 65535):
                return None
        if host == '' or any(ch in _FORBIDDEN_HOST or ord(ch) < 0x20 or ord(ch) == 0x7f for ch in host):
            return None
    # path: up to ? or #
    k = len(after)
    for j, ch in enumerate(after):
        if ch in '?#':
            k = j
            break
    path = after[:k].replace('\\', '/')
    out = []
    for ch in path:
        o = ord(ch)
        if o < 0x20 or o > 0x7e or ch in _PATH_ENCODE:
            out.append(urllib.parse.quote(ch.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'replace') if '\ud800' <= ch <= '\udfff' else ch, safe=''))
        else:
            out.append(ch)
    path = ''.join(out)
    # dot segments
    segs = path.split('/')[1:] if path.startswith('/') else path.split('/')
    stack = []
    for n, seg in enumerate(segs):
        sl = seg.lower()
        last = n == len(segs) - 1
        if sl in ('..', '.%2e', '%2e.', '%2e%2e'):
            if stack:
                stack.pop()
            if last:
                stack.append('')
        elif sl in ('.', '%2e'):
            if last:
                stack.append('')
        else:
            stack.append(seg)
    return '/' + '/'.join(stack)


# --------------------------------------------------------------------------- the scan


def _closure(start, graph, max_depth):
    out = {}

    def walk_g(n, d):
        if d > max_depth:
            return
        nxt = graph.get(n)
        if not nxt:
            return
        for x in nxt:
            if x not in out:
                out[x] = True
                walk_g(x, d + 1)

    walk_g(start, 0)
    return out


def _iso_now():
    t = datetime.datetime.now(datetime.timezone.utc)
    return t.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (t.microsecond // 1000)


def _scan_loaded(loaded, sql_files):
    t0 = time.time()
    root = loaded['root']
    warnings = []
    for w in loaded['warnings']:
        d = {'level': 'warn'}
        d.update(w)
        warnings.append(d)
    files, truncated = walk_ex(root)
    if truncated:
        warnings.append({'code': 'files-truncated', 'level': 'warn', 'limit': LIMITS['maxFiles']})
    if loaded['rootRel']:
        warnings.append({'code': 'site-root-inside', 'level': 'info', 'path': loaded['rootRel']})

    by_rel = {f['rel']: f for f in files}
    by_lower = {}
    for f in files:
        by_lower[f['rel'].lower()] = f['rel']  # later duplicates win, like Map.set
    platform = detect_platform(files)

    def exists(rel):
        if rel in by_rel:
            return rel
        return by_lower.get(rel.lower())

    is_wp = platform['name'] == 'WordPress'

    def skip_analysis(rel):
        return bool(_VENDOR.search(rel) or _SPAMGUARD_DIR.search(rel) or (is_wp and _WP_SKIP.search(rel)))

    # ---- pass 1: read every page-like file
    pages = {}
    php_info = {}
    inc_targets = {}
    contact_acc = new_contact_acc()
    all_scripts = []
    raw_includes = []
    analyzed = 0
    for f in files:
        if f['ext'] not in MARKUP_EXT or skip_analysis(f['rel']) or f['size'] > LIMITS['maxTextBytes']:
            continue
        if is_wp:
            analyzed += 1
            if analyzed > 600:
                continue
        text = read_text(os.path.join(root, f['rel']))
        if text is None:
            continue
        has_php_tag = bool(_HAS_PHP_TAG.search(text))
        if has_php_tag:
            sp = split_php(normalize_self_action(text))
        else:
            sp = {'html': text, 'php': '', 'blocks': [], 'hasPhp': False}
        parsed = parse_html(f['rel'], sp['html'])
        gen = php_generated_forms(sp['blocks']) if has_php_tag else []
        extract_contacts(f['rel'], sp['html'], contact_acc)
        if sp['hasPhp']:
            an = analyze_php(sp['php'])
            php_info[f['rel']] = an
            for inc in an['includes']:
                raw_includes.append((f['rel'], inc))
        for s in parsed['scripts']['inline']:
            all_scripts.append({'file': f['rel'], 'line': s['line'], 'text': s['text'], 'kind': 'inline'})
        visible = len(js_trim(_TAG.sub('', _SCRIPT_STYLE.sub('', _PHP_MARK.sub('', sp['html'])))))
        pages[f['rel']] = {'rel': f['rel'], 'parsed': parsed, 'phpGeneratedForms': gen, 'hasPhp': sp['hasPhp'], 'visibleLength': visible}
    for f in files:
        if f['ext'] != '.js' or _ajax.is_library_js(f['rel']) or f['size'] > 300 * 1024 or skip_analysis(f['rel']):
            continue
        text = read_text(os.path.join(root, f['rel']), 300 * 1024)
        if text is not None:
            all_scripts.append({'file': f['rel'], 'line': None, 'text': text, 'kind': 'file'})

    # ---- include graph
    def resolve_include(frm, inc):
        p = inc['path']
        cands = []
        if inc['base'] == 'root':
            cands.append(resolve_rel('', p))
        elif inc['base'] == 'dir':
            cands.append(resolve_rel(frm, _LEADING_SLASHES.sub('', p)))
        else:
            cands.append(resolve_rel(frm, p))
            cands.append(resolve_rel('', p))
        for c in cands:
            if c is None:
                continue
            hit = exists(c)
            if hit:
                return hit
        return None

    rinc = {}
    for frm, inc in raw_includes:
        t = resolve_include(frm, inc)
        if not t:
            continue
        inc_targets.setdefault(frm, []).append(t)
        rinc.setdefault(t, {})[frm] = True

    effective_cache = {}

    def effective(rel):
        if rel in effective_cache:
            return effective_cache[rel]
        caps = _empty_caps()
        direct = php_info.get(rel)
        if direct:
            _merge_caps(caps, direct, rel)
        for t in _closure(rel, inc_targets, 3):
            an = php_info.get(t)
            if an:
                _merge_caps(caps, an, t)
        effective_cache[rel] = caps
        return caps

    def is_page(p):
        if extname(p['rel']).lower() in HTML_EXT:
            return True
        if NOT_A_PAGE_DIR.search(p['rel']) or p['visibleLength'] < 20:
            return False
        sn = p['parsed']['snapshot']
        return bool(sn['hasHtmlShell'] or sn['h1Count'] > 0 or len(p['parsed']['forms']) > 0)

    pages_list = []
    client_script_files = set()
    for p in pages.values():
        if p['parsed']['snapshot']['hasSpamGuardScript']:
            client_script_files.add(p['rel'])

    def has_client(form_rel):
        if form_rel in client_script_files:
            return True
        if any(x in client_script_files for x in _closure(form_rel, rinc, 3)):
            return True
        return any(x in client_script_files for x in _closure(form_rel, inc_targets, 3))

    for p in pages.values():
        if not is_page(p):
            continue
        item = {'file': p['rel'], 'formCount': len(p['parsed']['forms']), 'includes': list(inc_targets.get(p['rel'], []))[:10]}
        item.update(p['parsed']['snapshot'])
        pages_list.append(item)

    # ---- resolve where a form posts to
    def resolve_target(from_rel, raw):
        r = {'raw': raw, 'type': 'none', 'rel': None, 'exists': False, 'service': None, 'note': None}
        s = js_trim(raw or '')
        if raw is None or s == '' or s == '#':
            r['type'] = 'self'
            r['rel'] = from_rel
            r['exists'] = True
            return r
        if _MAILTO.search(s):
            r['type'] = 'mailto'
            return r
        if _JS_SCHEME.search(s):
            r['type'] = 'js'
            return r
        if '{{PHP}}' in s:
            r['type'] = 'dynamic'
            return r
        p = s
        if _ABS_URL.search(s):
            svc = external_service(s)
            if svc:
                r['type'] = 'external'
                r['service'] = svc
                return r
            pn = url_pathname('https:' + s if s.startswith('//') else s)
            if pn is None:
                r['type'] = 'external'
                return r
            p = pn
            r['note'] = 'absolute-url'
            local = exists(resolve_rel('', p) or '')
            if not local:
                r['type'] = 'external'
                r['service'] = None
                return r
        p = _QS_REST.sub('', p)
        if p == '':
            r['type'] = 'self'
            r['rel'] = from_rel
            r['exists'] = True
            return r
        cands = [resolve_rel(from_rel, p), resolve_rel('', p)]
        if p.endswith('/'):
            cands = [None if c is None else (c + '/' if c else '') + 'index.php' for c in cands]
        for c in cands:
            if c is None:
                continue
            hit = exists(c)
            if hit:
                r['type'] = 'local'
                r['rel'] = hit
                r['exists'] = True
                if hit != c:
                    r['note'] = 'case-mismatch'
                return r
        r['type'] = 'local'
        first = next((c for c in cands if c is not None), None)
        r['rel'] = first or p
        r['exists'] = False
        return r

    # ---- pass 2: build the forms
    forms = []
    forms_by_handler = {}
    for p in pages.values():
        using = [x for x in _closure(p['rel'], rinc, 3) if x in pages and is_page(pages[x])]
        ctx_files = {p['rel']: True}
        for x in _closure(p['rel'], rinc, 3):
            ctx_files[x] = True
        for x in list(ctx_files):
            for y in _closure(x, inc_targets, 3):
                ctx_files[y] = True
        general_scripts = [s for s in all_scripts if s['file'] in ctx_files]
        entries = [{'f': f, 'generated': False} for f in p['parsed']['forms']]
        for g in p['phpGeneratedForms']:
            entries.append({'f': None, 'generated': True, 'line': g['line']})
        for entry in entries:
            if entry['generated']:
                rec = {
                    'id': '%s:%s' % (p['rel'], entry['line']), 'file': p['rel'], 'line': entry['line'], 'endLine': None,
                    'label': 'form printed by PHP code', 'kind': 'enquiry', 'protectable': True, 'generatedByPhp': True,
                    'attrs': {}, 'fields': [], 'submitMode': 'classic',
                    'action': {'raw': None, 'type': 'dynamic', 'rel': None, 'exists': False, 'service': None, 'note': None},
                    'ajax': None, 'handler': None,
                    'existing': {'captcha': [], 'csrf': False, 'honeypot': False, 'clientScript': False},
                }
                rec['plan'] = plan_form(rec, {'platform': platform, 'handlerMixedKinds': {}})
                forms.append(rec)
                continue
            f = entry['f']
            protectable = f['kind'] in ('enquiry', 'newsletter', 'callback')
            fa = f['attrs']
            rec = {
                'id': '%s:%s' % (f['file'], f['line']),
                'file': f['file'],
                'line': f['line'],
                'endLine': f['endLine'],
                'label': fa['id'] or fa['name'] or f['submitText'] or 'form',
                'kind': f['kind'],
                'protectable': protectable,
                'generatedByPhp': False,
                'attrs': {'id': fa['id'], 'name': fa['name'], 'class': fa['class'], 'method': fa['method'], 'action': fa['action']},
                'fields': [
                    {'name': x['name'], 'id': x['id'], 'type': x['type'], 'required': x['required']}
                    for x in f['fields'] if x['tag'] != 'button' and x['type'] not in ('submit', 'button', 'image', 'reset')
                ],
                'hasFileUpload': f['hasFileUpload'],
                'submitMode': 'classic',
                'action': None,
                'ajax': None,
                'handler': None,
                'pagesUsing': using,
                'existing': {'captcha': f['captcha'], 'csrf': f['hasCsrf'], 'honeypot': f['hasHoneypot'], 'clientScript': bool(f['hasSgFields'] or has_client(f['file']))},
            }
            rec['action'] = resolve_target(f['file'], fa['action'])
            target = rec['action']
            if protectable and rec['action']['type'] not in ('external', 'mailto'):
                jf = dict(f)
                jf['fieldIds'] = [x['id'] for x in f['fields'] if x['id']]
                aj = _ajax.link_ajax(jf, all_scripts, general_scripts)
                if aj:
                    rec['submitMode'] = 'ajax'
                    rec['ajax'] = {'url': aj['url'], 'usesFormAction': aj['usesFormAction'], 'confidence': aj['confidence'], 'file': aj['file'], 'line': aj['line'], 'kind': aj['kind'], 'expects': aj['expects']}
                    if aj['url'] and not aj['usesFormAction']:
                        target = resolve_target(f['file'], aj['url'])
            if protectable and target['type'] not in ('external', 'mailto'):
                hrel = target['rel'] if target['rel'] and target['exists'] else None
                is_php = bool(hrel) and extname(hrel).lower() in PHP_EXT and not NON_PHP_HANDLER.search(hrel)
                if hrel:
                    caps = effective(hrel)
                    direct = php_info.get(hrel)
                    json_guess = guess_success_json(direct) if direct else None
                    expects = rec['ajax']['expects'] if rec['ajax'] else None
                    success_json = None
                    success_text = None
                    conf = None
                    if rec['submitMode'] == 'ajax':
                        if json_guess:
                            success_json = json_guess['json']
                            conf = 'high'
                        elif expects and any(h.get('key') and h['op'] == '==' and h['value'] for h in expects['hints']):
                            success_json = {}
                            for h in expects['hints']:
                                if h.get('key') and h['op'] == '==' and h['value'] and h['key'] not in success_json:
                                    v = h['value']
                                    success_json[h['key']] = (v == 'true') if _BOOL.search(v) else (js_number(v) if _DIGITS.search(v) else v)
                            conf = 'medium'
                        if not success_json and direct and direct['textResponses']:
                            want = [h['value'].lower() for h in expects['hints'] if not h.get('key')] if expects else []
                            t = next((x for x in direct['textResponses'] if x['text'].lower() in want), None) \
                                or next((x for x in direct['textResponses'] if _OKTEXT.search(x['text'])), None)
                            if t:
                                success_text = t['text']
                                conf = 'high' if t['text'].lower() in want else 'medium'
                    redirect = next((r for r in (direct['redirects'] if direct else []) if r and not _DOLLAR.search(r)), None)
                    rec['handler'] = {
                        'file': hrel,
                        'path': hrel,
                        'exists': True,
                        'isPhp': is_php,
                        'capabilities': {
                            'readsPost': caps['readsPost'], 'sendsMail': caps['sendsMail'], 'mailVia': caps['mailVia'], 'usesDb': caps['usesDb'],
                            'dbEngines': caps['dbEngines'], 'writesFile': caps['writesFile'], 'acceptsUpload': caps['acceptsUpload'],
                            'verifiesCaptcha': caps['verifiesCaptcha'], 'guardCalled': caps['guardCalled'],
                        },
                        'postFields': caps['postFields'],
                        'mailRecipients': caps['mailRecipients'],
                        'tables': caps['insertTables'],
                        'includedFiles': [x for x in caps['files'] if x != hrel],
                        'response': {'successJson': success_json, 'successText': success_text, 'redirect': redirect, 'confidence': conf},
                        'injection': {'firstPhpLine': direct['firstPhpLine'], 'hasDeclareStrict': direct['hasDeclareStrict'], 'hasNamespace': direct['hasNamespace']} if direct else None,
                    }
                    forms_by_handler.setdefault(hrel, []).append(rec)
                else:
                    rec['handler'] = {'file': target['rel'], 'path': target['rel'] or target['raw'], 'exists': False, 'isPhp': False}
            forms.append(rec)

    # one handler shared by an enquiry form AND something else (login etc.) => a person should look
    handler_mixed = {}
    for h in forms_by_handler:
        same = pages.get(h)
        if same and len(same['parsed']['forms']) > 1:
            kinds = set('e' if x['kind'] in ('enquiry', 'newsletter', 'callback') else x['kind'] for x in same['parsed']['forms'])
            if len(kinds) > 1:
                handler_mixed[h] = True
    for rec in forms:
        if 'plan' not in rec:
            rec['plan'] = plan_form(rec, {'platform': platform, 'handlerMixedKinds': handler_mixed})

    # ---- database + SQL dumps
    dumps = []
    dump_files = [{'rel': f['rel'], 'abs': os.path.join(root, f['rel']), 'size': f['size']} for f in files if _SQL_EXT.search(f['rel']) and f['size'] < 2 * 1024 * 1024 * 1024][:6]
    for x in sql_files or []:
        try:
            st = os.stat(x)
            dump_files.append({'rel': os.path.basename(x), 'abs': os.path.abspath(x), 'size': st.st_size, 'external': True})
        except OSError:
            warnings.append({'code': 'sql-file-missing', 'level': 'warn', 'path': x})
    for d in dump_files:
        try:
            res = parse_dump(d['abs'])
            dumps.append({'file': d['rel'], 'sizeBytes': d['size'], 'external': bool(d.get('external')), 'tables': res['tables']})
        except OSError as e:
            msg = e.args[0] if e.args and isinstance(e.args[0], str) else str(e)
            warnings.append({'code': 'sql-unreadable', 'level': 'warn', 'path': d['rel'], 'message': msg})

    all_caps = _empty_caps()
    for rel, an in php_info.items():
        _merge_caps(all_caps, an, rel)

    def dump_table(name):
        for d in dumps:
            t = next((x for x in d['tables'] if x['name'].lower() == name.lower()), None)
            if t:
                return {'dump': d['file'], 'table': t}
        return None

    for rec in forms:
        h = rec['handler']
        if h and h['exists']:
            new_tables = []
            for t in h['tables']:
                hit = dump_table(t['table'])
                nt = dict(t)
                if hit:
                    nt['inDump'] = hit['dump']
                    nt['dumpColumns'] = [c['name'] for c in hit['table']['columns']]
                    nt['insertStatements'] = hit['table']['insertStatements']
                else:
                    nt['inDump'] = None
                new_tables.append(nt)
            h['tables'] = new_tables

    enquiry_tables = []
    seen_t = set()
    for d in dumps:
        for t in d['tables']:
            if t['looksLikeEnquiries'] and t['name'] not in seen_t:
                seen_t.add(t['name'])
                handlers = uniq([r['handler']['file'] for r in forms if r['handler'] and r['handler']['exists'] and any(x['table'].lower() == t['name'].lower() for x in r['handler']['tables'])])
                enquiry_tables.append({
                    'name': t['name'], 'source': 'dump', 'dump': d['file'], 'columns': [c['name'] for c in t['columns']],
                    'insertStatements': t['insertStatements'], 'hasStatusColumn': t['hasStatusColumn'], 'hasDateColumn': t['hasDateColumn'],
                    'handlers': handlers,
                })
    for rec in forms:
        h = rec['handler']
        if not h or not h['exists']:
            continue
        for t in h['tables']:
            if t['table'] not in seen_t and _ENQ_TABLE.search(t['table']):
                seen_t.add(t['table'])
                enquiry_tables.append({'name': t['table'], 'source': 'handler-code', 'columns': t['columns'], 'insertStatements': None, 'handlers': [h['file']]})

    database = {
        'used': bool(all_caps['usesDb'] or len(dumps) > 0),
        'engines': all_caps['dbEngines'],
        'configFiles': all_caps['configFiles'],
        'databaseNames': all_caps['dbNames'],
        'sqlDumps': [{
            'file': d['file'], 'sizeBytes': d['sizeBytes'], 'tableCount': len(d['tables']),
            'tables': [{'name': t['name'], 'columns': len(t['columns']), 'rows': 'has-data' if t['insertStatements'] > 0 else 'empty', 'looksLikeEnquiries': t['looksLikeEnquiries']} for t in d['tables']],
        } for d in dumps],
        'enquiryTables': enquiry_tables,
        'note': 'Passwords and row data are never read or stored.',
    }

    # ---- misc: security quick-look, SEO files, CMS forms
    exposed_files = []
    for f in files:
        for pat, kind in EXPOSED:
            if pat.search(f['rel']):
                if kind == 'archive' and f['size'] < 1024:
                    break
                exposed_files.append({'file': f['rel'], 'kind': kind, 'sizeBytes': f['size']})
                break
    if os.path.exists(os.path.join(root, '.git')):
        exposed_files.append({'file': '.git/', 'kind': 'git-folder', 'sizeBytes': 0})
    cms_forms = []
    if platform['cms']:
        for f in files:
            m = CMS_FORM_PLUGINS.search(f['rel'])
            if m and m.group(1):
                cms_forms.append(m.group(1))
        cms_forms = uniq(cms_forms)
    site_files = {
        'robotsTxt': 'robots.txt' in by_rel,
        'sitemapXml': 'sitemap.xml' in by_rel or any(_SITEMAP.search(f['rel']) for f in files),
        'htaccess': '.htaccess' in by_rel,
        'spamguardInstalled': any(_SG_PHP.search(f['rel']) for f in files),
    }

    # ---- summary
    def count(s):
        return len([f for f in forms if f['plan']['status'] == s])

    protectable_forms = [f for f in forms if f['protectable']]
    summary = {
        'forms': len(forms),
        'enquiryForms': len(protectable_forms),
        'auto': count('auto'),
        'review': count('review'),
        'manual': count('manual'),
        'skip': count('skip'),
        'done': count('done'),
        'ajaxForms': len([f for f in forms if f['submitMode'] == 'ajax']),
        'pages': len(pages_list),
        'exposedFiles': len(exposed_files),
    }
    if not pages_list and not forms:
        warnings.append({'code': 'no-pages', 'level': 'warn'})
    mail_guess = uniq([m for f in forms if f['handler'] and f['handler']['exists'] for m in f['handler']['mailRecipients']])
    site_actions = []
    if summary['auto'] + summary['review'] > 0:
        site_actions.append({'type': 'install-kit', 'to': 'spamguard/', 'alreadyThere': site_files['spamguardInstalled']})
        site_actions.append({'type': 'write-config', 'siteId': _ID_JUNK.sub('-', loaded['name'].lower()), 'notifyEmailGuess': mail_guess[0] if mail_guess else None})
    return {
        'scanner': {'version': VERSION, 'scannedAt': _iso_now(), 'durationMs': int((time.time() - t0) * 1000)},
        'site': {
            'name': loaded['name'],
            'source': loaded['source'],
            'platform': platform['name'],
            'cms': platform['cms'],
            'cmsFormPlugins': cms_forms,
            'files': len(files),
            'sizeBytes': sum(f['size'] for f in files),
            'phpFiles': len([f for f in files if f['ext'] in PHP_EXT]),
            'htmlFiles': len([f for f in files if f['ext'] in HTML_EXT]),
            'jsFiles': len([f for f in files if f['ext'] == '.js']),
            'siteFiles': site_files,
        },
        'summary': summary,
        'database': database,
        'forms': forms,
        'pages': pages_list,
        'contacts': finish_contacts(contact_acc),
        'security': {'exposedFiles': exposed_files},
        'plan': {'siteActions': site_actions},
        'warnings': warnings,
    }


def scan_site(input_path, sql_files=None):
    """Scan one site: a folder or a .zip. Never executes anything from the site.

    Returns the report dict (camelCase keys, same structure as the Node version).
    """
    loaded = prepare_input(input_path)
    try:
        report = _scan_loaded(loaded, sql_files)
    finally:
        loaded.cleanup()
    return from16_deep(report)
