"""Plain-language (Hinglish) report for non-technical users (port of report.js).

The JSON report stays the source of truth; render_text() only formats it.
"""
import json

STATUS = {
    'auto': 'AUTO   - apne aap protect ho jayega',
    'review': 'REVIEW - ek baar dekhna padega',
    'manual': 'MANUAL - haath se karna padega',
    'skip': 'SKIP   - enquiry form nahi hai',
    'done': 'DONE   - pehle se protected hai',
}

KIND = {'login': 'login', 'search': 'search', 'other': 'koi aur', 'newsletter': 'newsletter', 'callback': 'call-back', 'enquiry': 'enquiry'}


def _kind(k):
    return KIND.get(k) or k


REASON = {
    'not-enquiry': lambda r: 'Ye %s form hai, enquiry form nahi, isliye chhod diya.' % _kind(r['kind']),
    'cms': lambda r: '%s site hai. Yahan forms plugin/theme se bante hain, tool se sahi protect nahi honge.' % r['cms'],
    'php-generated': lambda r: 'Form PHP code ke andar echo se ban raha hai. Tool ise safe tarah edit nahi kar sakta.',
    'external-service': lambda r: 'Form ka data %s ko jata hai, aapke server par aata hi nahi. Server-side protection mumkin nahi.' % r['service'],
    'mailto-form': lambda r: 'Form "mailto:" use karta hai (user ka email app khulta hai). Isse spam rok nahi sakte, PHP handler banana padega.',
    'dynamic-action': lambda r: 'Form ka action PHP se banta hai, pata nahi chal raha ki data kahan jata hai.',
    'js-action': lambda r: 'Form javascript: se submit hota hai aur handler nahi mila.',
    'handler-missing': lambda r: 'Form jis file par data bhejta hai (%s) wo zip/folder mein nahi mili.' % (r.get('path') or '?'),
    'handler-not-php': lambda r: 'Handler (%s) PHP file nahi hai.' % r['path'],
    'handler-no-post': lambda r: '%s mein form ka data padhne ka code nahi dikha (shayad kisi aur file mein hai).' % r['file'],
    'ajax-link-uncertain': lambda r: 'Form AJAX se submit hota hai, par JS aur form ka jod pakka nahi hua.',
    'ajax-response-unknown': lambda r: 'AJAX form hai, par handler ka "success" jawab samajh nahi aaya. Spam par nakli success kaisa bhejna hai ye dekhna padega.',
    'ajax-response-found': lambda r: 'AJAX form hai, handler ka success jawab mil gaya%s.' % (' (JSON)' if r.get('json') else ' (text)'),
    'shared-handler-multiple-forms': lambda r: '%s par ek se zyada tarah ke forms hain (jaise login + enquiry), dhyan se lagana padega.' % r['file'],
    'existing-captcha': lambda r: 'Pehle se %s laga hai. Ye extra layer rahegi.' % ', '.join(r['types']),
    'file-upload': lambda r: 'Form mein file upload bhi hai.',
    'form-in-include': lambda r: 'Ye form shared file mein hai, %s page(s) par dikhta hai.' % r['pages'],
    'self-post': lambda r: 'Form usi page par submit hota hai.',
    'already-protected': lambda r: 'SpamGuard pehle se laga hai.',
    'client-script-missing': lambda r: 'Server side guard laga hai, par page par script tag nahi hai.',
    'guard-missing': lambda r: 'Page par script hai, par handler mein guard nahi hai.',
}

EXPOSED = {
    'database-dump': 'Database ka backup (.sql) site folder mein pada hai. Server par public ho to koi bhi download kar sakta hai. Hata do.',
    'backup-copy': 'Purani/backup copy ki file hai (.bak/.old). Code ya password leak kar sakti hai. Hata do.',
    'env-file': '.env file hai, isme secret keys hoti hain. Public nahi honi chahiye.',
    'archive': 'Zip/archive file site folder mein hai. Hata do.',
    'info-script': 'phpinfo/test/adminer jaisi file hai, hackers ke kaam aati hai. Hata do.',
    'log-file': 'Error log file hai, andar server ke raaz ho sakte hain.',
    'secret-file': 'Secret/password file mili. Turant hata do.',
    'git-folder': '.git folder hai, poora source code bahar nikal sakta hai.',
}

WARN = {
    'no-pages': lambda w: 'Koi page ya form nahi mila. Shayad galat folder diya hai?',
    'files-truncated': lambda w: 'Bahut zyada files hain, sirf pehli %s scan hui.' % w['limit'],
    'site-root-inside': lambda w: 'Site ka asli folder "%s" ke andar mila, wahin se scan kiya.' % w['path'],
    'zip-unsafe-path': lambda w: 'ZIP mein khatarnak path wali file thi, use chhod diya (%s).' % w['file'],
    'zip-symlink-skipped': lambda w: 'ZIP mein shortcut (symlink) thi, chhod di (%s).' % w['file'],
    'zip-file-too-large': lambda w: 'Bahut badi file chhod di (%s).' % w['file'],
    'zip-entry-unreadable': lambda w: 'ZIP ki ek file padh nahi paye (%s).' % w['file'],
    'sql-file-missing': lambda w: 'SQL file nahi mili: %s' % w['path'],
    'sql-unreadable': lambda w: 'SQL dump padh nahi paye (%s).' % w['path'],
}


def _plural(n, one, many):
    return '%s %s' % (n, one if n == 1 else many)


def _len16(s):
    return len(s.encode('utf-16-le', 'surrogatepass')) // 2


def _json(v):
    """JSON.stringify (compact)."""
    return json.dumps(v, separators=(',', ':'), ensure_ascii=False)


def _handler_line(h):
    parts = []
    caps = h['capabilities']
    if caps['sendsMail']:
        parts.append('mail bhejta hai (%s)' % ', '.join(caps['mailVia']))
    if caps['usesDb']:
        t = [x['table'] for x in h['tables']]
        parts.append('database mein save karta hai' + (' (table: %s)' % ', '.join(t) if t else ''))
    if caps['writesFile']:
        parts.append('file mein likhta hai')
    if not parts:
        parts.append('koi mail/database ka code nahi dikha')
    return ', '.join(parts)


def _action_line(a):
    t = a['type']
    if t == 'add-script-tag':
        return 'page par script tag lagegi (%s)' % a['file']
    if t == 'add-guard-call':
        return '%s ke top par guard line lagegi' % a['file']
    if t == 'set-success-response':
        if a.get('json'):
            return 'spam par bot ko ye nakli success jayega: %s' % _json(a['json'])
        if a.get('text'):
            return 'spam par bot ko ye nakli success jayega: "%s"' % a['text']
        if a.get('redirect'):
            return 'spam par bot "%s" par bheja jayega' % a['redirect']
    return t


def render_text(r):
    L = []
    bar = '=' * 64
    s = r['summary']
    L.append(bar)
    L.append('SITE: %s   (%s, %s)' % (r['site']['name'], r['site']['source'], r['site']['platform']))
    L.append('Files: %s  (PHP %s, HTML %s, JS %s)' % (r['site']['files'], r['site']['phpFiles'], r['site']['htmlFiles'], r['site']['jsFiles']))
    L.append(bar)
    L.append('Kul forms: %s   |   protect ho sakte hain: %s' % (s['forms'], s['enquiryForms']))
    L.append('AUTO %s  |  REVIEW %s  |  MANUAL %s  |  SKIP %s  |  DONE %s' % (s['auto'], s['review'], s['manual'], s['skip'], s['done']))
    L.append('')

    d = r['database']
    if d['used']:
        L.append('DATABASE: haan' + (' (' + ', '.join(d['engines']) + ')' if d['engines'] else ''))
        if d['configFiles']:
            L.append('  Connection file: ' + ', '.join(d['configFiles']))
        for dump in d['sqlDumps']:
            L.append('  SQL dump: %s (%s)' % (dump['file'], _plural(dump['tableCount'], 'table', 'tables')))
        for t in d['enquiryTables']:
            L.append('  Enquiry table: %s  [%s%s]' % (t['name'], ', '.join(t['columns'][:8]), ', ...' if len(t['columns']) > 8 else '')
                     + ('  <- ' + ', '.join(t['handlers']) if t['handlers'] else ''))
    else:
        L.append('DATABASE: nahi mila (is site mein enquiry mail ya file se jaati hai). SpamGuard apna chhota SQLite use karega.')
    L.append('')

    if r['forms']:
        L.append('FORMS:')
        for i, f in enumerate(r['forms']):
            L.append(' %d. %s:%s  [%s]  "%s"' % (i + 1, f['file'], f.get('line') or '?', _kind(f['kind']), f['label']))
            if f.get('fields'):
                names = [x.get('name') or x.get('id') or '(naam nahi)' for x in f['fields'] if x.get('type') != 'hidden']
                L.append('    fields: %s' % (', '.join(names) or '-'))
            h = f.get('handler')
            if h and h.get('exists'):
                L.append('    bhejta hai: %s  (%s)' % (h['file'], 'AJAX' if f['submitMode'] == 'ajax' else 'normal submit'))
                L.append('    handler: %s' % _handler_line(h))
            L.append('    %s' % STATUS[f['plan']['status']])
            for reason in f['plan']['reasons']:
                fn = REASON.get(reason['code'])
                if fn and reason['code'] != 'already-protected':
                    L.append('      - %s' % fn(reason))
            if f['plan']['status'] in ('auto', 'review'):
                for a in f['plan']['actions']:
                    L.append('      > %s' % _action_line(a))
        L.append('')

    notes = []
    for e in r['security']['exposedFiles']:
        notes.append('%s: %s' % (e['file'], EXPOSED.get(e['kind']) or e['kind']))
    c = r['contacts']
    if c['phones'] or c['emails']:
        notes.append('Contact details mile: %s, %s (hub se ek jagah se badal sakte honge).' % (_plural(len(c['phones']), 'phone number', 'phone numbers'), _plural(len(c['emails']), 'email', 'emails')))
    pg = r['pages']
    if pg:
        no_desc = len([p for p in pg if not p['metaDescription'] and not p['titleDynamic']])
        no_title = len([p for p in pg if not p['title'] and not p['titleDynamic']])
        no_vp = len([p for p in pg if not p['viewport'] and p['hasHtmlShell']])
        if no_title:
            notes.append('%s mein title nahi hai (SEO ke liye zaroori).' % _plural(no_title, 'page', 'pages'))
        if no_desc:
            notes.append('%s mein meta description nahi hai.' % _plural(no_desc, 'page', 'pages'))
        if no_vp:
            notes.append('%s mein mobile viewport tag nahi hai (mobile par kharab dikh sakta hai).' % _plural(no_vp, 'page', 'pages'))
    if not r['site']['siteFiles']['robotsTxt']:
        notes.append('robots.txt nahi hai.')
    if not r['site']['siteFiles']['sitemapXml']:
        notes.append('sitemap.xml nahi hai (Google ko pages dhoondhne mein dikkat).')
    for w in r['warnings']:
        fn = WARN.get(w['code'])
        notes.append(fn(w) if fn else w['code'])
    if notes:
        L.append('DHYAN DENE WALI BAATEIN:')
        for n in notes:
            L.append(' * %s' % n)
        L.append('')
    L.append('Note: %s Scan mein site ka koi code chalaya nahi gaya.' % r['database']['note'])
    return '\n'.join(L) + '\n'


def _pad(s, n):
    s = str(s)
    ln = _len16(s)
    if ln > n:
        # slice(0, n-1) works on UTF-16 units
        u = s.encode('utf-16-le', 'surrogatepass')[:(n - 1) * 2]
        return u.decode('utf-16-le', 'surrogatepass') + '~'
    return s + ' ' * (n - ln)


def render_bulk_text(b):
    L = []
    t = b['totals']
    L.append('=' * 72)
    L.append('BULK SCAN: %s sites  |  scan ho gayi: %s  |  fail: %s' % (t['sites'], t['ok'], t['failed']))
    L.append('=' * 72)
    L.append('Kul forms: %s  |  AUTO %s  |  REVIEW %s  |  MANUAL %s  |  DONE %s' % (t['forms'], t['auto'], t['review'], t['manual'], t['done']))
    L.append('Sites jisme database hai: %s   |   jisme exposed (khatarnak) files hain: %s' % (t['withDb'], t['withExposed']))
    L.append('')
    L.append('%s %s %s %s %s %s NOTE' % (_pad('SITE', 28), _pad('PLATFORM', 12), _pad('FORMS', 6), _pad('AUTO', 5), _pad('REVW', 5), _pad('MANL', 5)))
    for row in b['rows']:
        if row['status'] == 'failed':
            L.append('%s %s %s %s %s %s FAIL: %s' % (_pad(row['name'], 28), _pad('-', 12), _pad('-', 6), _pad('-', 5), _pad('-', 5), _pad('-', 5), row['error']))
            continue
        note = ', '.join([x for x in [
            'DB' if row['db'] == 'yes' else None,
            '%s exposed' % row['exposedFiles'] if row['exposedFiles'] else None,
            'no enquiry form' if row['enquiryForms'] == 0 else None] if x])
        L.append('%s %s %s %s %s %s %s' % (_pad(row['name'], 28), _pad(row['platform'], 12), _pad(row['enquiryForms'], 6), _pad(row['auto'], 5), _pad(row['review'], 5), _pad(row['manual'], 5), note))
    L.append('')
    L.append('FORMS = protect ho sakne wale (enquiry) forms. Har site ki poori report reports/ folder mein hai.')
    return '\n'.join(L) + '\n'
