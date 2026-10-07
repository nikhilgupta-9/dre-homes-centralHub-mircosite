"""Plain-language (Hinglish) reports for the injector (port of src/injector/report.js)."""
from sgstudio.scanner.report import REASON, KIND

STATUS_LINE = {
    'protected': 'PROTECTED - sabhi enquiry forms protect ho gaye.',
    'partial': 'PARTIAL - kuch forms protect hue, kuch ko haath se ya review ke baad karna hai (neeche list hai).',
    'manual-only': 'KUCH NAHI BADLA - jo forms mile unhe tool apne aap safe tarah protect nahi kar sakta (neeche wajah likhi hai).',
    'nothing-to-do': 'KUCH NAHI BADLA - protect karne layak koi form nahi mila.',
    'no-forms': 'KUCH NAHI BADLA - is site mein enquiry form hi nahi mila.',
    'already-protected': 'PEHLE SE PROTECTED - SpamGuard pehle se laga hua hai.',
    'failed': 'FAIL - is site par kaam nahi ho paya.',
}

OUTCOME = {
    'protected': 'PROTECTED',
    'already-protected': 'PEHLE SE PROTECTED',
    'needs-review': 'REVIEW BAAKI (tool ne chhoda)',
    'manual': 'MANUAL BAAKI',
    'failed': 'FAIL',
    'skipped': 'SKIP (enquiry form nahi)',
}

ERR = {
    'php-not-at-top': 'handler file ke upar HTML hai, PHP baad mein shuru hota hai (guard sahi jagah nahi laga sakte)',
    'short-open-tag': 'handler "<?" jaisa short tag use karta hai',
    'bracketed-namespace': 'handler mein namespace { } hai',
    'no-php': 'handler mein PHP code hi nahi mila',
    'script-position-unsafe': 'script tag lagane ki surakshit jagah nahi mili',
    'php-syntax-check-failed': 'badlav ke baad PHP syntax check fail hua, file wapas original kar di',
    'verification-failed': 'badlav ke baad dobara scan mein form protected nahi dikha',
}

WAHAN = [
    'ZIP ko khol kar uske andar ki saari files apni site ke folder (public_html) mein upload karo. Purani files overwrite hone do.',
    'Browser mein selftest kholo (link PRIVATE-login.txt mein hai). Sab kuch hara (PASS) dikhna chahiye. Phir server se selftest.php delete kar do.',
    'Site par ek test enquiry bhejo. Fir /spamguard/spam-admin.php kholo, wahan wo "Real" mein dikhni chahiye.',
    'Kuch galat lage to backup ZIP wapas upload kar do, site pehle jaisi ho jayegi.',
]


def _manual_how_to(f):
    if not f.get('handler'):
        return None
    return ("Haath se karna ho to: (1) page %s mein </body> se pehle <script src=\"/spamguard/spamguard.js\" defer></script> lagao. "
            "(2) %s ke bilkul upar <?php ke baad: require_once __DIR__ . '/spamguard/spamguard.php'; SpamGuard::guard();  (path folder ke hisaab se ../ badlo)"
            % (f['file'], f['handler']))


def render_protect_text(r):
    L = []
    bar = '=' * 64
    L.extend([bar, 'SITE: %s   (%s, %s)' % (r['site']['name'], r['site']['source'], r['site'].get('platform') or 'plain PHP'), bar])
    L.append(STATUS_LINE.get(r['status'], r['status']))
    if r.get('options') and r['options'].get('dryRun'):
        L.append('(DRY RUN: sirf dikhaya gaya, koi file nahi likhi gayi)')
    L.append('')
    s = r.get('summary')
    if s:
        L.append('Enquiry forms: %d   |   Protected: %d   |   Pehle se: %d   |   Review baaki: %d   |   Manual: %d   |   Fail: %d'
                 % (s['enquiryForms'], s['protected'], s['alreadyProtected'], s['needsReview'], s['manual'], s['failed']))
        kit = r['kit']
        L.append('Files jinme badlav hua: %d   |   Kit: %s' % (s['filesChanged'], 'naya lagaya' if kit['installed'] else 'pehle se tha' if kit['alreadyPresent'] else 'nahi lagaya'))
    outputs = r.get('outputs') or {}
    if outputs.get('protectedZip'):
        L.extend(['', 'OUTPUT:', '  Protected site : %s' % outputs['protectedZip'], '  Backup (asli)  : %s' % outputs['backupZip']])
        if outputs.get('folder'):
            L.append('  Folder         : %s' % outputs['folder'])
    h = r.get('hub')
    if h:
        st = h.get('status')
        if st == 'connected':
            L.append('HUB: connect ho gaya (hub mein site #%s). Site pehli enquiry/page-view ke baad "Live" dikhegi.' % h.get('siteId'))
        elif st == 'failed':
            L.append("HUB: connect NAHI hua: %s Site protect ho gayi hai, par hub mein nahi judi. Hub se keys lekar spamguard/config.php mein 'hub' wala hissa jodo." % h.get('error'))
        elif st == 'dry-run':
            L.append('HUB: asli run mein site hub mein register hogi.')
        else:
            L.append('')
    L.append('')

    if r['changes']:
        L.append('KYA BADLA (sirf jodi gayi lines, kuch delete ya rewrite nahi hua):')
        for c in [x for x in r['changes'] if x['kind'] in ('guard-call', 'script-tag')]:
            L.append('  + %s  (line ~%s)  [%s]' % (c['file'], c['line'], 'guard' if c['kind'] == 'guard-call' else 'script'))
            L.append('      %s' % c['text'])
        sw = r.get('siteWide')
        if sw and sw.get('enabled'):
            L.append('  + HUB se jude hooks: %d PHP page(s) mein 1 line (central SEO + contact badlav), %d page(s) mein contact.js ka <script> tag.' % (sw['phpPages'], sw['jsPages']))
            for k in sw['skipped'][:8]:
                L.append('      chhoda: %s (%s)' % (k['file'], k['why']))
            if len(sw['skipped']) > 8:
                L.append('      ... aur %d files' % (len(sw['skipped']) - 8))
        if r['kit']['installed']:
            L.append('  + spamguard/  (kit ka folder + config.php, naya)')
        L.append('')

    rest = [f for f in r['forms'] if f['outcome'] != 'skipped']
    if rest:
        L.append('FORMS:')
        for i, f in enumerate(rest):
            L.append(' %d. %s:%s  [%s]  "%s"  ->  %s' % (i + 1, f['file'], f.get('line') or '?', KIND.get(f['kind'], f['kind']), f['label'], OUTCOME[f['outcome']]))
            if f.get('handler'):
                L.append('    handler: %s%s' % (f['handler'], '  (AJAX)' if f.get('submitMode') == 'ajax' else ''))
            for e in f['errors']:
                L.append('    ! %s' % ERR.get(e['code'], e['code']))
            if f['outcome'] in ('manual', 'needs-review'):
                for reason in f['reasons']:
                    fn = REASON.get(reason['code'])
                    if fn and reason.get('level') == 'warn':
                        L.append('    - %s' % fn(reason))
                if f['outcome'] == 'needs-review':
                    L.append('    (Ye form tab patch hoga jab --include-review use karoge, ya haath se.)')
                how = _manual_how_to(f)
                if how and f['outcome'] != 'manual':
                    L.append('    %s' % how)
        L.append('')
    if r['verification']['rolledBack']:
        L.append('WAPAS ORIGINAL KIYE GAYE (PHP syntax error aaya):')
        for x in r['verification']['rolledBack']:
            L.append('  %s: %s' % (x['file'], x['why']))
        L.append('')
    if r['changes']:
        v = r['verification']
        L.append('JAANCH:')
        L.append('  Badlav ke baad site dobara scan hui: %d form(s) "protected" dikh rahe hain.' % v['rescan']['formsProtectedAfter'])
        L.append('  PHP syntax check: %s' % ('har badli hui PHP file par chala, sab theek' if v['phpLint'] == 'ran' else v['phpLint']))
        L.append('')
        L.append('AB AAPKO KYA KARNA HAI:')
        for i, t in enumerate(WAHAN):
            L.append('  %d. %s' % (i + 1, t))
        L.append('')
        L.append('DHYAN: SpamGuard ko PHP 7.1 ya usse naya chahiye. Purane server par selftest hi sabse pehle batayega.')
        if r.get('login'):
            L.append('Admin password aur selftest link: PRIVATE-login.txt mein (isse kisi ko mat bhejo).')
    L.append('')
    return '\n'.join(L)


def render_login_text(r, site_host=None):
    if not r.get('login'):
        return None
    h = site_host or 'https://<aapki-site>'
    lg = r['login']
    return '\n'.join([
        'SpamGuard login: %s' % r['site']['name'],
        'PRIVATE - ye file kisi ko forward mat karo.',
        '',
        'Admin page : %s%s' % (h, lg['adminPath']),
        'Password   : %s%s' % (lg['password'], '   (apne aap banaya gaya)' if lg.get('passwordWasGenerated') else ''),
        'Selftest   : %s%s' % (h, lg['selftestPath']),
        '',
        'Selftest ke baad server se selftest.php delete kar do.',
        '',
    ])


def render_protect_bulk(b):
    L = []
    t = b['totals']
    L.append('=== BULK PROTECT ===')
    L.append('Sites: %d  |  Protected: %d  |  Partial: %d  |  Kuch nahi badla: %d  |  Pehle se: %d  |  Fail: %d'
             % (t['sites'], t['protected'], t['partial'], t['untouched'], t['already'], t['failed']))
    L.append('Forms protected: %d  |  Haath se baaki: %d' % (t['formsProtected'], t['formsOpen']))
    L.append('')
    for r in b['rows']:
        L.append('%s %s protected %d  baaki %d' % (r['name'].ljust(36), str(r['status']).ljust(18), r['protectedForms'], r['openForms']) + ('  ERROR: %s' % r['error'] if r.get('error') else ''))
    L.append('')
    return '\n'.join(L)
