"""Static analysis of PHP files (never executed). Port of php.js + phpmask.js."""
import re
from decimal import Decimal

from .util import count_newlines, js_key_order, line_at, rx, uniq

# --------------------------------------------------------------------------- phpmask.js

_PHP_BLOCK = rx(r'<\?(?!xml)(?:php\b|=)?[\s\S]*?(?:\?>|$)', 'gi')
_FORM_TAG = rx(r'<form\b', 'gi')
_BLOCK_COMMENT = rx(r'\/\*[\s\S]*?\*\/', 'g')
_LINE_COMMENT = rx(r'^[ \t]*(?:\/\/|#(?!\[)).*$', 'gm')


def split_php(text):
    """Split a mixed PHP/HTML file into two views of the SAME line numbering:

    - html: PHP blocks replaced by {{PHP}} (so attributes built by PHP are visibly dynamic)
    - php : only the PHP code (HTML replaced by blank lines)
    Also returns blocks (with start lines) so forms printed from inside PHP strings can be found.
    """
    html = []
    php = []
    last = 0
    blocks = []
    line = 1
    line_idx = 0
    for m in _PHP_BLOCK.finditer(text):
        if m.end() == m.start():
            continue
        before = text[last:m.start()]
        block = m.group()
        nl = count_newlines(block)
        html.append(before + '{{PHP}}' + '\n' * nl)
        php.append('\n' * count_newlines(before) + block)
        line += text.count('\n', line_idx, m.start())
        line_idx = m.start()
        blocks.append({'index': m.start(), 'line': line, 'text': block})
        last = m.end()
    rest = text[last:]
    html.append(rest)
    php.append('\n' * count_newlines(rest))
    return {'html': ''.join(html), 'php': ''.join(php), 'blocks': blocks, 'hasPhp': len(blocks) > 0}


def php_generated_forms(blocks):
    """Forms that are printed by PHP code (echo '<form ...>') cannot be edited safely by a tool."""
    out = []
    for b in blocks:
        for m in _FORM_TAG.finditer(b['text']):
            out.append({'line': b['line'] + count_newlines(b['text'][:m.start()])})
    return out


def strip_php_comments(code):
    """Remove /* */ and whole-line // and # comments, keeping line numbers intact."""
    code = _BLOCK_COMMENT.sub(lambda m: '\n' * count_newlines(m.group()), code)
    return _LINE_COMMENT.sub('', code)


# --------------------------------------------------------------------------- php.js

_PAIRS = rx(r'''['"]([\w\-]+)['"]\s*=>\s*(true|false|null|-?\d+(?:\.\d+)?|'((?:[^'\\]|\\.)*)'|"((?:[^"\\$]|\\.)*)")''', 'gi')
_UNESCAPE = rx(r'''\\(['"\\])''', 'g')
_TRUE = rx(r'^true$', 'i')
_FALSE = rx(r'^false$', 'i')
_NULL = rx(r'^null$', 'i')
_NUM_START = rx(r'^-?\d')


def js_number(raw):
    """Number(raw) rendered the way JSON.stringify would print it (ints stay ints)."""
    f = float(raw)
    if f == int(f) and abs(f) < 1e21:
        return int(Decimal(repr(f))) if abs(f) >= 2 ** 53 else int(f)
    return f


def js_str(v):
    """String(v) for JSON-ish values."""
    if v is True:
        return 'true'
    if v is False:
        return 'false'
    if v is None:
        return 'null'
    if isinstance(v, float):
        return repr(v)
    return str(v)


def parse_pairs(body):
    """Parse the literal key => value pairs of a simple PHP array expression."""
    pairs = {}
    for m in _PAIRS.finditer(body):
        raw = m.group(2)
        if _TRUE.search(raw):
            v = True
        elif _FALSE.search(raw):
            v = False
        elif _NULL.search(raw):
            v = None
        elif _NUM_START.search(raw):
            v = js_number(raw)
        else:
            s = m.group(3) if m.group(3) is not None else m.group(4)
            v = _UNESCAPE.sub(r'\1', s)
        pairs[m.group(1)] = v
    return js_key_order(pairs)


_RE_POST_FIELD = rx(r'''\$_(?:POST|REQUEST)\s*\[\s*['"]([^'"]+)['"]\s*\]''', 'g')
_RE_FILTER_INPUT = rx(r'''filter_input\s*\(\s*INPUT_POST\s*,\s*['"]([^'"]+)['"]''', 'g')
_RE_POST_ANY = rx(r'\$_(?:POST|REQUEST)\b')
_RE_REQ_METHOD = rx(r'''\$_SERVER\s*\[\s*['"]REQUEST_METHOD['"]\s*\]\s*={2,3}\s*['"]POST['"]''', 'i')
_RE_PHP_INPUT = rx(r'''file_get_contents\s*\(\s*['"]php:\/\/input['"]''')
_RE_FILES = rx(r'\$_FILES\b')
_RE_MAIL = rx(r'(?<![\w>:$])mail\s*\(')
_RE_PHPMAILER = rx(r'new\s+\\?PHPMailer\b|PHPMailer\\PHPMailer', 'i')
_RE_SWIFT = rx(r'Swift_Mailer|Symfony\\Component\\Mailer')
_RE_WPMAIL = rx(r'\bwp_mail\s*\(|mb_send_mail\s*\(')
_RE_MAILAPI = rx(r'api\.sendgrid\.com|api\.mailgun\.net|api\.postmarkapp\.com|api\.brevo\.com|api\.sendinblue\.com', 'i')
_RE_REC1 = rx(r'''(?<![\w>:$])mail\s*\(\s*['"]([^'"]+@[^'"]+)['"]''', 'g')
_RE_REC2 = rx(r'''\$(?:to|recipient|recipients|email_to|admin_email|mailto|send_to|to_email|receiver)\s*=\s*['"]([^'"$]+@[^'"$]+)['"]''', 'gi')
_RE_REC3 = rx(r'''addAddress\s*\(\s*['"]([^'"]+@[^'"]+)['"]''', 'g')
_RE_DOLLAR = rx(r'\$')
_RE_MYSQLI = rx(r'mysqli_connect\s*\(|new\s+\\?mysqli\s*\(|mysqli_query\s*\(|mysqli_prepare\s*\(|->real_escape_string')
_RE_MYSQL_OLD = rx(r'\bmysql_(?:connect|query|select_db)\s*\(')
_RE_PDO_MYSQL = rx(r'''new\s+\\?PDO\s*\(\s*['"]mysql:''', 'i')
_RE_PDO_SQLITE = rx(r'''new\s+\\?PDO\s*\(\s*['"]sqlite:''', 'i')
_RE_PDO_PGSQL = rx(r'''new\s+\\?PDO\s*\(\s*['"]pgsql:''', 'i')
_RE_PDO = rx(r'new\s+\\?PDO\s*\(')
_RE_WPDB = rx(r'\$wpdb\b')
_RE_INSERT_INTO = rx(r'\bINSERT\s+INTO\b', 'i')
_RE_DEF_CONN = rx(r'''mysqli_connect\s*\(|new\s+\\?mysqli\s*\(|mysql_connect\s*\(|new\s+\\?PDO\s*\(\s*['"](?:mysql|pgsql):''', 'i')
_RE_DEF_DB = rx(r'''define\s*\(\s*['"]DB_(?:HOST|NAME|USER)['"]''')
_RE_DBNAME1 = rx(r'''define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]+)['"]''')
_RE_DBNAME2 = rx(r'''(?:mysqli_connect|new\s+\\?mysqli)\s*\(\s*(?:[^,()]+,){3}\s*['"]([^'"]+)['"]''')
_RE_DBNAME3 = rx(r'dbname=([\w\-]+)', 'i')
_RE_INSERT = rx(r'''INSERT\s+(?:IGNORE\s+)?INTO\s+[`"']?(\w+)[`"']?\s*(?:\(([^)]*)\))?''', 'gi')
_RE_COL_JUNK = rx(r'''[`"'\s]''', 'g')
_RE_WRITES = rx(r'\b(?:file_put_contents|fputcsv|fwrite)\s*\(')
_RE_FOPEN = rx(r'''\bfopen\s*\([^)]*['"][aw]\+?b?['"]''')
_RE_LOCATION = rx(r'''header\s*\(\s*['"]Location:\s*([^'"]*)['"]''', 'gi')
_RE_JSON_ENCODE = rx(r'json_encode\s*\(\s*(?:array\s*\(|\[)([\s\S]{0,500}?)(?:\)|\])\s*\)', 'g')
_RE_TEXT_RESP = rx(r'''\b(?:echo|print|die|exit)\s*\(?\s*(['"])([^'"$\\]{1,40})\1\s*\)?\s*;''', 'g')
_RE_INCLUDE = rx(r'''\b(?:include|require)(?:_once)?\s*\(?\s*((?:__DIR__|dirname\s*\(\s*__FILE__\s*\)|\$_SERVER\s*\[\s*['"]DOCUMENT_ROOT['"]\s*\])\s*\.\s*)?(['"])([^'"]+\.(?:php|inc|phtml|html?))\2''', 'gi')
_RE_DOC_ROOT = rx(r'DOCUMENT_ROOT')
_RE_DYN_INCLUDE = rx(r'\b(?:include|require)(?:_once)?\s*\(?\s*(\$|[A-Za-z_]+\s*\()', 'g')
_RE_DIR_START = rx(r'^\s*(?:__DIR__|dirname)')
_RE_RECAPTCHA = rx(r'recaptcha\/api\/siteverify|google\.com\/recaptcha', 'i')
_RE_HCAPTCHA = rx(r'hcaptcha\.com\/siteverify', 'i')
_RE_TURNSTILE = rx(r'turnstile\/v0\/siteverify', 'i')
_RE_GUARD = rx(r'SpamGuard\s*::\s*guard\s*\(')
_RE_STRICT = rx(r'^\s*declare\s*\(\s*strict_types\s*=\s*1\s*\)', 'm')
_RE_NAMESPACE = rx(r'^\s*namespace\s+[\w\\]+\s*[;{]', 'm')
_RE_OPEN_TAG = rx(r'<\?(?:php\b|=)?', 'i')


def analyze_php(code):
    """Static analysis of one PHP file (never executed). `code` is the PHP-only view of the file.

    Passwords and other secrets are deliberately never captured.
    """
    c = strip_php_comments(code)
    a = {
        'readsPost': False,
        'postFields': [],
        'sendsMail': False,
        'mailVia': [],
        'mailRecipients': [],
        'usesDb': False,
        'dbEngines': [],
        'dbName': '',
        'definesDbConnection': False,
        'insertTables': [],
        'writesFile': False,
        'acceptsUpload': False,
        'redirects': [],
        'jsonResponses': [],
        'textResponses': [],
        'includes': [],
        'dynamicIncludes': 0,
        'verifiesCaptcha': [],
        'guardCalled': False,
        'hasDeclareStrict': False,
        'hasNamespace': False,
        'firstPhpLine': None,
    }

    om = _RE_OPEN_TAG.search(code)
    a['firstPhpLine'] = line_at(code, om.start()) if om else None

    # --- input
    fields = []
    for m in _RE_POST_FIELD.finditer(c):
        fields.append(m.group(1))
    for m in _RE_FILTER_INPUT.finditer(c):
        fields.append(m.group(1))
    a['postFields'] = uniq(fields)
    a['readsPost'] = (
        len(fields) > 0
        or bool(_RE_POST_ANY.search(c))
        or bool(_RE_REQ_METHOD.search(c))
        or bool(_RE_PHP_INPUT.search(c))
    )
    a['acceptsUpload'] = bool(_RE_FILES.search(c))

    # --- mail
    if _RE_MAIL.search(c):
        a['sendsMail'] = True
        a['mailVia'].append('mail()')
    if _RE_PHPMAILER.search(c):
        a['sendsMail'] = True
        a['mailVia'].append('PHPMailer')
    if _RE_SWIFT.search(c):
        a['sendsMail'] = True
        a['mailVia'].append('SwiftMailer/Symfony')
    if _RE_WPMAIL.search(c):
        a['sendsMail'] = True
        a['mailVia'].append('wp_mail')
    if _RE_MAILAPI.search(c):
        a['sendsMail'] = True
        a['mailVia'].append('mail API')
    rec = []
    for pat in (_RE_REC1, _RE_REC2, _RE_REC3):
        for m in pat.finditer(c):
            rec.append(m.group(1).lower())
    a['mailRecipients'] = [e for e in uniq(rec) if not _RE_DOLLAR.search(e)]

    # --- database
    eng = []
    if _RE_MYSQLI.search(c):
        eng.append('mysqli')
    if _RE_MYSQL_OLD.search(c):
        eng.append('mysql (old)')
    if _RE_PDO_MYSQL.search(c):
        eng.append('PDO-mysql')
    elif _RE_PDO_SQLITE.search(c):
        eng.append('PDO-sqlite')
    elif _RE_PDO_PGSQL.search(c):
        eng.append('PDO-pgsql')
    elif _RE_PDO.search(c):
        eng.append('PDO')
    if _RE_WPDB.search(c):
        eng.append('wpdb')
    a['dbEngines'] = uniq(eng)
    a['usesDb'] = len(a['dbEngines']) > 0 or bool(_RE_INSERT_INTO.search(c))
    a['definesDbConnection'] = bool(_RE_DEF_CONN.search(c)) or bool(_RE_DEF_DB.search(c))
    # database NAME only (never user/password)
    dn = _RE_DBNAME1.search(c) or _RE_DBNAME2.search(c) or _RE_DBNAME3.search(c)
    if dn:
        a['dbName'] = dn.group(1)
    tables = {}
    for m in _RE_INSERT.finditer(c):
        cols = [x for x in (_RE_COL_JUNK.sub('', y) for y in m.group(2).split(',')) if x] if m.group(2) else []
        prev = tables.get(m.group(1))
        if prev is None or len(cols) > len(prev['columns']):
            tables[m.group(1)] = {'table': m.group(1), 'columns': cols}
    a['insertTables'] = list(tables.values())

    # --- other effects
    a['writesFile'] = bool(_RE_WRITES.search(c)) or bool(_RE_FOPEN.search(c))
    for m in _RE_LOCATION.finditer(c):
        a['redirects'].append(m.group(1).strip(' \t\n\x0b\x0c\r                 　﻿'))

    # --- what the handler answers (matters for AJAX forms)
    for m in _RE_JSON_ENCODE.finditer(c):
        pairs = parse_pairs(m.group(1))
        if pairs:
            a['jsonResponses'].append({'line': line_at(c, m.start()), 'pairs': pairs})
    for m in _RE_TEXT_RESP.finditer(c):
        a['textResponses'].append({'line': line_at(c, m.start()), 'text': m.group(2)})

    # --- includes (static only)
    for m in _RE_INCLUDE.finditer(c):
        base = m.group(1)
        a['includes'].append({'path': m.group(3), 'base': ('root' if _RE_DOC_ROOT.search(base) else 'dir') if base else 'plain'})
    for m in _RE_DYN_INCLUDE.finditer(c):
        if not _RE_DIR_START.search(m.group(1)):
            a['dynamicIncludes'] += 1

    # --- existing protections
    if _RE_RECAPTCHA.search(c):
        a['verifiesCaptcha'].append('recaptcha')
    if _RE_HCAPTCHA.search(c):
        a['verifiesCaptcha'].append('hcaptcha')
    if _RE_TURNSTILE.search(c):
        a['verifiesCaptcha'].append('turnstile')
    a['guardCalled'] = bool(_RE_GUARD.search(c))

    # --- facts the injector needs
    a['hasDeclareStrict'] = bool(_RE_STRICT.search(c))
    a['hasNamespace'] = bool(_RE_NAMESPACE.search(c))
    return a


_KEY_STATUS = rx(r'^(status|success|result|ok|code|error)$', 'i')
_GOOD_VAL = rx(r'^(success|ok|sent|true|1|200)$', 'i')
_BAD_VAL = rx(r'^(error|fail|failed|false|0)$', 'i')
_KEY_ERROR = rx(r'^error$', 'i')
_HAPPY_TXT = rx(r'thank|sent|success|received', 'i')
_SAD_TXT = rx(r'error|fail|invalid|please|required|wrong', 'i')


def _is_zero(v):
    return (not isinstance(v, bool)) and isinstance(v, (int, float)) and v == 0


def guess_success_json(an):
    """Pick the most likely "success" answer out of a handler's json_encode calls."""

    def score(p):
        s = 0
        for k, v in p['pairs'].items():
            if _KEY_STATUS.search(k):
                if v is True or _GOOD_VAL.search(js_str(v)):
                    s += 3
                if v is False or _BAD_VAL.search(js_str(v)):
                    s -= 3
                if _KEY_ERROR.search(k) and (v is False or _is_zero(v) or v == ''):
                    s += 4
            if _HAPPY_TXT.search(js_str(v)):
                s += 1
            if _SAD_TXT.search(js_str(v)):
                s -= 1
        return s

    best = None
    for p in an['jsonResponses']:
        s = score(p)
        if s > 0 and (best is None or s > best['s']):
            best = {'s': s, 'pairs': p['pairs'], 'line': p['line']}
    return {'json': best['pairs'], 'line': best['line']} if best else None
