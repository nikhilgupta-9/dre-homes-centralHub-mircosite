"""Protect one site (port of src/injector/index.js).  Python 3.9, stdlib only."""
import inspect
import math
import os
import re
import shutil
import stat as _stat
import subprocess
import tempfile
import zipfile

from sgstudio.scanner import scan_site
from sgstudio.scanner.loader import prepare_input
from sgstudio.scanner import util as _scanner_util
from sgstudio.config import generate_config
from sgstudio.hub import provision_site
from sgstudio.injector import edits as E

KIT_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'kit', 'spamguard'))
MAX_SITE_BYTES = int(1.5 * 1024 * 1024 * 1024)

_SKIP_FILE = getattr(_scanner_util, 'SKIP_FILE', None) or re.compile(r'^(\.DS_Store|Thumbs\.db|\._.*)$')


def _skip_file(name):
    if isinstance(_SKIP_FILE, str):
        _re = re.compile(_SKIP_FILE)
        return bool(_re.search(name))
    return bool(_SKIP_FILE.search(name))


def safe_name(n):
    s = re.sub(r'[^A-Za-z0-9_.\-]+', '_', str(n))
    s = re.sub(r'^_+|_+$', '', s)[:80]
    return s or 'site'


_php_avail = None


def has_php():
    global _php_avail
    if _php_avail is None:
        try:
            _php_avail = subprocess.run(['php', '-v'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0
        except Exception:
            _php_avail = False
    return _php_avail


def _php_lint(path):
    """Returns (ok, first_line_of_output)."""
    try:
        r = subprocess.run(['php', '-l', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    except Exception:
        return False, ''
    if r.returncode == 0:
        return True, ''
    out = (r.stdout.decode('utf-8', 'replace') + r.stderr.decode('utf-8', 'replace')).strip()
    return False, out.split('\n')[0]


def list_tree(root):
    """Every regular file + directory under root (symlinks and Mac junk are never followed or copied)."""
    files = []
    dirs = []
    stack = ['']
    while stack:
        rel = stack.pop()
        try:
            ents = list(os.scandir(os.path.join(root, rel) if rel else root))
        except OSError:
            continue
        for e in ents:
            if e.is_symlink():
                continue
            r = rel + '/' + e.name if rel else e.name
            try:
                if e.is_dir(follow_symlinks=False):
                    if e.name == '__MACOSX':
                        continue
                    dirs.append(r)
                    stack.append(r)
                elif e.is_file(follow_symlinks=False) and not _skip_file(e.name):
                    files.append({'rel': r, 'size': e.stat(follow_symlinks=False).st_size})
            except OSError:
                continue
    files.sort(key=lambda f: f['rel'])
    dirs.sort()
    return {'files': files, 'dirs': dirs}


def copy_tree(src, dest, tree):
    os.makedirs(dest, exist_ok=True)
    for d in tree['dirs']:
        os.makedirs(os.path.join(dest, d), exist_ok=True)
    for f in tree['files']:
        s = os.path.join(src, f['rel'])
        t = os.path.join(dest, f['rel'])
        os.makedirs(os.path.dirname(t), exist_ok=True)
        shutil.copyfile(s, t)
        try:
            shutil.copymode(s, t)
        except OSError:
            pass


def zip_folder(dir_, out_zip):
    """Zip a folder; empty folders (like uploads/) are kept. Returns the number of files."""
    tree = list_tree(dir_)
    os.makedirs(os.path.dirname(os.path.abspath(out_zip)), exist_ok=True)
    with zipfile.ZipFile(out_zip, 'w', zipfile.ZIP_DEFLATED, strict_timestamps=False) as z:
        for d in tree['dirs']:
            zi = zipfile.ZipInfo(d + '/', date_time=(1980, 1, 1, 0, 0, 0))
            zi.external_attr = (_stat.S_IFDIR | 0o755) << 16 | 0x10
            z.writestr(zi, b'')
        for f in tree['files']:
            z.write(os.path.join(dir_, f['rel']), f['rel'], compress_type=zipfile.ZIP_DEFLATED)
    return len(tree['files'])


def read_latin(p):
    with open(p, 'rb') as fh:
        return fh.read().decode('latin1')


def write_latin(p, t):
    try:
        data = t.encode('latin1')
    except UnicodeEncodeError:  # same as Node's Buffer.from(t, 'latin1'): keep the low byte
        data = bytes(ord(c) & 0xFF for c in t)
    with open(p, 'wb') as fh:
        fh.write(data)


def rel_to_root(file):
    depth = len(file.split('/')) - 1
    return '' if depth == 0 else '/'.join(['..'] * depth)


def _get(o, k, default=None):
    if isinstance(o, dict):
        return o.get(k, default)
    return getattr(o, k, default)


def _run(maybe_awaitable):
    if inspect.isawaitable(maybe_awaitable):
        import asyncio
        return asyncio.run(maybe_awaitable) if not inspect.iscoroutine(maybe_awaitable) else asyncio.run(maybe_awaitable)
    return maybe_awaitable


def _scan(site_dir, sql_files):
    return _run(scan_site(site_dir, list(sql_files or [])))


def _truthy(v):
    """JavaScript truthiness for values coming from JSON-like data (containers are always truthy)."""
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v != 0
    if isinstance(v, str):
        return v != ''
    return True


def _lead(insert):
    return 2 if insert.startswith('\r\n') else 1 if insert.startswith('\n') else 0


def _change(rel, e, original_text):
    lead = _lead(e['insert'])
    return {'file': rel, 'kind': e['kind'], 'line': E.line_of_offset(original_text, e['offset']) + (1 if lead else 0), 'text': E.js_trim(e['insert'])}


def _js_round(x):
    return int(math.floor(x + 0.5))


_SKIP_DIR = re.compile(r'(^|/)(spamguard|vendor|node_modules|\.git|admin|administrator|wp-admin|wp-includes|phpmyadmin)/', re.I)
_PHP_EXT = re.compile(r'\.(php|phtml|inc)$', re.I)
_PHP_EXT2 = re.compile(r'\.(php|phtml)$', re.I)
_SW_EXT = re.compile(r'\.(php|phtml|html?)$', re.I)
_HAS_PAGE = re.compile(r'<html[\t\n\x0b\x0c\r \xa0>]|<head[\t\n\x0b\x0c\r \xa0>]|</body>', re.I)
_HAS_HEAD = re.compile(r'<html[\t\n\x0b\x0c\r \xa0>]|<head[\t\n\x0b\x0c\r \xa0>]', re.I)
_HUB_IN_CFG = re.compile(r"'hub'[\t\n\x0b\x0c\r \xa0]*=>")


def protect_site(input_path, opts=None):
    """Protect one site.

    input_path: .zip or folder.  opts (camelCase keys, as in the JS version): outDir, includeReview, dryRun, password,
    notifyEmail, quarantine, timezone, turnstile, basePath, sqlFiles, name, siteId, keepFolder, siteWide,
    hub={url, token}.
    """
    opts = dict(opts or {})
    dry = bool(opts.get('dryRun'))
    out_dir_abs = os.path.abspath(opts['outDir']) if opts.get('outDir') else None
    if not out_dir_abs and not dry:
        raise Exception('outDir chahiye (ya dryRun)')
    loaded = prepare_input(input_path)
    work = tempfile.mkdtemp(prefix='sg-protect-')
    try:
        source = _get(loaded, 'source')
        root = _get(loaded, 'root')
        if out_dir_abs and source == 'folder':
            in_abs = os.path.realpath(os.path.abspath(input_path))
            if out_dir_abs == in_abs or out_dir_abs.startswith(in_abs + os.sep):
                raise Exception('Output folder site ke folder ke andar nahi ho sakta. Koi aur folder chuno.')
        tree = list_tree(root)
        total = sum(f['size'] for f in tree['files'])
        if total > MAX_SITE_BYTES:
            raise Exception('Site bahut badi hai (%d MB). Pehle badi videos/backups hata do.' % _js_round(total / 1048576))

        site_dir = os.path.join(work, 'site')
        copy_tree(root, site_dir, tree)
        scan = _scan(site_dir, opts.get('sqlFiles'))
        name = opts.get('name') or _get(loaded, 'name')
        hub_opt = opts.get('hub')
        hub_given = bool(hub_opt and hub_opt.get('url') and hub_opt.get('token'))
        platform = scan['site'].get('platform')
        result = {
            'tool': 'spamguard-studio/injector',
            'site': {'name': name, 'source': source, 'platform': platform, 'rootInsideInput': _get(loaded, 'rootRel') or ''},
            'status': 'nothing-to-do',
            'options': {'includeReview': bool(opts.get('includeReview')), 'dryRun': dry, 'quarantine': bool(opts.get('quarantine'))},
            'forms': [],
            'changes': [],
            'kit': {'installed': False, 'alreadyPresent': False},
            'verification': {'rescan': None, 'phpLint': 'ran' if has_php() else 'skipped (PHP is computer par nahi hai)', 'rolledBack': []},
            'outputs': {},
            'login': None,
            'warnings': [(w.get('code') if isinstance(w, dict) and w.get('code') else str(w)) for w in scan.get('warnings', [])],
        }

        def applicable(f):
            return f['plan']['status'] == 'auto' or (opts.get('includeReview') and f['plan']['status'] == 'review')

        scan_forms = scan['forms']
        targets = [i for i, f in enumerate(scan_forms) if applicable(f)]
        already_done = [f for f in scan_forms if f['plan']['status'] == 'done']

        # ---- decide every edit (per file), nothing is written yet
        file_edits = {}  # rel -> [edit]  (insertion ordered)
        original = {}
        form_state = {}  # form index -> {'errors': [], 'files': []}

        def text(rel):
            if rel not in original:
                original[rel] = read_latin(os.path.join(site_dir, rel))
            return original[rel]

        def add_edit(rel, edit):
            file_edits.setdefault(rel, []).append(edit)

        bp = opts.get('basePath')
        script_src = (re.sub(r'/*$', '/', bp) if bp else '/') + 'spamguard/spamguard.js'
        guard_planned = set()
        script_planned = set()

        for fi in targets:
            f = scan_forms[fi]
            st = {'errors': [], 'files': []}
            form_state[fi] = st

            def add_file(x, st=st):
                if x not in st['files']:
                    st['files'].append(x)

            for a in f['plan']['actions']:
                if a['type'] == 'add-script-tag':
                    add_file(a['file'])
                    if a['file'] in script_planned:
                        continue
                    p = E.plan_script_edit(text(a['file']), a.get('afterLine'), script_src)
                    if p.get('error') == 'already':
                        continue
                    if p.get('error'):
                        st['errors'].append({'code': p['error'], 'file': a['file'], 'action': a['type']})
                        continue
                    script_planned.add(a['file'])
                    e = {'kind': 'script-tag', 'file': a['file']}
                    e.update(p)
                    add_edit(a['file'], e)
                elif a['type'] == 'add-guard-call':
                    add_file(a['file'])
                    if a['file'] in guard_planned:
                        continue
                    resp = next((x for x in f['plan']['actions'] if x['type'] == 'set-success-response'), None)
                    override = {}
                    if resp:
                        succ = {}
                        if _truthy(resp.get('json')):
                            succ['json'] = resp['json']
                        elif _truthy(resp.get('text')):
                            succ['text'] = resp['text']
                        if _truthy(resp.get('redirect')):
                            succ['redirect'] = resp['redirect']
                        if succ:
                            override['success'] = succ
                    p = E.plan_guard_edit(text(a['file']), rel_to_root(a['file']), override)
                    if p.get('error') == 'already':
                        continue
                    if p.get('error'):
                        st['errors'].append({'code': p['error'], 'file': a['file'], 'action': a['type']})
                        continue
                    guard_planned.add(a['file'])
                    e = {'kind': 'guard-call', 'file': a['file']}
                    e.update(p)
                    add_edit(a['file'], e)

        # ---- write the edited files into the working copy
        touched = []
        for rel, edits in file_edits.items():
            out = E.apply_insertions(text(rel), edits)
            write_latin(os.path.join(site_dir, rel), out)
            touched.append(rel)
            for e in edits:
                result['changes'].append(_change(rel, e, original[rel]))

        # ---- PHP syntax check (when PHP exists); a file that fails is restored to the original
        lint_failed = set()
        if has_php():
            for rel in touched:
                if not _PHP_EXT.search(rel):
                    continue
                ok, why = _php_lint(os.path.join(site_dir, rel))
                if not ok:
                    write_latin(os.path.join(site_dir, rel), original[rel])
                    lint_failed.add(rel)
                    result['verification']['rolledBack'].append({'file': rel, 'why': why})
            result['changes'] = [c for c in result['changes'] if c['file'] not in lint_failed]

        # ---- install the kit (only if at least one form got protected)
        any_applied = len(result['changes']) > 0 or len(already_done) > 0
        kit_target = os.path.join(site_dir, 'spamguard')
        hub_wanted = hub_given and opts.get('siteWide') is not False and platform != 'wordpress'
        if len(result['changes']) > 0 or hub_wanted:
            if os.path.exists(kit_target):
                result['kit']['alreadyPresent'] = True
            else:
                copy_tree(KIT_DIR, kit_target, list_tree(KIT_DIR))
                result['kit']['installed'] = True
            if not os.path.exists(os.path.join(kit_target, 'config.php')):
                extra = None
                if hub_given:
                    if dry:
                        result['hub'] = {'status': 'dry-run'}
                    else:
                        try:
                            p = provision_site(hub_opt, name)
                            extra = {'hub': {'url': p['hub_url'], 'site_key': p['site_key'], 'secret': p['secret']}}
                            result['hub'] = {'status': 'connected', 'siteId': p['site_id']}
                        except Exception as e:
                            result['hub'] = {'status': 'failed', 'error': str(e)}
                gen = generate_config({
                    'extra': extra,
                    'siteId': opts.get('siteId') or safe_name(name),
                    'password': opts.get('password'),
                    'notifyEmail': opts.get('notifyEmail'),
                    'timezone': opts.get('timezone'),
                    'quarantine': opts.get('quarantine'),
                    'turnstile': opts.get('turnstile'),
                })
                with open(os.path.join(kit_target, 'config.php'), 'wb') as fh:
                    fh.write(_get(gen, 'php').encode('utf-8'))
                result['login'] = {
                    'adminPath': '/spamguard/spam-admin.php',
                    'selftestPath': '/spamguard/selftest.php?key=%s' % _get(gen, 'selftestKey'),
                    'password': _get(gen, 'password'),
                    'passwordWasGenerated': _get(gen, 'generatedPassword'),
                }

        # ---- site-wide hooks (only for sites that are connected to the hub): central SEO + contact details
        result['siteWide'] = {'enabled': False, 'phpPages': 0, 'jsPages': 0, 'skipped': []}
        hub_res = result.get('hub')
        hub_ok = bool(hub_res) and hub_res['status'] in ('connected', 'dry-run')
        cfg_file = os.path.join(kit_target, 'config.php')
        existing_hub = (not hub_res) and os.path.exists(cfg_file) and bool(_HUB_IN_CFG.search(read_latin(cfg_file)))
        if (hub_ok or existing_hub) and opts.get('siteWide') is not False and platform != 'wordpress' and os.path.exists(kit_target):
            sw = result['siteWide']
            sw['enabled'] = True
            js_src = (re.sub(r'/*$', '/', bp) if bp else '/') + 'spamguard/contact.js'
            sw_tree = list_tree(site_dir)
            snapshot = {}
            sw_edits = {}
            for f in sw_tree['files']:
                rel = f['rel']
                if _SKIP_DIR.search(rel) or not _SW_EXT.search(rel) or f['size'] > 1500000:
                    continue
                is_php = bool(_PHP_EXT2.search(rel))
                cur = read_latin(os.path.join(site_dir, rel))
                edits = []
                if not _HAS_PAGE.search(cur):
                    continue
                if is_php and _HAS_HEAD.search(cur):
                    a = E.plan_apply_edit(cur, rel_to_root(rel))
                    if a.get('error') and a['error'] != 'already':
                        sw['skipped'].append({'file': rel, 'why': a['error']})
                    elif not a.get('error'):
                        e = {'kind': 'sg-apply', 'file': rel}
                        e.update(a)
                        edits.append(e)
                j = E.plan_contact_script_edit(cur, js_src)
                if j.get('error') and j['error'] not in ('already', 'no-body'):
                    sw['skipped'].append({'file': rel, 'why': j['error']})
                elif not j.get('error'):
                    e = {'kind': 'contact-js', 'file': rel}
                    e.update(j)
                    edits.append(e)
                if edits:
                    snapshot[rel] = cur
                    sw_edits[rel] = edits
            for rel, edits in sw_edits.items():
                write_latin(os.path.join(site_dir, rel), E.apply_insertions(snapshot[rel], edits))
                if has_php() and _PHP_EXT2.search(rel):
                    ok, _why = _php_lint(os.path.join(site_dir, rel))
                    if not ok:
                        write_latin(os.path.join(site_dir, rel), snapshot[rel])  # back to how it was before this step
                        sw['skipped'].append({'file': rel, 'why': 'php-syntax-check-failed'})
                        continue
                for e in edits:
                    result['changes'].append(_change(rel, e, snapshot[rel]))
                    if e['kind'] == 'sg-apply':
                        sw['phpPages'] += 1
                    else:
                        sw['jsPages'] += 1

        # ---- verify by scanning the protected copy again
        after = _scan(site_dir, opts.get('sqlFiles'))

        def key_of(f, i, lst):
            return f['file'] + '#' + str(sum(1 for j, x in enumerate(lst) if x['file'] == f['file'] and j < i))

        after_map = {}
        for i, f in enumerate(after['forms']):
            after_map[key_of(f, i, after['forms'])] = f
        for i, f in enumerate(scan_forms):
            key = key_of(f, i, scan_forms)
            st = form_state.get(i)
            aft = after_map.get(key)
            h = f.get('handler')
            rec = {
                'file': f['file'],
                'line': f.get('line'),
                'label': f.get('label'),
                'kind': f.get('kind'),
                'handler': h['file'] if h and h.get('exists') else None,
                'submitMode': f.get('submitMode'),
                'planBefore': f['plan']['status'],
                'reasons': f['plan'].get('reasons', []),
                'outcome': None,
                'errors': [],
            }
            if f['plan']['status'] == 'skip':
                rec['outcome'] = 'skipped'
            elif f['plan']['status'] == 'done':
                rec['outcome'] = 'already-protected'
            elif st is None:
                rec['outcome'] = 'needs-review' if f['plan']['status'] == 'review' else 'manual'
            else:
                rec['errors'] = list(st['errors'])
                for rel in st['files']:
                    if rel in lint_failed:
                        rec['errors'].append({'code': 'php-syntax-check-failed', 'file': rel})
                verified = bool(aft and aft['plan']['status'] == 'done')
                rec['outcome'] = 'protected' if (not rec['errors'] and verified) else 'failed'
                if not rec['errors'] and not verified:
                    rec['errors'].append({'code': 'verification-failed'})
            result['forms'].append(rec)

        def count(o):
            return sum(1 for f in result['forms'] if f['outcome'] == o)

        n_prot = count('protected')
        n_open = sum(1 for f in result['forms'] if f['outcome'] in ('manual', 'needs-review', 'failed'))
        result['summary'] = {
            'forms': len(result['forms']),
            'enquiryForms': sum(1 for f in result['forms'] if f['outcome'] != 'skipped'),
            'protected': n_prot,
            'alreadyProtected': count('already-protected'),
            'needsReview': count('needs-review'),
            'manual': count('manual'),
            'failed': count('failed'),
            'filesChanged': len(set(c['file'] for c in result['changes'])),
        }
        a_sum = after.get('summary', {})
        result['verification']['rescan'] = {
            'formsProtectedAfter': sum(1 for f in after['forms'] if f['plan']['status'] == 'done'),
            'autoLeft': a_sum.get('auto'),
            'reviewLeft': a_sum.get('review'),
        }
        result['status'] = ('manual-only' if n_open else 'nothing-to-do') if not any_applied else ('partial' if n_open else 'protected')
        if result['summary']['enquiryForms'] == 0:
            result['status'] = 'no-forms'
        if len(result['changes']) == 0 and result['summary']['alreadyProtected'] and not n_open:
            result['status'] = 'already-protected'

        # ---- outputs
        if not dry and len(result['changes']) > 0:
            base = os.path.join(out_dir_abs, safe_name(name))
            os.makedirs(base, exist_ok=True)
            backup = os.path.join(base, safe_name(name) + '-backup-original.zip')
            if source == 'zip':
                shutil.copyfile(os.path.abspath(input_path), backup)
            else:
                zip_folder(root, backup)
            prot = os.path.join(base, safe_name(name) + '-protected.zip')
            zip_folder(site_dir, prot)
            result['outputs'] = {'dir': base, 'backupZip': backup, 'protectedZip': prot}
            if opts.get('keepFolder'):
                keep = os.path.join(base, 'protected-site')
                shutil.rmtree(keep, ignore_errors=True)
                copy_tree(site_dir, keep, list_tree(site_dir))
                result['outputs']['folder'] = keep
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)
        cl = getattr(loaded, 'cleanup', None) or _get(loaded, 'cleanup')
        if callable(cl):
            cl()
