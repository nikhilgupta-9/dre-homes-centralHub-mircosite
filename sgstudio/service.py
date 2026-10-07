"""Everything the screen needs, plain data in and out (port of src/app/service.js)."""
import os
import re
import shutil
import tempfile

from .scanner import scan_site, render_text, REASON
from .scanner.bulk import scan_many
from .scanner.util import SKIP_DIRS
from .injector import protect_site
from .injector.bulk import protect_many, write_site_reports
from .injector.report import render_protect_text, STATUS_LINE, OUTCOME, ERR, WAHAN


def _is_site_dir(d):
    try:
        return any(re.match(r'^index\.(html?|php)$', n, re.I) for n in os.listdir(d))
    except OSError:
        return False


def classify_drop(paths):
    """one zip -> site; folder with index.* -> site; folder of sites / many items -> bulk."""
    allp = [p for p in (paths or []) if isinstance(p, str) and p and not os.path.basename(p).startswith('.')]
    sql_files = [p for p in allp if re.search(r'\.sql$', p, re.I)]
    lst = [p for p in allp if not re.search(r'\.sql$', p, re.I)]
    if sql_files and not lst:
        return {'kind': 'invalid', 'reason': 'Ye database (.sql) file hai. Isse site ke zip/folder ke saath hi dalo.'}
    r = _classify1(lst)
    if sql_files and r['kind'] == 'site':
        r['sqlFiles'] = sql_files
    return r


def _classify1(lst):
    if not lst:
        return {'kind': 'invalid', 'reason': 'Kuch nahi mila. Zip ya folder dalo.'}
    items = []
    for p in lst:
        if not os.path.exists(p):
            return {'kind': 'invalid', 'reason': 'Ye file/folder nahi khul raha: ' + os.path.basename(p)}
        if os.path.isfile(p):
            if not re.search(r'\.zip$', p, re.I):
                return {'kind': 'invalid', 'reason': 'Sirf .zip ya folder chalega: ' + os.path.basename(p)}
            items.append({'name': re.sub(r'\.zip$', '', os.path.basename(p), flags=re.I), 'input': p, 'type': 'zip'})
        elif os.path.isdir(p):
            items.append({'name': os.path.basename(p), 'input': p, 'type': 'folder'})
    if len(items) == 1:
        it = items[0]
        if it['type'] == 'folder' and not _is_site_dir(it['input']):
            kids = 0
            try:
                for e in os.scandir(it['input']):
                    if e.name.startswith('.') or e.name in SKIP_DIRS:
                        continue
                    if e.is_file() and re.search(r'\.zip$', e.name, re.I):
                        kids += 1
                    elif e.is_dir():
                        if _is_site_dir(e.path) or any(x.is_dir() and _is_site_dir(x.path) for x in os.scandir(e.path)):
                            kids += 1
            except OSError:
                kids = 0
            if kids >= 2:
                count = sum(1 for e in os.scandir(it['input']) if not e.name.startswith('.') and e.name not in SKIP_DIRS and (e.is_dir() or (e.is_file() and re.search(r'\.zip$', e.name, re.I))))
                return {'kind': 'bulk', 'parent': it['input'], 'name': it['name'], 'count': count}
        return {'kind': 'site', 'input': it['input'], 'name': it['name'], 'type': it['type']}
    return {'kind': 'bulk', 'items': items, 'count': len(items), 'name': '%d sites' % len(items)}


def _notes_of(reasons):
    return [REASON[r['code']](r) for r in (reasons or []) if r.get('level') == 'warn' and r.get('code') in REASON]


def ui_scan(report):
    return {
        'name': report['site']['name'],
        'platform': report['site']['platform'],
        'summary': report['summary'],
        'database': {'used': report['database']['used'], 'engines': report['database'].get('engines') or []},
        'forms': [{
            'file': f['file'], 'line': f['line'], 'kind': f['kind'], 'label': f['label'],
            'status': f['plan']['status'],
            'handler': f['handler']['file'] if f.get('handler') and f['handler'].get('exists') else None,
            'submitMode': f.get('submitMode'),
            'notes': _notes_of(f['plan'].get('reasons')),
        } for f in report['forms']],
        'exposed': len(report['security']['exposedFiles']),
        'contacts': {'phones': len(report['contacts']['phones']), 'emails': len(report['contacts']['emails'])},
    }


def ui_protect(r):
    forms = []
    for f in r['forms']:
        if f['outcome'] == 'skipped':
            continue
        notes = [ERR.get(e['code'], e['code']) for e in f['errors']]
        if f['outcome'] in ('manual', 'needs-review'):
            notes += _notes_of(f.get('reasons'))
        forms.append({'file': f['file'], 'line': f['line'], 'label': f['label'], 'outcome': f['outcome'], 'outcomeText': OUTCOME.get(f['outcome']), 'handler': f.get('handler'), 'notes': notes})
    login = r.get('login')
    return {
        'name': r['site']['name'], 'status': r['status'], 'statusText': STATUS_LINE.get(r['status'], r['status']),
        'summary': r['summary'], 'kit': r.get('kit'), 'hub': r.get('hub'), 'outputs': r.get('outputs'),
        'login': {'password': login['password'], 'adminPath': login['adminPath'], 'selftestPath': login['selftestPath']} if login else None,
        'changed': len(r['changes']) > 0,
        'forms': forms,
        'steps': WAHAN if r['changes'] else [],
        'rolledBack': r['verification']['rolledBack'],
    }


def scan(input_path, sql_files=None):
    report = scan_site(input_path, sql_files or [])
    return {'ui': ui_scan(report), 'text': render_text(report)}


def _popts(o):
    hub = o.get('hub')
    return {
        'outDir': o.get('outDir'), 'sqlFiles': o.get('sqlFiles') or [], 'includeReview': bool(o.get('includeReview')),
        'quarantine': bool(o.get('quarantine')), 'notifyEmail': o.get('notifyEmail') or None, 'timezone': o.get('timezone') or None,
        'password': o.get('password') or None, 'dryRun': bool(o.get('dryRun')),
        'hub': {'url': hub['url'], 'token': hub['token']} if hub and hub.get('url') and hub.get('token') else None,
    }


def protect(input_path, opts):
    if not opts.get('outDir') and not opts.get('dryRun'):
        raise ValueError('Result kahan save karna hai? Folder chuno.')
    r = protect_site(input_path, _popts(opts))
    if not opts.get('dryRun'):
        write_site_reports(r, os.path.abspath(opts['outDir']))
    return {'ui': ui_protect(r), 'text': render_protect_text(r)}


def _stage(drop, deref):
    """Several loose items: copy them into one temp parent so the batch tools see a normal folder of sites."""
    staging = tempfile.mkdtemp(prefix='sg-drop-')
    used = set()
    for it in drop['items']:
        n = it['name']
        k = 2
        while n.lower() in used:
            n = '%s_%d' % (it['name'], k)
            k += 1
        used.add(n.lower())
        if it['type'] == 'zip':
            shutil.copyfile(it['input'], os.path.join(staging, n + '.zip'))
        else:
            shutil.copytree(it['input'], os.path.join(staging, n), symlinks=True)
    return staging


def protect_bulk(drop, opts, on_progress=None):
    if not opts.get('outDir') and not opts.get('dryRun'):
        raise ValueError('Result kahan save karna hai? Folder chuno.')
    parent = drop.get('parent')
    staging = None
    if not parent:
        staging = parent = _stage(drop, False)
    try:
        o = _popts(opts)
        o['onProgress'] = on_progress
        return protect_many(parent, o)
    finally:
        if staging:
            shutil.rmtree(staging, ignore_errors=True)


def scan_bulk(drop, on_progress=None):
    parent = drop.get('parent')
    staging = None
    if not parent:
        staging = parent = _stage(drop, False)
    try:
        b = scan_many(parent, on_progress)
        return {'totals': b['totals'], 'rows': b['rows']}
    finally:
        if staging:
            shutil.rmtree(staging, ignore_errors=True)
