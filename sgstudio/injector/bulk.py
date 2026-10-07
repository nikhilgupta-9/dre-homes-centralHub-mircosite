"""Protect many sites at once (port of src/injector/bulk.js)."""
import copy
import json
import os
import re

from sgstudio.injector.index import protect_site, safe_name
from sgstudio.injector.report import render_protect_text, render_login_text, render_protect_bulk
from sgstudio.scanner import util as _scanner_util

_SKIP_DIRS = getattr(_scanner_util, 'SKIP_DIRS', None) or {'node_modules', '.git', '.svn', '.hg', '__MACOSX', '.idea', '.vscode'}

_FORMULA = re.compile(r'^[=+\-@\t\r]')


def _csv_cell(v):
    s = '' if v is None else str(v)
    safe = "'" + s if _FORMULA.match(s) else s
    if re.search(r'[",\n]', safe):
        return '"' + safe.replace('"', '""') + '"'
    return safe


def _raw_cell(v):
    # passwords are written verbatim (an apostrophe prefix would corrupt them); generated ones never start with a symbol
    s = str(v)
    return '"' + s.replace('"', '""') + '"' if re.search(r'[",\n]', s) else s


def _write(path, text, mode=None):
    data = text.encode('utf-8')
    if mode is None:
        with open(path, 'wb') as fh:
            fh.write(data)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)


def _json(o):
    return json.dumps(o, indent=2, ensure_ascii=False)


def write_site_reports(r, out_dir):
    """Write report.txt / report.json (+ PRIVATE-login.txt) for one site next to its zips."""
    outputs = r.get('outputs') or {}
    d = outputs['dir'] if outputs.get('dir') else os.path.join(out_dir, safe_name(r['site']['name']))
    os.makedirs(d, exist_ok=True)
    pub = copy.deepcopy(r)
    if pub.get('login'):
        pub['login'].pop('password', None)  # the password lives only in PRIVATE-login.txt
    _write(os.path.join(d, 'report.txt'), render_protect_text(r))
    _write(os.path.join(d, 'report.json'), _json(pub))
    login = render_login_text(r)
    if login:
        _write(os.path.join(d, 'PRIVATE-login.txt'), login, 0o600)
    return d


def _name_key(n):
    # close to ICU localeCompare for plain names: case-insensitive, '_' before '-'
    return (n.lower().replace('_', '\x01').replace('-', '\x02'), n.swapcase())


def protect_many(parent, opts=None):
    """Every sub-folder / .zip in `parent` is one site. One failure never stops the rest."""
    opts = dict(opts or {})
    abs_ = os.path.abspath(parent)
    items = []
    for e in os.scandir(abs_):
        if e.name.startswith('.') or e.name in _SKIP_DIRS:
            continue
        if e.is_dir():
            items.append({'name': e.name, 'input': os.path.join(abs_, e.name)})
        elif e.is_file() and re.search(r'\.zip$', e.name, re.I):
            items.append({'name': re.sub(r'\.zip$', '', e.name, flags=re.I), 'input': os.path.join(abs_, e.name)})
    items.sort(key=lambda it: _name_key(it['name']))
    if not items:
        raise Exception('Is folder mein koi site folder ya .zip nahi mila: %s' % parent)
    if not opts.get('outDir'):
        raise TypeError('outDir is required')
    out_abs = os.path.abspath(opts['outDir'])
    if out_abs == abs_ or out_abs.startswith(abs_ + os.sep):
        raise Exception('Output folder sites wale folder ke andar nahi ho sakta.')
    on_progress = opts.get('onProgress')
    rows = []
    creds = []
    used = set()
    for i, it in enumerate(items):
        n = safe_name(it['name'])
        k = 2
        while n.lower() in used:
            n = safe_name(it['name']) + '_' + str(k)
            k += 1
        used.add(n.lower())
        try:
            o = dict(opts)
            o.pop('onProgress', None)
            o.update({'name': n, 'siteId': n, 'sqlFiles': None})
            r = protect_site(it['input'], o)
            if not opts.get('dryRun'):
                write_site_reports(r, out_abs)
            s = r['summary']
            hub = r.get('hub')
            row = {
                'name': n, 'status': r['status'], 'protectedForms': s['protected'],
                'openForms': s['needsReview'] + s['manual'] + s['failed'], 'filesChanged': s['filesChanged'],
                'hub': hub['status'] if hub else '',
                'error': 'Hub: ' + str(hub.get('error')) if hub and hub['status'] == 'failed' else '',
            }
            if r.get('login'):
                creds.append({'site': n, 'adminPath': r['login']['adminPath'], 'password': r['login']['password'], 'selftestPath': r['login']['selftestPath']})
        except Exception as e:
            row = {'name': n, 'status': 'failed', 'protectedForms': 0, 'openForms': 0, 'filesChanged': 0, 'error': str(e)}
        rows.append(row)
        if callable(on_progress):
            on_progress({'done': i + 1, 'total': len(items), 'name': n, 'status': row['status']})

    def cnt(st):
        return sum(1 for r in rows if r['status'] == st)

    bulk = {
        'totals': {
            'sites': len(rows),
            'protected': cnt('protected'),
            'partial': cnt('partial'),
            'already': cnt('already-protected'),
            'failed': cnt('failed'),
            'untouched': sum(1 for r in rows if r['status'] in ('manual-only', 'nothing-to-do', 'no-forms')),
            'formsProtected': sum(r['protectedForms'] for r in rows),
            'formsOpen': sum(r['openForms'] for r in rows),
        },
        'rows': rows,
    }
    if not opts.get('dryRun'):
        os.makedirs(out_abs, exist_ok=True)
        cols = ['name', 'status', 'protectedForms', 'openForms', 'filesChanged', 'hub', 'error']
        lines = [','.join(cols)] + [','.join(_csv_cell(r.get(c)) for c in cols) for r in rows]
        _write(os.path.join(out_abs, 'summary.csv'), '﻿' + '\n'.join(lines) + '\n')
        _write(os.path.join(out_abs, 'summary.json'), _json(bulk))
        _write(os.path.join(out_abs, 'report.txt'), render_protect_bulk(bulk))
        if creds:
            c = ['site', 'adminPath', 'password', 'selftestPath']
            lines = [','.join(c)] + [','.join((_raw_cell(r[k]) if k == 'password' else _csv_cell(r[k])) for k in c) for r in creds]
            _write(os.path.join(out_abs, 'PRIVATE-credentials.csv'), '﻿' + '\n'.join(lines) + '\n', 0o600)
    return bulk
