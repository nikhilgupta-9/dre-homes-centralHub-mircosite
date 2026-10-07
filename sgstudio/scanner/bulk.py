"""Scan many sites in one go (port of bulk.js): every sub-folder and every .zip inside a folder is one site."""
import json
import os
import re
import unicodedata

from .index import scan_site
from .report import render_bulk_text, render_text
from .util import SKIP_DIRS, ScanError, rx

_ZIP_EXT = rx(r'\.zip$', 'i')
_INDEX_FILE = rx(r'^index\.(html?|php)$', 'i')
_LONE_SURROGATE = re.compile('[\ud800-\udfff]')
_NAME_JUNK = re.compile(r'[^A-Za-z0-9_.\-]+')
_CSV_FORMULA = re.compile(r'^[=+\-@\t\r]')
_CSV_QUOTE = re.compile(r'[",\n]')

# --------------------------------------------------------------------------- String.prototype.localeCompare (approximation of ICU "en")

_PUNCT_ORDER = '_-,;:!?.\'"()[]{}@*/\\&#%`^+<=>|~$'


def _collation_key(s):
    """Primary key: whitespace < punctuation < digits < letters, case and accents ignored."""
    prim = []
    sec = []
    ter = []
    for ch in unicodedata.normalize('NFD', s):
        if unicodedata.combining(ch):
            sec.append(ord(ch))
            continue
        lo = ch.lower()
        if ch.isspace():
            prim.append((0, 0, ' '))
        elif ch in _PUNCT_ORDER:
            prim.append((1, _PUNCT_ORDER.index(ch), ''))
        elif ch.isdigit():
            prim.append((2, 0, ch))
        elif ch.isalpha():
            prim.append((3, 0, lo))
        else:
            prim.append((1, 100, lo))
        ter.append(0 if ch == lo else 1)  # lower case sorts before upper case
        sec.append(0)
    return (prim, sec, ter)


def locale_key(s):
    return _collation_key(s)


# --------------------------------------------------------------------------- scanning


def _row_of(name, status, report, error):
    if status == 'failed':
        return {'name': name, 'status': status, 'error': error}
    s = report['summary']
    return {
        'name': name,
        'status': status,
        'source': report['site']['source'],
        'platform': report['site']['platform'],
        'db': 'yes' if report['database']['used'] else 'no',
        'pages': s['pages'],
        'forms': s['forms'],
        'enquiryForms': s['enquiryForms'],
        'auto': s['auto'],
        'review': s['review'],
        'manual': s['manual'],
        'skip': s['skip'],
        'done': s['done'],
        'exposedFiles': s['exposedFiles'],
        'phones': len(report['contacts']['phones']),
        'emails': len(report['contacts']['emails']),
        'warnings': len(report['warnings']),
    }


def scan_many(parent_dir, on_progress=None, sql_files=None):
    """Scan every site folder / .zip inside parent_dir. A broken site never stops the batch (reported as "failed").

    on_progress({'done','total','name','status'}) is called after each site.
    """
    parent_dir = os.fspath(parent_dir)
    absp = os.path.abspath(parent_dir)
    try:
        with os.scandir(absp) as it:
            ents = sorted(it, key=lambda e: os.fsencode(e.name))
    except OSError:
        raise ScanError('Folder nahi khula: ' + parent_dir)
    items = []
    for e in ents:
        if e.name.startswith('.') or e.name in SKIP_DIRS:
            continue
        if e.is_dir(follow_symlinks=False):
            items.append({'name': e.name, 'input': os.path.join(absp, e.name)})
        elif e.is_file(follow_symlinks=False) and _ZIP_EXT.search(e.name):
            items.append({'name': _ZIP_EXT.sub('', e.name), 'input': os.path.join(absp, e.name)})
    items.sort(key=lambda it: locale_key(it['name']))
    if not items:
        raise ScanError('Is folder mein koi site folder ya .zip nahi mila: ' + parent_dir)
    looks_like_single_site = any(e.is_file(follow_symlinks=False) and _INDEX_FILE.search(e.name) for e in ents)

    results = []
    rows = []
    for i, it in enumerate(items):
        status = 'ok'
        report = None
        error = None
        try:
            report = scan_site(it['input'], sql_files)
            report['site']['name'] = it['name']
        except Exception as e:  # noqa: BLE001 - one bad site must never stop the batch
            status = 'failed'
            error = e.args[0] if isinstance(e, (ScanError, OSError)) and e.args and isinstance(e.args[0], str) else str(e)
        results.append({'name': it['name'], 'input': it['input'], 'status': status, 'report': report, 'error': error})
        rows.append(_row_of(it['name'], status, report, error))
        if on_progress:
            on_progress({'done': i + 1, 'total': len(items), 'name': it['name'], 'status': status})
    ok = [r for r in rows if r['status'] == 'ok']

    def total(k):
        return sum(r.get(k) or 0 for r in ok)

    return {
        'parent': absp,
        'warnings': [{'code': 'parent-looks-like-site', 'level': 'warn'}] if looks_like_single_site else [],
        'totals': {
            'sites': len(rows),
            'ok': len(ok),
            'failed': len(rows) - len(ok),
            'forms': total('enquiryForms'),
            'auto': total('auto'),
            'review': total('review'),
            'manual': total('manual'),
            'done': total('done'),
            'withDb': len([r for r in ok if r['db'] == 'yes']),
            'withExposed': len([r for r in ok if r['exposedFiles'] > 0]),
        },
        'rows': rows,
        'results': results,
    }


# --------------------------------------------------------------------------- output files


def json_stringify(v, indent=2):
    """JSON.stringify(v, null, 2): lone surrogates are escaped instead of written raw."""
    s = json.dumps(v, indent=indent, ensure_ascii=False)
    return _LONE_SURROGATE.sub(lambda m: '\\u%04x' % ord(m.group()), s)


def _csv_cell(v):
    if v is None:
        s = ''
    elif v is True:
        s = 'true'
    elif v is False:
        s = 'false'
    else:
        s = str(v)
    safe = "'" + s if _CSV_FORMULA.search(s) else s
    return '"' + safe.replace('"', '""') + '"' if _CSV_QUOTE.search(safe) else safe


def _write(path, text):
    with open(path, 'w', encoding='utf-8', errors='replace', newline='') as fh:
        fh.write(text)


def write_bulk_outputs(bulk, out_dir):
    """Write summary.csv, summary.json, report.txt, plus one json + txt report per site."""
    out_dir = os.fspath(out_dir)
    os.makedirs(os.path.join(out_dir, 'reports'), exist_ok=True)
    used = set()

    def file_for(name):
        base = _NAME_JUNK.sub('_', name)[:80] or 'site'
        n = base
        i = 2
        while n.lower() in used:
            n = '%s_%d' % (base, i)
            i += 1
        used.add(n.lower())
        return n

    for r in bulk['results']:
        f = file_for(r['name'])
        if r['report']:
            _write(os.path.join(out_dir, 'reports', f + '.json'), json_stringify(r['report']))
            _write(os.path.join(out_dir, 'reports', f + '.txt'), render_text(r['report']))
        else:
            _write(os.path.join(out_dir, 'reports', f + '.txt'), 'SITE: %s\nSCAN FAIL HUA: %s\n' % (r['name'], r['error']))
    cols = ['name', 'status', 'source', 'platform', 'db', 'pages', 'forms', 'enquiryForms', 'auto', 'review', 'manual', 'skip', 'done', 'exposedFiles', 'phones', 'emails', 'warnings', 'error']
    lines = [','.join(cols)] + [','.join(_csv_cell(r.get(c)) for c in cols) for r in bulk['rows']]
    _write(os.path.join(out_dir, 'summary.csv'), '﻿' + '\n'.join(lines) + '\n')
    _write(os.path.join(out_dir, 'summary.json'), json_stringify({'totals': bulk['totals'], 'rows': bulk['rows'], 'warnings': bulk['warnings']}))
    _write(os.path.join(out_dir, 'report.txt'), render_bulk_text(bulk))
    return out_dir
