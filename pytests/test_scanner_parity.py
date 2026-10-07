"""Tests for sgstudio.scanner / sgstudio.config: differential tests against the original Node scanner.

pytests/dump_scan.js builds the fixture sites of test/helpers.js, scans them (as folders AND as zips) with the
Node scanner and dumps the results. The Python scanner must give the SAME JSON and the SAME text report.
These parity tests are skipped when `node` (or node_modules) is not available; everything else runs
with plain Python.

Run:  python3 -m unittest discover -s pytests -v
"""
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sgstudio import config as sg_config  # noqa: E402
from sgstudio import scanner  # noqa: E402
from sgstudio.scanner import bulk as sg_bulk  # noqa: E402
from sgstudio.scanner import forms as sg_forms  # noqa: E402
from sgstudio.scanner import index as sg_index  # noqa: E402
from sgstudio.scanner import util as sg_util  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
HAS_NODE = shutil.which('node') is not None and os.path.isdir(os.path.join(ROOT, 'node_modules'))
HAS_PHP = shutil.which('php') is not None
needs_node = unittest.skipUnless(HAS_NODE, 'node + node_modules needed for parity tests')


def load(path):
    with open(path, encoding='utf-8') as fh:
        return json.load(fh)


def read(path):
    with open(path, encoding='utf-8', newline='') as fh:
        return fh.read()


def norm(report):
    """JSON round trip + drop the two fields that change from run to run."""
    r = json.loads(json.dumps(report))
    r['scanner'].pop('scannedAt', None)
    r['scanner'].pop('durationMs', None)
    return r


def deep_diff(a, b, path=''):
    """First differences between two JSON-like values (for readable failures)."""
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append('%s/%s only in python: %r' % (path, k, b[k]))
            elif k not in b:
                out.append('%s/%s only in node: %r' % (path, k, a[k]))
            else:
                out.extend(deep_diff(a[k], b[k], path + '/' + k))
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append('%s length node=%d python=%d' % (path, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            out.extend(deep_diff(x, y, '%s[%d]' % (path, i)))
    elif a != b or type(a) is not type(b):
        out.append('%s node=%r python=%r' % (path, a, b))
    return out[:8]


class ParityBase(unittest.TestCase):
    out = None  # directory made by dump_scan.js

    @classmethod
    def setUpClass(cls):
        if not HAS_NODE:
            raise unittest.SkipTest('node not available')
        cls.out = ParityBase.out
        if cls.out is None:
            tmp = tempfile.mkdtemp(prefix='sg-parity-')
            r = subprocess.run(['node', os.path.join(HERE, 'dump_scan.js'), 'build', tmp], capture_output=True, text=True, cwd=ROOT)
            if r.returncode != 0:
                shutil.rmtree(tmp, ignore_errors=True)
                raise RuntimeError('dump_scan.js failed:\n' + r.stderr)
            ParityBase.out = cls.out = tmp
            unittest.addModuleCleanup(shutil.rmtree, tmp, True)

    def exp(self, name):
        return os.path.join(self.out, 'expected', name)


@needs_node
class TestSiteParity(ParityBase):
    def names(self):
        return load(os.path.join(self.out, 'names.json'))

    def test_fixture_list_not_empty(self):
        self.assertGreaterEqual(len(self.names()), 12)

    def check(self, label, src, expected_json, expected_txt=None):
        rep = scanner.scan_site(src)
        d = deep_diff(load(expected_json), norm(rep))
        self.assertEqual(d, [], label)
        if expected_txt:
            self.assertEqual(read(expected_txt), scanner.render_text(rep), label + ' (text report)')

    def test_folders(self):
        for n in self.names():
            with self.subTest(site=n):
                self.check(n, os.path.join(self.out, 'sites', n), self.exp(n + '.folder.json'), self.exp(n + '.folder.txt'))

    def test_zips_with_mac_wrapper(self):
        for n in self.names():
            with self.subTest(site=n):
                self.check(n, os.path.join(self.out, 'zips', n + '.zip'), self.exp(n + '.zip.json'), self.exp(n + '.zip.txt'))

    def test_zips_without_wrapper(self):
        for n in self.names():
            with self.subTest(site=n):
                self.check(n, os.path.join(self.out, 'zips', n + '.flat.zip'), self.exp(n + '.flat.json'))

    def test_report_is_json_serialisable_with_expected_shape(self):
        rep = scanner.scan_site(os.path.join(self.out, 'sites', 'acme-dental'))
        json.dumps(rep)
        self.assertEqual(rep['site']['name'], 'acme-dental')
        self.assertEqual(rep['forms'][0]['plan']['status'], 'auto')
        self.assertTrue(rep['security']['exposedFiles'])
        self.assertTrue(rep['contacts']['phones'])
        self.assertTrue(rep['database']['used'])
        self.assertIn('summary', rep)

    def test_odd_inputs_and_hostile_zip(self):
        exp = load(self.exp('odd.json'))
        odd = os.path.join(self.out, 'odd')
        files = {'evil': 'evil.zip', 'junk': 'only-junk.zip', 'txt': 'x.txt', 'garbage': 'garbage.zip', 'empty': 'empty.zip', 'missing': 'nope', 'nodir': 'nodir'}
        for key, fn in files.items():
            with self.subTest(case=key):
                e = exp[key]
                try:
                    rep = scanner.scan_site(os.path.join(odd, fn))
                except Exception as ex:  # noqa: BLE001
                    self.assertIn('error', e, 'python raised %r but node scanned it' % ex)
                    msg = str(ex.args[0] if ex.args else ex)
                    self.assertEqual(e['error'], msg)
                else:
                    self.assertIn('ok', e, 'python scanned it but node raised %r' % e.get('error'))
                    self.assertEqual(deep_diff(e['ok'], norm(rep)), [])
                    if key == 'evil':
                        self.assertEqual(read(self.exp('odd-evil.txt')), scanner.render_text(rep))

    def test_zip_slip_nothing_written_outside(self):
        before = set(os.listdir(tempfile.gettempdir()))
        scanner.scan_site(os.path.join(self.out, 'odd', 'evil.zip'))
        after = set(os.listdir(tempfile.gettempdir()))
        self.assertEqual([n for n in after - before if n.startswith('sgevil')], [])
        # and the temp folder made for the zip is gone again
        self.assertEqual([n for n in after - before if n.startswith('sg-scan-')], [])
        rep = scanner.scan_site(os.path.join(self.out, 'odd', 'evil.zip'))
        codes = [w['code'] for w in rep['warnings']]
        self.assertGreaterEqual(codes.count('zip-unsafe-path'), 4)
        self.assertIn('zip-symlink-skipped', codes)

    def test_external_sql_files(self):
        sqlx = os.path.join(self.out, 'sqlx')
        files = [os.path.join(sqlx, x) for x in ('plain.sql', 'packed.sql.gz', 'cut.sql.gz', 'bad.sql.gz', 'missing.sql')]
        rep = scanner.scan_site(os.path.join(self.out, 'sites', 'acme-dental'), sql_files=files)
        self.assertEqual(deep_diff(load(self.exp('sqlx.json')), norm(rep)), [])
        self.assertEqual(read(self.exp('sqlx.txt')), scanner.render_text(rep))


@needs_node
class TestBulkParity(ParityBase):
    def test_scan_many_matches_node(self):
        exp = load(self.exp('bulk.json'))
        seen = []
        b = scanner.bulk.scan_many(os.path.join(self.out, 'bulk'), on_progress=seen.append)
        self.assertEqual(exp['progress'], seen)
        self.assertEqual(exp['parent'], b['parent'])
        self.assertEqual(exp['warnings'], b['warnings'])
        self.assertEqual(exp['totals'], b['totals'])
        self.assertEqual(exp['rows'], b['rows'])
        self.assertEqual([r['name'] for r in exp['results']], [r['name'] for r in b['results']])
        for e, r in zip(exp['results'], b['results']):
            with self.subTest(site=e['name']):
                self.assertEqual(e['input'], r['input'])
                self.assertEqual(e['status'], r['status'])
                if e['report'] is None:
                    self.assertIsNone(r['report'])
                    self.assertEqual(e['error'], r['error'])
                else:
                    self.assertEqual(deep_diff(e['report'], norm(r['report'])), [])
        self.assertEqual(read(self.exp('bulk.txt')), scanner.render_bulk_text(b))
        self.assertEqual(b['totals']['sites'], 11)
        self.assertEqual(b['totals']['failed'], 1)

    def test_write_bulk_outputs_files_match_node(self):
        b = scanner.bulk.scan_many(os.path.join(self.out, 'bulk'))
        dest = tempfile.mkdtemp(prefix='sg-bulkout-')
        self.addCleanup(shutil.rmtree, dest, True)
        scanner.bulk.write_bulk_outputs(b, dest)
        ref = os.path.join(self.out, 'bulk-js-out')

        def listing(base):
            return sorted(os.path.relpath(os.path.join(d, f), base) for d, _, fs in os.walk(base) for f in fs)

        self.assertEqual(listing(ref), listing(dest))
        stamp = re.compile(r'"(scannedAt|durationMs)": [^\n]*\n')
        for rel in listing(ref):
            with self.subTest(file=rel):
                a, c = read(os.path.join(ref, rel)), read(os.path.join(dest, rel))
                if rel.endswith('.json') and rel.startswith('reports'):
                    a, c = stamp.sub('', a), stamp.sub('', c)
                elif rel.endswith('.txt') and rel.startswith('reports'):
                    pass
                self.assertEqual(a, c)
        csv = read(os.path.join(dest, 'summary.csv'))
        self.assertTrue(csv.startswith('﻿'))
        self.assertIn("'=evil", csv)
        self.assertNotRegex(csv, r'(?m)^=evil|,=evil,')

    def test_single_site_folder_warns(self):
        exp = load(self.exp('bulk-single.json'))
        b = scanner.bulk.scan_many(os.path.join(self.out, 'sites', 'acme-dental'))
        self.assertEqual(exp['warnings'], b['warnings'])
        self.assertEqual(exp['totals'], b['totals'])
        self.assertEqual(exp['rows'], b['rows'])
        self.assertTrue(any(w['code'] == 'parent-looks-like-site' for w in b['warnings']))

    def test_bulk_errors(self):
        exp = load(self.exp('bulk-errors.json'))
        for key, path in (('missing', os.path.join(self.out, 'sqlx', 'nonexistent')), ('empty', os.path.join(self.out, 'emptyparent'))):
            with self.assertRaises(Exception) as cm:
                scanner.bulk.scan_many(path)
            self.assertEqual(exp[key], str(cm.exception.args[0]))


@needs_node
class TestParseHtmlParity(ParityBase):
    CASES = [
        '<form action="x.php" method="post"><input name="email"><textarea name="m"></textarea><button>Go</button></form>',
        '<table><form action="a.php"><tr><td><input name="email"></td></tr></form></table>',
        '<form><form><input name="a"></form></form>',
        '<noscript><form action="n.php"><input name=email></form></noscript><form id=a action=b.php><input name=email>',
        '<FORM ACTION="X.PHP" METHOD=POST ENCTYPE="multipart/form-data"><INPUT TYPE=FILE NAME=f><INPUT TYPE=submit VALUE="  Send   now "></FORM>',
        '<div><p>one<p>two<form action=c.php><select name=s><option>1</select><input type=hidden name=csrf_token></form>',
        '<html><head><title>T {{PHP}}</title><meta name="Description" content=" hi  there "><link rel="CANONICAL" href="/x"></head><body><h1>H</h1><img src=a><img src=b alt=""></body></html>',
        '<script>var a = "<form>";</script><form action="s.php"><input name="honeypot"><input name="sg_t"><button type="submit">  Hi </button></form>',
        '<form action="{{PHP}}"><input name=tel><input type=email name=e></form>',
        '<form action="https://hooks.zapier.com/x"><div class="g-recaptcha"></div><input name=email></form>',
        '<svg><form><input name=x></form></svg><math><mi><form></form></mi></math>',
        '<template><form action=t.php><input name=email></form></template>',
        '<form action=a.php>\n<input name=email value="a&\nb">\n<textarea name=m>&\n</textarea>\n</form>\n<form action=b.php></form',
        '<!-- <form action="c.php"> --><form action="d.php"><input name="q"></form><b><form><i></b></i></form>',
        '<script type="application/ld+json">{}</script><script src="a.js"></script><script>\n\n  x();\n</script><body><body>a</body></html>',
        '﻿<!doctype html><html lang=" EN "><body class=x><form method=get action=search.php><input name=q></form>',
        '<form id="x" action="a.php"><button type="button">no</button><input type=submit value=ok><button>last</button></form><form action=z><button name=b>B</button></form>',
        '<p>café \U0001F600 <form action="ü.php"><input name="n\U0001F600"></form> \U0001F600\n<form></form>',
        '',
        '<',
        '<form',
        '<form action="a',
        '<form action=a.php><input name=email><!--',
        '<frameset><form></form></frameset>',
        '<select><form></form></select><form action="in-select.php"></form>',
        '<a href=x><form action=in-a.php><a href=y>q</a></form></a>',
        '<textarea><form action=hid.php></textarea><title><form></title><style><form></style>',
        '<form action="a.php"><fieldset><legend>L</legend><label>Name <input name=name></label><input name="Phone Number"><input type=tel name=m></fieldset></form>',
    ]

    def test_cases(self):
        tmp = tempfile.mkdtemp(prefix='sg-html-')
        self.addCleanup(shutil.rmtree, tmp, True)
        cases = [['page%d.html' % i, h] for i, h in enumerate(self.CASES)]
        # also every real page of the fixtures, raw and with PHP masked the way the scanner does
        sites = os.path.join(self.out, 'sites')
        for d, _, fs in os.walk(sites):
            for f in sorted(fs):
                if f.endswith(('.html', '.php', '.htm')):
                    txt = read(os.path.join(d, f))
                    cases.append([f, txt])
                    cases.append([f, scanner.index.split_php(txt)['html']])
        cf = os.path.join(tmp, 'cases.json')
        of = os.path.join(tmp, 'out.json')
        with open(cf, 'w', encoding='utf-8') as fh:
            json.dump(cases, fh)
        r = subprocess.run(['node', os.path.join(HERE, 'dump_scan.js'), 'html', cf, of], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)
        expected = load(of)
        self.assertEqual(len(expected), len(cases))
        for (rel, h), e in zip(cases, expected):
            with self.subTest(rel=rel, html=h[:60]):
                got = json.loads(json.dumps(sg_forms.parse_html(rel, sg_util.to16(h)), ensure_ascii=False))
                got = sg_util.from16_deep(got)
                for f in got['forms']:  # JS `undefined` is dropped by JSON; Python keeps None
                    if f['attrs']['action'] is None:
                        del f['attrs']['action']
                self.assertEqual(deep_diff(e, got), [])


@needs_node
class TestHelpersAgainstNode(unittest.TestCase):
    """Small JS behaviours that the port has to imitate."""

    def node_eval(self, code, data):
        r = subprocess.run(['node', '-e', code], input=json.dumps(data), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_url_pathname(self):
        urls = [
            'http://example.com/a/b.php', 'https://example.com', 'https://example.com/', 'HTTP://Example.com/X/../y.php?q=1#z',
            '//cdn.example.com/p/q.php', 'https://example.com:8080/a b/c.php', 'https://example.com/a/./b/../c.php',
            'https://example.com/a%2e%2e/b', 'https://example.com/%2e%2E/x.php', 'https://example.com\\a\\b.php',
            'https:////example.com//a//b.php', 'http://user:pw@example.com/p.php', 'http://example.com:99999/x',
            'http://example.com:abc/x', 'http:///x.php', 'https://exa mple.com/x', 'https://example.com/café/ü.php',
            'https://example.com/a?b/../c', 'https://example.com/a/..', 'https://example.com/a/.', 'https://example.com/{x}/`y`/"z"',
            'https://[::1]/x.php', 'https://example.com/\U0001F600.php', 'https://exa<mple.com/', 'https://example.com/%zz',
        ]
        exp = self.node_eval(
            "const u=JSON.parse(require('fs').readFileSync(0,'utf8'));"
            "console.log(JSON.stringify(u.map(s=>{try{return new URL(s.startsWith('//')?'https:'+s:s).pathname}catch(e){return null}})))",
            urls)
        got = [sg_index.url_pathname('https:' + u if u.startswith('//') else u) for u in urls]
        for u, e, g in zip(urls, exp, got):
            with self.subTest(url=u):
                self.assertEqual(e, g)

    def test_locale_compare_order(self):
        names = ['acme-dental', 'Acme-Dental2', 'alpha_site', 'Zeta Site', '=evil', 'broken', 'wp-site', 'self-post', 'Self Post', 'site2', 'site10', 'site1',
                 'B', 'a', 'A', 'b', '_x', '-y', 'café', 'cafe', 'cafz', '1abc', 'abc1', 'Abc', 'abc', 'x.y', 'x_y', 'x-y', 'x y', 'xy']
        exp = self.node_eval(
            "const n=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(JSON.stringify(n.slice().sort((a,b)=>a.localeCompare(b))))", names)
        got = sorted(names, key=sg_bulk.locale_key)
        self.assertEqual(exp, got)

    def test_js_regex_translation(self):
        cases = [
            (r'^a.c$', '', ['abc', 'a\nc', 'a c', 'abc\n']),
            (r'^a.c$', 'm', ['x\nabc\ny', 'abc\r\nq']),
            (r'\s+', 'g', ['  ﻿ x', '᠎x', '\u0085x']),
            (r'\w+', 'g', ['café x_1']),
            (r'a$', '', ['a\n', 'a']),
            (r'[^\s]+', 'g', ['ab   cd']),
            (r'\bfoo\b', 'gi', ['Foo éfoo']),
        ]
        for src, flags, texts in cases:
            exp = self.node_eval(
                "const [s,f,t]=JSON.parse(require('fs').readFileSync(0,'utf8'));"
                "console.log(JSON.stringify(t.map(x=>{const r=new RegExp(s,f.includes('g')?f:f+'g');return [...x.matchAll(r)].map(m=>[m.index,m[0]])})))",
                [src, flags, texts])
            rx = sg_util.rx(src, flags)
            for t, e in zip(texts, exp):
                got = [[m.start(), m.group()] for m in rx.finditer(sg_util.to16(t))]
                with self.subTest(src=src, flags=flags, text=t):
                    self.assertEqual(e, got)


class TestApi(unittest.TestCase):
    def test_exports(self):
        for name in ('scan_site', 'render_text', 'render_bulk_text', 'REASON', 'KIND', 'scan_many', 'write_bulk_outputs', 'prepare_input', 'SKIP_FILE', 'SKIP_DIRS'):
            self.assertTrue(hasattr(scanner, name), name)
        self.assertIsInstance(scanner.util.SKIP_DIRS, set)
        self.assertIn('node_modules', scanner.util.SKIP_DIRS)
        self.assertIs(scanner.SKIP_DIRS, scanner.util.SKIP_DIRS)
        self.assertTrue(scanner.SKIP_FILE.search('.DS_Store') and scanner.SKIP_FILE.search('._x') and not scanner.SKIP_FILE.search('index.html'))
        self.assertEqual(scanner.REASON['cms']({'cms': 'WordPress'}).split(' ')[0], 'WordPress')
        for code, fn in scanner.REASON.items():
            self.assertTrue(callable(fn), code)
        self.assertEqual(scanner.KIND['callback'], 'call-back')

    def test_reason_codes_cover_every_plan_reason(self):
        src = read(os.path.join(ROOT, 'sgstudio', 'scanner', 'plan.py'))
        used = set(re.findall(r"_r\('([a-z-]+)'", src))
        self.assertTrue(used)
        self.assertEqual(sorted(used - set(scanner.REASON)), [])

    def test_prepare_input_context_manager(self):
        d = tempfile.mkdtemp(prefix='sg-pi-')
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, 'index.html'), 'w') as fh:
            fh.write('<html><body><h1>hello hello hello</h1></body></html>')
        zp = os.path.join(d, 'site.zip')
        with zipfile.ZipFile(zp, 'w') as z:
            z.writestr('wrap/index.html', '<html><body><h1>hello hello hello</h1></body></html>')
            z.writestr('__MACOSX/wrap/._index.html', 'junk')
        with scanner.prepare_input(zp) as li:
            self.assertEqual(li.source, 'zip')
            self.assertEqual(li['rootRel'], 'wrap')
            self.assertEqual(li.name, 'site')
            root = li.root
            self.assertTrue(os.path.isfile(os.path.join(root, 'index.html')))
        self.assertFalse(os.path.exists(root))
        li = scanner.prepare_input(d)
        self.assertEqual((li.source, li.rootRel), ('folder', ''))
        li.cleanup()
        self.assertTrue(os.path.isdir(d))

    def test_symlinks_are_not_followed(self):
        d = tempfile.mkdtemp(prefix='sg-sym-')
        self.addCleanup(shutil.rmtree, d, True)
        outside = tempfile.mkdtemp(prefix='sg-outside-')
        self.addCleanup(shutil.rmtree, outside, True)
        with open(os.path.join(outside, 'secret.php'), 'w') as fh:
            fh.write('<?php echo "x";')
        with open(os.path.join(d, 'index.html'), 'w') as fh:
            fh.write('<html><body><h1>hello hello hello</h1></body></html>')
        os.symlink(outside, os.path.join(d, 'linked'))
        os.symlink(os.path.join(outside, 'secret.php'), os.path.join(d, 'link.php'))
        rep = scanner.scan_site(d)
        self.assertEqual(rep['site']['files'], 1)
        self.assertEqual(rep['site']['phpFiles'], 0)

    def test_zip_with_traversal_written_by_python_zipfile(self):
        d = tempfile.mkdtemp(prefix='sg-zs-')
        self.addCleanup(shutil.rmtree, d, True)
        zp = os.path.join(d, 'evil.zip')
        with zipfile.ZipFile(zp, 'w') as z:
            z.writestr('../escape.txt', 'x')
            z.writestr('ok/index.html', '<html><body><h1>fine fine fine</h1></body></html>')
        rep = scanner.scan_site(zp)
        self.assertEqual(rep['site']['files'], 1)
        self.assertEqual([w['code'] for w in rep['warnings'] if w['code'].startswith('zip-')], ['zip-unsafe-path'])
        self.assertFalse(os.path.exists(os.path.join(d, 'escape.txt')))

    def test_zip_bomb_limit(self):
        d = tempfile.mkdtemp(prefix='sg-zb-')
        self.addCleanup(shutil.rmtree, d, True)
        zp = os.path.join(d, 'many.zip')
        old = dict(sg_util.LIMITS)
        try:
            sg_util.LIMITS['maxZipEntries'] = 3
            with zipfile.ZipFile(zp, 'w') as z:
                for i in range(5):
                    z.writestr('f%d.txt' % i, 'x')
            with self.assertRaises(Exception) as cm:
                scanner.scan_site(zp)
            self.assertIn('bahut zyada files', str(cm.exception))
            sg_util.LIMITS['maxZipEntries'] = 100
            sg_util.LIMITS['maxZipTotalBytes'] = 10
            with zipfile.ZipFile(zp, 'w') as z:
                z.writestr('a.txt', 'x' * 6)
                z.writestr('b.txt', 'x' * 6)
            with self.assertRaises(Exception) as cm:
                scanner.scan_site(zp)
            self.assertIn('zip bomb', str(cm.exception))
            # one file over the per-file limit is skipped with a warning, the rest is scanned
            sg_util.LIMITS['maxZipTotalBytes'] = old['maxZipTotalBytes']
            sg_util.LIMITS['maxZipFileBytes'] = 4
            with zipfile.ZipFile(zp, 'w') as z:
                z.writestr('big.txt', 'x' * 6)
                z.writestr('a.txt', 'x')
            rep = scanner.scan_site(zp)
        finally:
            sg_util.LIMITS.update(old)
        self.assertEqual([w['file'] for w in rep['warnings'] if w['code'] == 'zip-file-too-large'], ['big.txt'])
        self.assertEqual(rep['site']['files'], 1)


class TestPortability(unittest.TestCase):
    """The scanner has to run on Python 3.9 with the standard library only."""

    def py_files(self):
        for base in ('sgstudio',):
            for d, _, fs in os.walk(os.path.join(ROOT, base)):
                for f in fs:
                    if f.endswith('.py'):
                        yield os.path.join(d, f)

    def test_parses_as_python_39(self):
        for p in self.py_files():
            with self.subTest(file=os.path.relpath(p, ROOT)):
                ast.parse(read(p), filename=p, feature_version=(3, 9))

    def test_no_match_statements_or_union_annotations_at_runtime(self):
        for p in self.py_files():
            src = read(p)
            tree = ast.parse(src)
            for node in ast.walk(tree):
                self.assertFalse(type(node).__name__ == 'Match', p)
            self.assertNotRegex(src, r'(?m)^\s*match\s+\S+.*:\s*$', p) if 'scanner' in p else None

    def test_only_stdlib_imports(self):
        std = getattr(sys, 'stdlib_module_names', None)
        if std is None:
            self.skipTest('needs Python 3.10+ to list the standard library')
        for p in self.py_files():
            tree = ast.parse(read(p))
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    mods = [node.module]
                for m in mods:
                    top = m.split('.')[0]
                    self.assertTrue(top in std or top == 'sgstudio', '%s imports %s' % (p, m))


class TestConfig(unittest.TestCase):
    def test_php_lit_valid_php_for_tricky_values(self):
        if not HAS_PHP:
            self.skipTest('php not installed')
        value = {'a': "it's a \\ \"quote\" $notvar {$x}", 'b': [1, 2.5, True, False, None], 'c': {'d': 'हिन्दी ✓', 'e': ''}}
        r = subprocess.run(['php', '-r', 'echo json_encode(%s, JSON_UNESCAPED_UNICODE);' % sg_config.php_lit(value)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), value)

    def test_refuses_weak_password_and_overwrite(self):
        with self.assertRaisesRegex(Exception, '8 characters'):
            sg_config.generate_config({'password': 'short'})
        d = tempfile.mkdtemp(prefix='sg-cfg-')
        self.addCleanup(shutil.rmtree, d, True)
        f = os.path.join(d, 'cfg-overwrite', 'config.php')
        sg_config.write_config(f, {'siteId': 'x'})
        with self.assertRaisesRegex(Exception, 'pehle se hai'):
            sg_config.write_config(f, {'siteId': 'x'})
        sg_config.write_config(f, {'siteId': 'x', 'force': True})

    def test_generated_shape(self):
        g = sg_config.generate_config({'siteId': 'My Site!!', 'notifyEmail': 'a@b.in', 'turnstile': {'siteKey': 'k', 'secret': 's'}, 'success': {'redirect': 'ty.html'}})
        self.assertEqual(g['siteId'], 'My-Site-')
        self.assertTrue(g['generatedPassword'])
        self.assertEqual(len(g['password']), 16)
        self.assertEqual(sorted(g), sorted(['php', 'password', 'generatedPassword', 'selftestKey', 'dataDirName', 'siteId']))
        self.assertIn("'redirect' => 'ty.html'", g['php'])
        self.assertIn("'enabled' => true", g['php'])
        self.assertRegex(g['php'], r"'admin_password_hash' => 'pbkdf2\$\d+\$[0-9a-f]{32}\$[0-9a-f]{64}'")
        self.assertIn("__DIR__ . '/" + g['dataDirName'] + "'", g['php'])

    def test_config_php_works_with_real_php_kit(self):
        if not HAS_PHP:
            self.skipTest('php not installed')
        kit = os.path.join(ROOT, 'kit', 'spamguard')
        if not os.path.isdir(kit):
            self.skipTest('kit not present')
        site = tempfile.mkdtemp(prefix='sg-cfgsite-')
        self.addCleanup(shutil.rmtree, site, True)
        shutil.copytree(kit, os.path.join(site, 'spamguard'))
        cfg = os.path.join(site, 'spamguard', 'config.php')
        if os.path.exists(cfg):
            os.remove(cfg)
        g = sg_config.write_config(cfg, {'siteId': 'Test Site', 'password': 'Test#Pass123', 'notifyEmail': 'o@x.in', 'quarantine': True})
        self.assertFalse(g['generatedPassword'])
        code = r'''
            require 'spamguard/spamguard.php';
            $c = SpamGuard::config();
            echo SpamGuard::verifyPassword('Test#Pass123', $c['admin_password_hash']) ? "PW_OK\n" : "PW_BAD\n";
            echo SpamGuard::verifyPassword('wrong', $c['admin_password_hash']) ? "WRONG_ACCEPTED\n" : "WRONG_REJECTED\n";
            echo strpos($c['data_dir'], __DIR__ . '/spamguard/sg-data-') === 0 ? "DIR_OK\n" : "DIR_BAD " . $c['data_dir'] . "\n";
            echo $c['suspicious_action'], "\n";
            $t = SpamGuard::makeToken(time() - 20);
            $r = SpamGuard::check(['name' => 'A', 'email' => 'a@gmail.com', 'message' => 'Hello I need a price list for your services please', 'sg_t' => $t, 'sg_i' => '5'], ['REMOTE_ADDR' => '1.2.3.4', 'HTTP_USER_AGENT' => 'Mozilla/5.0 Safari']);
            echo $r['status'], ' ', $r['logged'] ? "LOGGED" : "NOT_LOGGED", "\n";'''
        r = subprocess.run(['php', '-r', code], cwd=site, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn('PW_OK', r.stdout)
        self.assertIn('WRONG_REJECTED', r.stdout)
        self.assertIn('DIR_OK', r.stdout)
        self.assertIn('quarantine', r.stdout)
        self.assertRegex(r.stdout, r'real LOGGED')
        # the scanner recognises its own kit and does not scan it as customer forms
        with open(os.path.join(site, 'index.html'), 'w') as fh:
            fh.write('<html><body><h1>hello there</h1></body></html>')
        rep = scanner.scan_site(site)
        self.assertTrue(rep['site']['siteFiles']['spamguardInstalled'])
        self.assertEqual(len(rep['forms']), 0)


if __name__ == '__main__':
    unittest.main()
