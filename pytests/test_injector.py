"""Tests for sgstudio.injector / sgstudio.hub (ports of test/injector.test.js and the protect parts of
test/app-service.test.js), plus parity checks against the Node implementation when `node` is available.

Run:  python3 -m unittest discover -s pytests -v
"""
import copy
import hashlib
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sgstudio import hub as sg_hub  # noqa: E402
from sgstudio.injector import edits as E  # noqa: E402
from sgstudio.injector import protect_site  # noqa: E402
from sgstudio.injector.bulk import protect_many, write_site_reports  # noqa: E402
from sgstudio.injector.report import render_protect_text, STATUS_LINE, OUTCOME, ERR, WAHAN  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures', 'sites')
HAS_PHP = shutil.which('php') is not None
HAS_NODE = shutil.which('node') is not None and os.path.isdir(os.path.join(ROOT, 'node_modules'))

tmp = None
dirs = {}


def setUpModule():
    global tmp, dirs
    tmp = tempfile.mkdtemp(prefix='sg-pyinj-')
    sites = os.path.join(tmp, 'sites')
    shutil.copytree(FIXTURES, sites)
    dirs = {n: os.path.join(sites, n) for n in sorted(os.listdir(sites))}


def tearDownModule():
    shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ helpers
def tree_hash(d):
    h = hashlib.sha256()

    def walk(cur, rel):
        for name in sorted(os.listdir(cur)):
            p = os.path.join(cur, name)
            r = rel + '/' + name
            if os.path.isdir(p):
                walk(p, r)
            else:
                with open(p, 'rb') as fh:
                    h.update(r.encode()); h.update(fh.read())
    walk(d, '')
    return h.hexdigest()


def read(p, enc='latin1'):
    with open(p, 'rb') as fh:
        return fh.read().decode(enc)


def write(p, data):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'wb') as fh:
        fh.write(data if isinstance(data, bytes) else data.encode('utf-8'))


def unzip_to(z, dest):
    with zipfile.ZipFile(z) as zf:
        zf.extractall(dest)
    return dest


def zip_names(z):
    with zipfile.ZipFile(z) as zf:
        return zf.namelist()


def mac_zip(d, dest):
    """Zip a folder the way a Mac does: wrapper folder, __MACOSX junk, .DS_Store, ._ files."""
    wrap = os.path.basename(d) + '/'
    with zipfile.ZipFile(dest, 'w', zipfile.ZIP_STORED) as zf:
        for base, _dn, fns in os.walk(d):
            for fn in fns:
                p = os.path.join(base, fn)
                zf.write(p, wrap + os.path.relpath(p, d).replace(os.sep, '/'))
        zf.writestr('__MACOSX/' + wrap + '._index.html', bytes([0, 5, 22, 7, 0, 2]))
        zf.writestr(wrap + '.DS_Store', bytes([0, 0, 0, 1]))
    return dest


def strip_inserted(t):
    t = re.sub(r'<!-- SpamGuard --><script[^>]*></script>\r?\n', '', t)
    return re.sub(r'(?:\r?\n| )/\* SpamGuard:begin \*/.*?/\* SpamGuard:end \*/', '', t)


def php_lint(path):
    r = subprocess.run(['php', '-l', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return r.returncode == 0, (r.stdout + r.stderr).decode('utf-8', 'replace')


def all_php_files(d):
    for base, _dn, fns in os.walk(d):
        for fn in fns:
            if re.search(r'\.(php|phtml|inc)$', fn, re.I):
                yield os.path.join(base, fn)


SIMPLE_FORM = ('<html><head><title>x</title></head><body><form action="s.php" method="post"><input name="n">'
               '<input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form></body></html>')


# ------------------------------------------------------------------ pure edits
class PureEditsTest(unittest.TestCase):
    def test_guard_spot_plain_bom_crlf_strict_namespace(self):
        g = E.plan_guard_edit('<?php\n$a = 1;\n', 'inc', None)
        self.assertEqual(g['offset'], 5)
        self.assertRegex(g['insert'], r"^\n/\* SpamGuard:begin \*/ if \(is_file\(__DIR__ \. '/inc/spamguard/spamguard\.php'\)\)")
        bom = '\xEF\xBB\xBF<?php\r\n$a=1;'
        g = E.plan_guard_edit(bom, '', None)
        self.assertEqual(g['offset'], 8)
        self.assertTrue(g['insert'].startswith('\r\n'), 'keeps CRLF')
        strict = '<?php\ndeclare(strict_types=1);\nnamespace App\\Web;\n\nuse X;\n'
        g = E.plan_guard_edit(strict, '', None)
        self.assertEqual(strict[:g['offset']], '<?php\ndeclare(strict_types=1);\nnamespace App\\Web;')
        self.assertIn('\\SpamGuard::guard(', g['insert'])
        out = E.apply_insertions(strict, [g])
        self.assertLess(out.index('declare(strict_types=1)'), out.index('SpamGuard:begin'), 'declare stays first')

    def test_unsafe_files_are_refused(self):
        self.assertEqual(E.plan_guard_edit('<html>\n<?php echo 1;', '', None)['error'], 'php-not-at-top')
        self.assertEqual(E.plan_guard_edit('<? echo 1;', '', None)['error'], 'short-open-tag')
        self.assertEqual(E.plan_guard_edit('<?php\nnamespace A {\n}', '', None)['error'], 'bracketed-namespace')
        self.assertEqual(E.plan_guard_edit('just html', '', None)['error'], 'no-php')
        self.assertEqual(E.plan_guard_edit('<?php SpamGuard::guard();', '', None)['error'], 'already')

    def test_script_tag_placement(self):
        html = '<body>\n<form>\n</form>\n<?php if (1): ?>\n<p>x</p>\n<?php endif; ?>\n</body>'
        p = E.plan_script_edit(html, 3, '/spamguard/spamguard.js')
        self.assertEqual(p['offset'], html.index('<?php if'))
        inside = '<?php\nif (1) {\n echo "x";\n}\n?>\n</body>'
        q = E.plan_script_edit(inside, 3, '/spamguard/spamguard.js')
        self.assertGreater(q['offset'], inside.index('?>'), 'falls back to before </body>, outside PHP')
        self.assertEqual(E.plan_script_edit('<?php\nforeach($a as $b){\n', 2, '/s.js')['error'], 'script-position-unsafe')
        self.assertEqual(E.plan_script_edit('<script src="/spamguard/spamguard.js"></script>', 1, '/x')['error'], 'already')

    def test_override_literal_is_escaped_php(self):
        self.assertEqual(E.php_inline({'success': {'json': {'status': "it's", 'n': 1, 'ok': True}}}),
                         "['success' => ['json' => ['status' => 'it\\'s', 'n' => 1, 'ok' => true]]]")
        self.assertEqual(E.php_inline("a\\b'\nc"), "'a\\\\b\\' c'")
        self.assertEqual(E.php_inline(None), 'null')
        self.assertEqual(E.php_inline([1, 'a', False]), "[1, 'a', false]")

    def test_apply_insertions_round_trip_and_multiple_edits(self):
        t = 'abcdef'
        out = E.apply_insertions(t, [{'offset': 2, 'insert': 'XX'}, {'offset': 4, 'insert': 'Y'}, {'offset': 0, 'insert': 'Z'}])
        self.assertEqual(out, 'ZabXXcdYef')
        self.assertEqual(E.line_of_offset('a\nb\nc', 4), 3)

    def test_site_wide_hooks(self):
        def ap(t, rel=''):
            return E.plan_apply_edit(t, rel)

        def run(t, rel=''):
            p = ap(t, rel)
            self.assertFalse(p.get('error'), json.dumps(p))
            return E.apply_insertions(t, [p])
        out = run('<?php\n$a = 1;\n?><html><head></head></html>')
        self.assertRegex(out, r"^<\?php\n/\* SpamGuard:apply \*/ if \(is_file\(__DIR__ \. '/spamguard/sg-apply\.php'\)\) \{ require_once __DIR__ \. '/spamguard/sg-apply\.php'; \} /\* SpamGuard:apply-end \*/\n\$a = 1;")
        out = run('\xEF\xBB\xBF<?php\r\ndeclare(strict_types=1);\r\nnamespace App;\r\necho 1;\r\n')
        self.assertTrue(out.startswith('\xEF\xBB\xBF<?php\r\ndeclare(strict_types=1);\r\nnamespace App;\r\n/* SpamGuard:apply */'))
        out = run('<!doctype html>\n<html><head></head><body><?= $x ?></body></html>')
        self.assertRegex(out, r'^<\?php /\* SpamGuard:apply \*/.*\?>\n<!doctype html>\n')
        self.assertRegex(run('<html><head></head></html>', '../..'), r"__DIR__ \. '/\.\./\.\./spamguard/sg-apply\.php'")
        self.assertEqual(ap(out)['error'], 'already')
        self.assertEqual(ap('<?php namespace A { echo 1; }')['error'], 'bracketed-namespace')
        self.assertEqual(ap('<? echo 1; ?><html></html>')['error'], 'short-open-tag')
        self.assertEqual(ap('<html></html><?php declare(strict_types=1);')['error'], 'declare-after-html')
        j = E.plan_contact_script_edit('<html><body>x</body></html>', '/spamguard/contact.js')
        self.assertIn('x\n<!-- SpamGuard:contact --><script src="/spamguard/contact.js" defer></script>\n</body>',
                      E.apply_insertions('<html><body>x</body></html>', [j]))
        self.assertEqual(E.plan_contact_script_edit('<?php echo "</body>"; ?>', '/x.js')['error'], 'script-position-unsafe')
        self.assertEqual(E.plan_contact_script_edit('<html></html>', '/x.js')['error'], 'no-body')
        self.assertEqual(E.plan_contact_script_edit('<script src="/spamguard/contact.js"></script></body>', '/x.js')['error'], 'already')

    def test_latin1_whitespace_is_not_python_whitespace(self):
        # \x85 is whitespace for str.isspace() but not for JavaScript's \s
        t = '<?php\x85\n$a=1;'
        g = E.plan_guard_edit(t, '', None)
        self.assertEqual(g.get('error'), 'short-open-tag', 'same answer as the JS version (\\s does not match \\x85)')


# ------------------------------------------------------------------ whole-site protection
class ProtectSiteTest(unittest.TestCase):
    def test_protects_a_classic_site(self):
        before = tree_hash(dirs['acme-dental'])
        out = os.path.join(tmp, 'out-acme')
        r = protect_site(dirs['acme-dental'], {'outDir': out, 'password': 'Secret-pass-1'})
        write_site_reports(r, out)
        self.assertEqual(tree_hash(dirs['acme-dental']), before, 'input folder must stay byte-identical')
        self.assertEqual(r['status'], 'protected')
        self.assertEqual(r['summary']['protected'], 1)
        self.assertEqual(r['verification']['rescan']['formsProtectedAfter'], 1)
        self.assertTrue(r['kit']['installed'])
        prot = unzip_to(r['outputs']['protectedZip'], os.path.join(tmp, 'x-acme'))
        bak = unzip_to(r['outputs']['backupZip'], os.path.join(tmp, 'x-acme-bak'))
        self.assertEqual(tree_hash(bak), before, 'backup equals the original')
        self.assertTrue(os.path.exists(os.path.join(prot, 'spamguard', 'spamguard.php')))
        self.assertTrue(os.path.exists(os.path.join(prot, 'spamguard', 'config.php')))
        self.assertFalse(os.path.exists(os.path.join(prot, 'spamguard', 'tests')), 'tests are not shipped')
        for c in r['changes']:
            was = read(os.path.join(dirs['acme-dental'], c['file']))
            now = read(os.path.join(prot, c['file']))
            self.assertEqual(strip_inserted(now), was, c['file'] + ': removing the inserted text gives the original back')
        changed = {c['file'] for c in r['changes']}
        for f in os.listdir(dirs['acme-dental']):
            p = os.path.join(dirs['acme-dental'], f)
            if f in changed or os.path.isdir(p):
                continue
            self.assertEqual(read(os.path.join(prot, f)), read(p), f)
        txt = read(os.path.join(out, 'acme-dental', 'report.txt'), 'utf-8')
        self.assertIn('PROTECTED', txt)
        self.assertNotIn('Secret-pass-1', txt, 'password is not in the shareable report')
        self.assertNotIn('Secret-pass-1', read(os.path.join(out, 'acme-dental', 'report.json'), 'utf-8'))
        self.assertIn('Secret-pass-1', read(os.path.join(out, 'acme-dental', 'PRIVATE-login.txt'), 'utf-8'))
        cfg = read(os.path.join(prot, 'spamguard', 'config.php'), 'utf-8')
        self.assertIn('return [', cfg)
        self.assertNotIn('Secret-pass-1', cfg, 'only a hash of the password is stored')
        if os.name == 'posix':
            self.assertEqual(os.stat(os.path.join(out, 'acme-dental', 'PRIVATE-login.txt')).st_mode & 0o077, 0)

    def test_idempotent(self):
        out = os.path.join(tmp, 'out-idem')
        r1 = protect_site(dirs['quick-ajax'], {'outDir': out, 'keepFolder': True})
        self.assertEqual(r1['status'], 'protected')
        r2 = protect_site(r1['outputs']['folder'], {'outDir': os.path.join(tmp, 'out-idem2')})
        self.assertEqual(len(r2['changes']), 0)
        self.assertEqual(r2['status'], 'already-protected')
        self.assertEqual(r2['outputs'], {})

    def test_ajax_handler_copies_success_json(self):
        r = protect_site(dirs['quick-ajax'], {'dryRun': True})
        g = [c for c in r['changes'] if c['kind'] == 'guard-call'][0]
        self.assertRegex(g['text'], r"SpamGuard::guard\(\['success' => \['json' => \['status' => 'success'")

    def test_unhandled_forms_are_left_alone_and_explained(self):
        for n in ['external-forms', 'wp-site', 'php-generated']:
            r = protect_site(dirs[n], {'outDir': os.path.join(tmp, 'out-' + n)})
            self.assertEqual(r['status'], 'manual-only', n)
            self.assertEqual(len(r['changes']), 0, n)
            self.assertEqual(r['outputs'], {}, n + ': no zip is made when nothing changed')
            self.assertTrue(all(f['outcome'] in ('manual', 'skipped') for f in r['forms']))
        e = protect_site(dirs['empty-site'], {'dryRun': True})
        self.assertEqual(e['status'], 'no-forms')

    def test_review_forms_only_patched_when_asked(self):
        a = protect_site(dirs['fetch-unknown'], {'dryRun': True})
        self.assertEqual(len(a['changes']), 0)
        self.assertEqual(a['summary']['needsReview'], 1)
        b = protect_site(dirs['fetch-unknown'], {'dryRun': True, 'includeReview': True})
        self.assertGreaterEqual(len(b['changes']), 1)
        self.assertEqual(b['summary']['needsReview'], 0)

    def test_self_post_and_shared_include(self):
        s = protect_site(dirs['self-post'], {'dryRun': True})
        self.assertEqual(s['status'], 'protected')
        self.assertEqual(sorted(c['file'] for c in s['changes']), ['contact.php', 'contact.php'])
        inc = protect_site(dirs['include-form'], {'dryRun': True})
        self.assertEqual(inc['status'], 'protected')
        self.assertTrue(any(c['file'] == 'footer.php' and c['kind'] == 'script-tag' for c in inc['changes']))
        self.assertTrue(any(c['file'] == 'lead-handler.php' and c['kind'] == 'guard-call' for c in inc['changes']))

    def test_handler_in_subfolder_gets_relative_path(self):
        d = os.path.join(tmp, 'sub')
        write(os.path.join(d, 'index.html'), '<html><head><title>S</title></head><body><form action="forms/deep/send.php" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form></body></html>')
        write(os.path.join(d, 'forms', 'deep', 'send.php'), "<?php\nmail('a@b.in','s',$_POST['message']);\n")
        r = protect_site(d, {'dryRun': True})
        self.assertEqual(r['status'], 'protected')
        g = [c for c in r['changes'] if c['kind'] == 'guard-call'][0]
        self.assertIn("__DIR__ . '/../../spamguard/spamguard.php'", g['text'])

    def test_zip_input_from_a_mac(self):
        z = mac_zip(dirs['acme-dental'], os.path.join(tmp, 'acme.zip'))
        r = protect_site(z, {'outDir': os.path.join(tmp, 'out-zip')})
        self.assertEqual(r['status'], 'protected')
        names = zip_names(r['outputs']['protectedZip'])
        self.assertIn('index.html', names)
        self.assertIn('spamguard/config.php', names)
        self.assertFalse([n for n in names if re.search(r'__MACOSX|\.DS_Store|^acme-dental/', n)])
        self.assertEqual(read(r['outputs']['backupZip']), read(z), 'backup is the very zip that was given')

    def test_output_inside_site_refused_and_odd_encodings_preserved(self):
        with self.assertRaisesRegex(Exception, 'andar nahi'):
            protect_site(dirs['acme-dental'], {'outDir': os.path.join(dirs['acme-dental'], 'result')})
        d = os.path.join(tmp, 'enc')
        os.makedirs(os.path.join(d, 'uploads'))
        write(os.path.join(d, 'index.html'), b'<html><head><title>Caf\xe9</title></head><body><form action="s.php" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form></body></html>')
        write(os.path.join(d, 's.php'), b"<?php\n// caf\xe9\nmail('a@b.in','s',$_POST['message']);\n")
        r = protect_site(d, {'outDir': os.path.join(tmp, 'out-enc')})
        prot = unzip_to(r['outputs']['protectedZip'], os.path.join(tmp, 'x-enc'))
        self.assertTrue(os.path.isdir(os.path.join(prot, 'uploads')), 'empty uploads/ folder survives')
        for f in ('index.html', 's.php'):
            with open(os.path.join(prot, f), 'rb') as fh:
                self.assertIn(b'\xe9', fh.read(), f)

    def test_bom_and_crlf_handler(self):
        d = os.path.join(tmp, 'bomcrlf')
        write(os.path.join(d, 'index.html'), SIMPLE_FORM.replace('\n', '\r\n'))
        src = b"\xef\xbb\xbf<?php\r\nmail('a@b.in','s',$_POST['message']);\r\n"
        write(os.path.join(d, 's.php'), src)
        r = protect_site(d, {'outDir': os.path.join(tmp, 'out-bom'), 'keepFolder': True})
        self.assertEqual(r['status'], 'protected', json.dumps(r['forms']))
        with open(os.path.join(r['outputs']['folder'], 's.php'), 'rb') as fh:
            got = fh.read()
        self.assertTrue(got.startswith(b"\xef\xbb\xbf<?php\r\n/* SpamGuard:begin */"))
        self.assertEqual(got.count(b'\n'), got.count(b'\r\n'), 'no bare LF introduced')
        self.assertTrue(got.endswith(b"mail('a@b.in','s',$_POST['message']);\r\n"))

    def test_symlinks_never_followed(self):
        if os.name != 'posix':
            self.skipTest('posix only')
        d = os.path.join(tmp, 'sym')
        write(os.path.join(d, 'index.html'), SIMPLE_FORM)
        write(os.path.join(d, 's.php'), "<?php\nmail('a@b.in','s',$_POST['message']);\n")
        write(os.path.join(tmp, 'outside-secret.txt'), 'TOP SECRET')
        os.symlink(os.path.join(tmp, 'outside-secret.txt'), os.path.join(d, 'leak.txt'))
        r = protect_site(d, {'outDir': os.path.join(tmp, 'out-sym')})
        self.assertNotIn('leak.txt', zip_names(r['outputs']['protectedZip']))

    @unittest.skipUnless(HAS_PHP, 'php not installed')
    def test_php_syntax_error_rolls_the_file_back(self):
        d = os.path.join(tmp, 'lint')
        write(os.path.join(d, 'index.html'), SIMPLE_FORM)
        write(os.path.join(d, 's.php'), "<?php\nmail('a@b.in','s',$_POST['message'] ;\n")
        r = protect_site(d, {'dryRun': True})
        self.assertEqual(len(r['verification']['rolledBack']), 1)
        self.assertEqual(r['forms'][0]['outcome'], 'failed')
        self.assertFalse(any(c['file'] == 's.php' for c in r['changes']))
        self.assertEqual(r['verification']['phpLint'], 'ran')

    def test_php_missing_is_skipped_gracefully(self):
        from sgstudio.injector import index as idx
        saved = idx._php_avail
        idx._php_avail = False
        try:
            r = protect_site(dirs['quick-ajax'], {'dryRun': True})
        finally:
            idx._php_avail = saved
        self.assertEqual(r['verification']['phpLint'], 'skipped (PHP is computer par nahi hai)')
        self.assertEqual(r['status'], 'protected')
        self.assertIn('PHP syntax check: skipped (PHP is computer par nahi hai)', render_protect_text(r))

    def test_needs_outdir_unless_dry_run(self):
        with self.assertRaisesRegex(Exception, 'outDir chahiye'):
            protect_site(dirs['quick-ajax'], {})

    def test_bad_input_paths(self):
        with self.assertRaises(Exception):
            protect_site(os.path.join(tmp, 'does-not-exist'), {'dryRun': True})
        bad = os.path.join(tmp, 'bad.zip')
        write(bad, 'this is not a zip')
        with self.assertRaises(Exception):
            protect_site(bad, {'dryRun': True})

    def test_no_temp_folders_left_behind(self):
        def count():
            return {n for n in os.listdir(tempfile.gettempdir()) if n.startswith(('sg-protect-', 'sg-scan-'))}
        before = count()
        protect_site(mac_zip(dirs['quick-ajax'], os.path.join(tmp, 'q.zip')), {'outDir': os.path.join(tmp, 'o-tmpcheck')})
        protect_site(dirs['acme-dental'], {'dryRun': True})
        self.assertEqual(count() - before, set())

    def test_generated_password_and_steps(self):
        r = protect_site(dirs['quick-ajax'], {'outDir': os.path.join(tmp, 'o-steps')})
        self.assertRegex(r['login']['password'], r'^[A-Za-z0-9]{16}$')
        self.assertTrue(r['login']['passwordWasGenerated'])
        self.assertEqual(len(WAHAN), 4)
        self.assertEqual(r['login']['adminPath'], '/spamguard/spam-admin.php')
        self.assertRegex(r['login']['selftestPath'], r'^/spamguard/selftest\.php\?key=[0-9a-f]{16}$')

    @unittest.skipUnless(HAS_PHP, 'php not installed')
    def test_every_protected_php_file_passes_lint(self):
        n = 0
        for name in dirs:
            r = protect_site(dirs[name], {'outDir': os.path.join(tmp, 'o-lint-' + name), 'keepFolder': True, 'includeReview': True})
            if not r['outputs']:
                continue
            for p in all_php_files(r['outputs']['folder']):
                ok, msg = php_lint(p)
                self.assertTrue(ok, '%s/%s: %s' % (name, os.path.relpath(p, r['outputs']['folder']), msg))
                n += 1
        self.assertGreater(n, 10)


class ReportTest(unittest.TestCase):
    def test_report_text_reads_well_and_stays_honest(self):
        r = protect_site(dirs['external-forms'], {'dryRun': True})
        t = render_protect_text(r)
        self.assertIn('KUCH NAHI BADLA', t)
        self.assertIn('MANUAL BAAKI', t)
        self.assertNotIn('AB AAPKO KYA KARNA HAI', t, 'no upload instructions when nothing changed')

    def test_constants(self):
        self.assertTrue(STATUS_LINE['protected'].startswith('PROTECTED'))
        self.assertEqual(OUTCOME['skipped'], 'SKIP (enquiry form nahi)')
        self.assertIn('php-syntax-check-failed', ERR)
        self.assertTrue(all(isinstance(x, str) for x in WAHAN))

    def test_dry_run_text(self):
        r = protect_site(dirs['quick-ajax'], {'dryRun': True})
        t = render_protect_text(r)
        self.assertIn('(DRY RUN:', t)
        self.assertIn('KYA BADLA', t)
        self.assertIn('AB AAPKO KYA KARNA HAI', t)


# ------------------------------------------------------------------ bulk
class BulkTest(unittest.TestCase):
    def test_many_sites_one_failure_does_not_stop_the_batch(self):
        parent = os.path.join(tmp, 'many')
        for n in ['acme-dental', 'quick-ajax', 'wp-site', 'empty-site', 'include-form']:
            shutil.copytree(dirs[n], os.path.join(parent, n))
        write(os.path.join(parent, 'broken.zip'), 'this is not a zip')
        out = os.path.join(tmp, 'out-many')
        progress = []
        b = protect_many(parent, {'outDir': out, 'onProgress': progress.append})
        self.assertEqual(b['totals']['sites'], 6)
        self.assertEqual(b['totals']['protected'], 3)
        self.assertEqual(b['totals']['failed'], 1)
        self.assertEqual(b['totals']['untouched'], 2)
        self.assertEqual([p['done'] for p in progress], [1, 2, 3, 4, 5, 6])
        self.assertTrue(all(p['total'] == 6 for p in progress))
        cred = read(os.path.join(out, 'PRIVATE-credentials.csv'), 'utf-8')
        self.assertEqual(len(cred.strip().split('\n')), 4, 'header + 3 protected sites')
        self.assertNotRegex(read(os.path.join(out, 'summary.csv'), 'utf-8'), r'(?i)password')
        pw = cred.strip().split('\n')[1].split(',')[2]
        self.assertRegex(pw, r'^[A-Za-z0-9]{16}$', 'generated passwords are plain letters/digits')
        for n in ['acme-dental', 'quick-ajax', 'include-form']:
            self.assertTrue(os.path.exists(os.path.join(out, n, n + '-protected.zip')), n)
        self.assertFalse(os.path.exists(os.path.join(out, 'wp-site', 'wp-site-protected.zip')))
        self.assertFalse(os.path.exists(os.path.join(parent, 'acme-dental', 'spamguard')), 'input never modified')
        for f in ('summary.csv', 'summary.json', 'report.txt'):
            self.assertTrue(os.path.exists(os.path.join(out, f)), f)
        self.assertTrue(read(os.path.join(out, 'summary.csv'), 'utf-8').startswith('\ufeffname,status'))
        self.assertEqual(json.loads(read(os.path.join(out, 'summary.json'), 'utf-8'))['totals'], b['totals'])

    def test_loose_items_as_a_batch_leave_no_temp_folder(self):
        def count():
            return {n for n in os.listdir(tempfile.gettempdir()) if n.startswith(('sg-protect-', 'sg-scan-', 'sg-drop-'))}
        before = count()
        parent = os.path.join(tmp, 'loose')
        shutil.copytree(dirs['acme-dental'], os.path.join(parent, 'acme-dental'))
        mac_zip(dirs['quick-ajax'], os.path.join(parent, 'q.zip'))
        r = protect_many(parent, {'outDir': os.path.join(tmp, 'o2')})
        self.assertEqual(r['totals']['protected'], 2)
        self.assertEqual(count() - before, set())

    def test_refuses_output_inside_parent_and_empty_parent(self):
        parent = os.path.join(tmp, 'many2')
        shutil.copytree(dirs['quick-ajax'], os.path.join(parent, 'quick-ajax'))
        with self.assertRaisesRegex(Exception, 'andar nahi'):
            protect_many(parent, {'outDir': os.path.join(parent, 'out')})
        empty = os.path.join(tmp, 'emptyparent')
        os.makedirs(empty)
        with self.assertRaisesRegex(Exception, 'koi site folder'):
            protect_many(empty, {'outDir': os.path.join(tmp, 'o3')})

    def test_dry_run_writes_nothing(self):
        parent = os.path.join(tmp, 'many3')
        shutil.copytree(dirs['quick-ajax'], os.path.join(parent, 'quick-ajax'))
        out = os.path.join(tmp, 'out-dry-bulk')
        b = protect_many(parent, {'outDir': out, 'dryRun': True})
        self.assertEqual(b['totals']['protected'], 1)
        self.assertFalse(os.path.exists(out))

    def test_csv_formula_cells_are_neutralised(self):
        parent = os.path.join(tmp, 'many4')
        shutil.copytree(dirs['quick-ajax'], os.path.join(parent, '=cmd'))
        out = os.path.join(tmp, 'out-csv')
        protect_many(parent, {'outDir': out})
        csv = read(os.path.join(out, 'summary.csv'), 'utf-8')
        # safe_name keeps '=' out of names, so the site shows up as 'cmd'
        self.assertNotRegex(csv, r'\n=')


# ------------------------------------------------------------------ the real thing: run the protected site under PHP
def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class PhpServer(object):
    def __init__(self, docroot):
        self.port = free_port()
        self.proc = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % self.port, '-t', docroot], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t0 = time.time()
        while True:
            try:
                socket.create_connection(('127.0.0.1', self.port), 0.5).close()
                break
            except OSError:
                if time.time() - t0 > 8:
                    self.stop()
                    raise RuntimeError('php server did not start')
                time.sleep(0.1)

    def req(self, method, path, form=None, headers=None):
        from urllib.parse import urlencode
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        h = dict(headers or {})
        body = None
        if form is not None:
            body = urlencode(form)
            h['Content-Type'] = 'application/x-www-form-urlencoded'
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read().decode('utf-8', 'replace')
        out = {'status': r.status, 'headers': {k.lower(): v for k, v in r.getheaders()}, 'body': data}
        c.close()
        return out

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except Exception:
            self.proc.kill()


@unittest.skipUnless(HAS_PHP, 'php not installed')
class LivePhpTest(unittest.TestCase):
    def test_real_run_under_php(self):
        d = os.path.join(tmp, 'live-src')
        write(os.path.join(d, 'index.html'), '<html><head><title>Live</title></head><body><form action="contact.php" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form></body></html>')
        write(os.path.join(d, 'contact.php'), "<?php\nfile_put_contents(__DIR__ . '/received.log', $_POST['name'] . \"\\n\", FILE_APPEND);\nheader('Location: thank-you.html');\n")
        write(os.path.join(d, 'thank-you.html'), '<html><body>thanks</body></html>')
        write(os.path.join(d, 'ajax.html'), '<html><head><title>A</title></head><body><form id="f" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form><script src="js/ajax.js"></script></body></html>')
        write(os.path.join(d, 'js', 'ajax.js'), "$('#f').on('submit', function(e){ e.preventDefault(); $.ajax({ type:'POST', url:'ajax/save.php', data:$(this).serialize(), dataType:'json', success:function(res){ if(res.status=='OK'){ alert('sent'); } } }); });")
        write(os.path.join(d, 'ajax', 'save.php'), "<?php\nfile_put_contents(dirname(__DIR__) . '/ajax-received.log', $_POST['name'] . \"\\n\", FILE_APPEND);\nheader('Content-Type: application/json');\necho json_encode(['status' => 'OK', 'code' => 200]);\n")

        r = protect_site(d, {'outDir': os.path.join(tmp, 'out-live'), 'keepFolder': True, 'password': 'Live-pass-123'})
        self.assertEqual(r['status'], 'protected', json.dumps(r['forms']))
        site = r['outputs']['folder']
        # control: the UNPROTECTED site really does let spam straight through
        ctl = PhpServer(d)
        spam = {'name': 'SPAMBOT', 'email': 'x@mailinator.com', 'message': 'cheap seo http://a.com http://b.com http://c.com'}
        try:
            c = ctl.req('POST', '/contact.php', spam)
        finally:
            ctl.stop()
        self.assertEqual(c['status'], 302)
        self.assertIn('SPAMBOT', read(os.path.join(d, 'received.log'), 'utf-8'), 'control: unprotected site accepted the spam')
        os.remove(os.path.join(d, 'received.log'))

        srv = PhpServer(site)
        try:
            page = srv.req('GET', '/index.html')
            self.assertIn('spamguard/spamguard.js', page['body'])
            self.assertEqual(srv.req('GET', '/spamguard/spamguard.js')['status'], 200)
            # 1. spam: honeypot filled -> looks like success, handler never runs
            sp = srv.req('POST', '/contact.php', dict({'sg_website': 'http://spam', 'sg_i': '0'}, **spam))
            self.assertEqual(sp['status'], 303, 'bot is told "thanks" (redirect), not "blocked"')
            self.assertRegex(sp['headers']['location'], r'thank-you\.html')
            self.assertFalse(os.path.exists(os.path.join(site, 'received.log')), 'spam never reached the original handler')
            # 2. AJAX spam gets the handler's own JSON shape
            a = srv.req('POST', '/ajax/save.php', dict({'sg_website': 'x'}, **spam), {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'})
            self.assertEqual(json.loads(a['body']), {'status': 'OK', 'code': 200})
            self.assertFalse(os.path.exists(os.path.join(site, 'ajax-received.log')))
            # 3. a real person: token from token.php, waits, then submits
            tok = json.loads(srv.req('GET', '/spamguard/token.php')['body'])['t']
            tok2 = json.loads(srv.req('GET', '/spamguard/token.php')['body'])['t']
            self.assertGreater(len(tok), 20)
            time.sleep(3.3)
            human = {'name': 'Rahul Sharma', 'email': 'rahul.sharma@gmail.com', 'phone': '9876543210',
                     'message': 'I would like to know the price of a two bedroom flat and the possession date.',
                     'sg_t': tok, 'sg_i': '37', 'sg_website': ''}
            ok = srv.req('POST', '/contact.php', human, {'User-Agent': 'Mozilla/5.0 (Macintosh) Safari/605'})
            self.assertEqual(ok['status'], 302, 'real enquiry reaches the ORIGINAL handler (its own redirect)')
            self.assertEqual(read(os.path.join(site, 'received.log'), 'utf-8'), 'Rahul Sharma\n')
            human2 = dict(human, name='Priya Singh', email='priya.singh@gmail.com', sg_t=tok2)
            ok2 = srv.req('POST', '/ajax/save.php', human2, {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0 (iPhone) Safari/604'})
            self.assertEqual(json.loads(ok2['body']), {'status': 'OK', 'code': 200})
            self.assertEqual(read(os.path.join(site, 'ajax-received.log'), 'utf-8'), 'Priya Singh\n')
            # 4. the admin page asks for a login; the right password (pbkdf2 hash made in Python) logs in, a wrong one does not
            adm = srv.req('GET', '/spamguard/spam-admin.php')
            self.assertEqual(adm['status'], 200)
            self.assertRegex(adm['body'], r'(?i)password')
            bad = srv.req('POST', '/spamguard/spam-admin.php', {'password': 'not-the-password'})
            self.assertIn('Wrong password', bad['body'])
            good = srv.req('POST', '/spamguard/spam-admin.php', {'password': 'Live-pass-123'})
            self.assertEqual(good['status'], 302, good['body'][:300])
        finally:
            srv.stop()


@unittest.skipUnless(HAS_PHP, 'php not installed')
class PasswordHashTest(unittest.TestCase):
    PHP = (r'define("SG_LIB", true); require $argv[1] . "/spamguard/spamguard.php"; '
           r'$cfg = require $argv[1] . "/spamguard/config.php"; '
           r'echo json_encode([SpamGuard::verifyPassword($argv[2], $cfg["admin_password_hash"]), SpamGuard::verifyPassword("nope-nope-1", $cfg["admin_password_hash"]), $cfg["admin_password_hash"]]);')

    def check(self, site_root, pw):
        r = subprocess.run(['php', '-r', self.PHP, site_root, pw], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        return json.loads(r.stdout.decode())

    def test_config_hash_verifies_in_the_real_kit(self):
        for pw in ['Secret-pass-1', "p\u00e4ss w\u00f6rd '\"$x\\ 99"]:
            res = protect_site(dirs['quick-ajax'], {'outDir': os.path.join(tmp, 'o-pw'), 'keepFolder': True, 'password': pw})
            self.assertEqual(res['login']['password'], pw)
            ok, wrong, stored = self.check(res['outputs']['folder'], pw)
            self.assertTrue(ok, stored)
            self.assertFalse(wrong)

    def test_kit_accepts_pbkdf2_and_legacy_bcrypt_and_rejects_garbage(self):
        salt = bytes(range(16))
        h = hashlib.pbkdf2_hmac('sha256', 'Pässword-1'.encode('utf-8'), salt, 120000).hex()
        stored = 'pbkdf2$120000$%s$%s' % (salt.hex(), h)
        code = (r'define("SG_LIB", true); require $argv[1] . "/spamguard.php";'
                r'$bc = password_hash("legacy-pass", PASSWORD_BCRYPT);'
                r'echo json_encode([SpamGuard::verifyPassword("P\xc3\xa4ssword-1", $argv[2]), SpamGuard::verifyPassword("P\xc3\xa4ssword-2", $argv[2]),'
                r'SpamGuard::verifyPassword("legacy-pass", $bc), SpamGuard::verifyPassword("x", $bc), SpamGuard::verifyPassword("x", ""),'
                r'SpamGuard::verifyPassword("x", "pbkdf2\$10\$zz\$zz"), SpamGuard::verifyPassword("x", "pbkdf2\$1\$00\$00"), SpamGuard::verifyPassword("x", "pbkdf2\$abc")]);')
        r = subprocess.run(['php', '-r', code, os.path.join(ROOT, 'kit', 'spamguard'), stored], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertEqual(json.loads(r.stdout.decode()), [True, False, True, False, False, False, False, False])


# ------------------------------------------------------------------ hub client + provisioning
class FakeHub(object):
    """A tiny local stand-in for the hub's /api/provision.php."""

    def __init__(self, token):
        outer = self
        self.token = token
        self.calls = []
        self.mode = 'ok'

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n)
                outer.calls.append({'path': self.path, 'auth': self.headers.get('Authorization'), 'ctype': self.headers.get('Content-Type'), 'body': json.loads(body.decode() or 'null')})
                if outer.mode == 'redirect':
                    self.send_response(302); self.send_header('Location', '/elsewhere'); self.end_headers(); return
                if outer.mode == '429':
                    self.send_response(429); self.end_headers(); return
                if outer.mode == 'garbage':
                    self.send_response(200); self.end_headers(); self.wfile.write(b'<html>not json'); return
                if outer.mode == '500':
                    self.send_response(500); self.end_headers(); self.wfile.write(b'{"ok":false}'); return
                if self.headers.get('Authorization') != 'Bearer ' + outer.token:
                    self.send_response(401); self.end_headers(); self.wfile.write(b'{"ok":false}'); return
                out = json.dumps({'ok': True, 'site_id': 7, 'site_key': 'K' * 24, 'secret': 'ab' * 24}).encode()
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(out)

        self.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.url = 'http://127.0.0.1:%d' % self.srv.server_address[1]
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


class HubClientTest(unittest.TestCase):
    def test_normalize_url(self):
        n = sg_hub.normalize_url
        self.assertEqual(n('https://Hub.Example.com/index.php'), 'https://hub.example.com')
        self.assertEqual(n(' https://h.com:443/x/ '), 'https://h.com/x')
        self.assertEqual(n('https://h.com/hub/install.php?x=1#y'), 'https://h.com/hub')
        self.assertEqual(n('http://127.0.0.1:8080/hub/login.php'), 'http://127.0.0.1:8080/hub')
        self.assertEqual(n('http://localhost'), 'http://localhost')
        self.assertEqual(n('http://[::1]:9000/'), 'http://[::1]:9000')
        with self.assertRaisesRegex(Exception, 'address galat'):
            n('hub.example.com')
        with self.assertRaisesRegex(Exception, 'https:// se shuru'):
            n('http://example.com')
        with self.assertRaisesRegex(Exception, 'https:// se shuru'):
            n('ftp://example.com')
        with self.assertRaisesRegex(Exception, 'username/password'):
            n('https://u:p@example.com')

    def test_looks_like_domain(self):
        self.assertTrue(sg_hub.looks_like_domain('acmedental.in'))
        self.assertTrue(sg_hub.looks_like_domain('www.a-b.co.uk'))
        self.assertFalse(sg_hub.looks_like_domain('acme-dental'))
        self.assertFalse(sg_hub.looks_like_domain('my site.com'))

    def test_provision_errors_and_success(self):
        tok = 'A' * 40
        h = FakeHub(tok)
        try:
            with self.assertRaisesRegex(Exception, 'token galat'):
                sg_hub.provision_site({'url': h.url, 'token': 'short'}, 'x')
            with self.assertRaisesRegex(Exception, 'token nahi manaa'):
                sg_hub.provision_site({'url': h.url, 'token': 'B' * 40}, 'x')
            p = sg_hub.provision_site({'url': h.url + '/index.php', 'token': ' ' + tok + ' '}, 'acmedental.in')
            self.assertEqual((p['site_id'], p['site_key'], p['hub_url']), (7, 'K' * 24, h.url))
            c = h.calls[-1]
            self.assertEqual(c['path'], '/api/provision.php')
            self.assertEqual(c['auth'], 'Bearer ' + tok)
            self.assertEqual(c['body'], {'name': 'acmedental.in', 'ref': 'studio:acmedental.in', 'domain': 'acmedental.in'})
            sg_hub.provision_site({'url': h.url, 'token': tok}, 'plain-name')
            self.assertNotIn('domain', h.calls[-1]['body'])
            for mode, rx in [('429', 'thoda ruko'), ('garbage', r'galat jawab aaya \(status 200\)'), ('500', r'galat jawab aaya \(status 500\)'), ('redirect', 'connect nahi hua')]:
                h.mode = mode
                with self.assertRaisesRegex(Exception, rx, msg=mode):
                    sg_hub.provision_site({'url': h.url, 'token': tok}, 'x')
        finally:
            h.stop()
        with self.assertRaisesRegex(Exception, 'connect nahi hua'):
            sg_hub.provision_site({'url': 'http://127.0.0.1:%d' % free_port(), 'token': tok}, 'x', timeout=2)

    def test_protect_with_hub(self):
        tok = 'T' * 40
        h = FakeHub(tok)
        try:
            site = os.path.join(tmp, 'hubsite', 'acmedental.in')
            shutil.copytree(dirs['acme-dental'], site)
            write(os.path.join(site, 'about.php'), "<?php\n$t='x';\n?><!doctype html>\n<html><head><title>a</title></head><body><p>hi</p></body></html>\n")
            before = len(h.calls)
            dry = protect_site(site, {'dryRun': True, 'hub': {'url': h.url, 'token': tok}})
            self.assertEqual(dry['hub'], {'status': 'dry-run'})
            self.assertEqual(len(h.calls), before, 'a dry run never registers anything')
            self.assertTrue(dry['siteWide']['enabled'])
            res = protect_site(site, {'outDir': os.path.join(tmp, 'o-hub'), 'keepFolder': True, 'hub': {'url': h.url, 'token': tok}})
            self.assertEqual(res['status'], 'protected')
            self.assertEqual(res['hub'], {'status': 'connected', 'siteId': 7})
            self.assertEqual(len(h.calls), before + 1)
            self.assertEqual(h.calls[-1]['body']['domain'], 'acmedental.in')
            cfg = read(os.path.join(res['outputs']['folder'], 'spamguard', 'config.php'), 'utf-8')
            self.assertIn("'hub' => [", cfg)
            self.assertIn("'url' => '%s'" % h.url, cfg)
            self.assertRegex(cfg, r"'site_key' => 'K{24}'")
            self.assertRegex(cfg, r"'secret' => '[a-f0-9]{48}'")
            self.assertNotIn(tok, json.dumps(res), 'the provision token is nowhere in the result')
            self.assertIn('HUB: connect ho gaya', render_protect_text(res))
            # site-wide: PHP page got the apply line, html pages the contact script
            self.assertTrue(res['siteWide']['enabled'])
            self.assertGreaterEqual(res['siteWide']['phpPages'], 1)
            self.assertGreaterEqual(res['siteWide']['jsPages'], 1)
            self.assertIn('sg-apply.php', read(os.path.join(res['outputs']['folder'], 'about.php')))
            self.assertIn('spamguard/contact.js', read(os.path.join(res['outputs']['folder'], 'about.html')))
            if HAS_PHP:
                for p in all_php_files(res['outputs']['folder']):
                    ok, msg = php_lint(p)
                    self.assertTrue(ok, msg)
            again = protect_site(res['outputs']['folder'], {'outDir': os.path.join(tmp, 'o-hub2'), 'hub': {'url': h.url, 'token': tok}})
            self.assertEqual(len(again['changes']), 0)
            self.assertEqual(len(h.calls), before + 1, 're-running on an already protected site creates no duplicate hub entry')
            # failure never blocks protection
            h.mode = '500'
            f = protect_site(dirs['quick-ajax'], {'outDir': os.path.join(tmp, 'o-hub3'), 'hub': {'url': h.url, 'token': tok}})
            self.assertEqual(f['status'], 'protected')
            self.assertEqual(f['hub']['status'], 'failed')
            self.assertRegex(render_protect_text(f), r'(?s)HUB: connect NAHI hua.*Site protect ho gayi hai')
        finally:
            h.stop()


# ------------------------------------------------------------------ parity with the Node implementation
NODE_RUN = r'''
const fs = require('fs');
const [kind, input, opts, outFile] = JSON.parse(process.argv[1]);
(async () => {
  let r;
  if (kind === 'site') { const { protectSite } = require(process.env.SG_ROOT + '/src/injector'); r = await protectSite(input, opts); const { writeSiteReports } = require(process.env.SG_ROOT + '/src/injector/bulk'); if (!opts.dryRun) writeSiteReports(r, opts.outDir); }
  else { const { protectMany } = require(process.env.SG_ROOT + '/src/injector/bulk'); r = await protectMany(input, opts); }
  fs.writeFileSync(outFile, JSON.stringify(r));
})().catch((e) => { fs.writeFileSync(outFile, JSON.stringify({ __error: e.message })); });
'''


def node_run(kind, input_, opts, tag):
    out = os.path.join(tmp, 'node-%s.json' % tag)
    env = dict(os.environ, SG_ROOT=ROOT)
    subprocess.run(['node', '-e', NODE_RUN, json.dumps([kind, input_, opts, out])], env=env, check=True, cwd=ROOT)
    with open(out, 'rb') as fh:
        return json.loads(fh.read().decode('utf-8'))


def normalise_config(t):
    t = re.sub(r"('secret' => ')[a-f0-9]{64}(')", r'\1<SECRET>\2', t)
    t = re.sub(r"(__DIR__ \. '/sg-data-)[0-9a-f]{6}(')", r'\1<DIR>\2', t)
    t = re.sub(r"('admin_password_hash' => ')[^']*(')", r'\1<HASH>\2', t)
    t = re.sub(r"('selftest_key' => ')[0-9a-f]{16}(')", r'\1<KEY>\2', t)
    return t


def file_map(root):
    out = {}
    for base, _dn, fns in os.walk(root):
        for fn in fns:
            p = os.path.join(base, fn)
            with open(p, 'rb') as fh:
                out[os.path.relpath(p, root).replace(os.sep, '/')] = fh.read()
    dir_set = set()
    for base, dn, _fns in os.walk(root):
        for d in dn:
            dir_set.add(os.path.relpath(os.path.join(base, d), root).replace(os.sep, '/'))
    return out, dir_set


_CMP = 0


@unittest.skipUnless(HAS_NODE, 'node (with node_modules) not available for parity checks')
class ParityWithNodeTest(unittest.TestCase):
    def compare_site(self, name, extra=None, dry=False):
        extra = dict(extra or {})
        global _CMP
        _CMP += 1
        tag = '%s%s-%d' % (name, '-dry' if dry else '', _CMP)
        pw = 'Parity-pass-77'
        roots = {k: os.path.join(tmp, 'par', k + '-' + tag) for k in ('node', 'py')}
        for k, rt in roots.items():
            shutil.copytree(dirs[name], os.path.join(rt, name))  # same folder name for both => same site name
        opts = {}
        for k, rt in roots.items():
            o = {'password': pw, 'keepFolder': True}
            o.update(extra)
            if dry:
                o['dryRun'] = True
            else:
                o['outDir'] = os.path.join(rt, 'out')
            opts[k] = o
        nr = node_run('site', os.path.join(roots['node'], name), opts['node'], tag)
        self.assertNotIn('__error', nr, nr)
        pr = protect_site(os.path.join(roots['py'], name), opts['py'])
        if not dry:
            write_site_reports(pr, opts['py']['outDir'])

        def norm(r, rt):
            s = json.dumps(r).replace(rt, '<T>')
            s = re.sub(r'selftest\.php\?key=[0-9a-f]{16}', 'selftest.php?key=<KEY>', s)
            d = json.loads(s)
            if d.get('login') and d['login'].get('password') == pw:
                d['login']['password'] = '<PW>'
            return d
        self.assertEqual(norm(pr, roots['py']), norm(nr, roots['node']), tag)
        if dry or not pr['outputs']:
            return
        self.assertEqual(sorted(nr['outputs']), sorted(pr['outputs']))
        for key in ('protectedZip', 'backupZip'):
            nz = unzip_to(nr['outputs'][key], os.path.join(roots['node'], 'x-' + key))
            pz = unzip_to(pr['outputs'][key], os.path.join(roots['py'], 'x-' + key))
            self.compare_trees(nz, pz, tag + ' ' + key)
        self.compare_trees(nr['outputs']['folder'], pr['outputs']['folder'], tag + ' folder')
        for rep in ('report.txt', 'report.json', 'PRIVATE-login.txt'):
            def load(r, rt):
                t = read(os.path.join(r['outputs']['dir'], rep), 'utf-8').replace(rt, '<T>').replace(pw, '<PW>')
                return re.sub(r'key=[0-9a-f]{16}', 'key=<KEY>', t)
            a, b = load(nr, roots['node']), load(pr, roots['py'])
            if rep == 'report.json':
                self.assertEqual(json.loads(b), json.loads(a), tag + ' ' + rep)
            else:
                self.assertEqual(b, a, tag + ' ' + rep)
        if HAS_PHP:
            for p in all_php_files(pr['outputs']['folder']):
                ok, msg = php_lint(p)
                self.assertTrue(ok, msg)

    def compare_trees(self, nz, pz, label):
        nf, nd = file_map(nz)
        pf, pd = file_map(pz)
        self.assertEqual(sorted(pf), sorted(nf), label + ' file list')
        self.assertEqual(pd, nd, label + ' folders')
        for rel in nf:
            a, b = nf[rel], pf[rel]
            if rel == 'spamguard/config.php':
                a = normalise_config(a.decode('utf-8')).encode()
                b = normalise_config(b.decode('utf-8')).encode()
            self.assertEqual(b, a, '%s %s differs' % (label, rel))

    def test_parity_all_fixtures_dry_run(self):
        for name in dirs:
            for review in (False, True):
                with self.subTest(site=name, includeReview=review):
                    self.compare_site(name, {'includeReview': review}, dry=True)

    def test_parity_all_fixtures_real_run(self):
        for name in dirs:
            for review in (False, True):
                with self.subTest(site=name, includeReview=review):
                    self.compare_site(name, {'includeReview': review}, dry=False)

    def test_parity_options(self):
        extra = {'quarantine': True, 'timezone': 'Europe/Berlin', 'notifyEmail': 'boss@example.com', 'basePath': '/sub'}
        for name in ('acme-dental', 'quick-ajax', 'include-form'):
            with self.subTest(site=name):
                self.compare_site(name, extra)

    def test_parity_with_hub_and_site_wide(self):
        tok = 'H' * 40
        hub = FakeHub(tok)
        try:
            for name in ('acme-dental', 'quick-ajax'):
                with self.subTest(site=name):
                    self.compare_site(name, {'hub': {'url': hub.url, 'token': tok}})
            with self.subTest(site='dry'):
                self.compare_site('acme-dental', {'hub': {'url': hub.url, 'token': tok}}, dry=True)
        finally:
            hub.stop()

    def test_parity_bulk(self):
        parent_n = os.path.join(tmp, 'par-bulk-node')
        parent_p = os.path.join(tmp, 'par-bulk-py')
        for parent in (parent_n, parent_p):
            for n in ['acme-dental', 'quick-ajax', 'wp-site', 'empty-site', 'include-form', 'self-post', 'already-protected']:
                shutil.copytree(dirs[n], os.path.join(parent, n))
            write(os.path.join(parent, 'broken.zip'), 'this is not a zip')
            mac_zip(dirs['fetch-unknown'], os.path.join(parent, 'fu.zip'))
        nb = node_run('many', parent_n, {'outDir': os.path.join(tmp, 'par-bulk-out-node'), 'password': 'Bulk-pass-1234'}, 'bulk')
        pb = protect_many(parent_p, {'outDir': os.path.join(tmp, 'par-bulk-out-py'), 'password': 'Bulk-pass-1234'})
        self.assertEqual(pb, json.loads(json.dumps(nb)))
        for f in ('summary.csv', 'summary.json', 'report.txt'):
            self.assertEqual(read(os.path.join(tmp, 'par-bulk-out-py', f), 'utf-8'), read(os.path.join(tmp, 'par-bulk-out-node', f), 'utf-8'), f)
        a = read(os.path.join(tmp, 'par-bulk-out-py', 'PRIVATE-credentials.csv'), 'utf-8')
        b = read(os.path.join(tmp, 'par-bulk-out-node', 'PRIVATE-credentials.csv'), 'utf-8')
        norm = lambda t: re.sub(r'key=[0-9a-f]{16}', 'key=<KEY>', t)  # noqa: E731
        self.assertEqual(norm(a), norm(b))

    def test_parity_errors(self):
        # both implementations refuse an output folder inside the site
        d = os.path.join(tmp, 'par-err')
        shutil.copytree(dirs['quick-ajax'], d)
        nr = node_run('site', d, {'outDir': os.path.join(d, 'res')}, 'err')
        self.assertIn('andar nahi', nr['__error'])
        with self.assertRaises(Exception) as cm:
            protect_site(d, {'outDir': os.path.join(d, 'res')})
        self.assertEqual(str(cm.exception), nr['__error'])


if __name__ == '__main__':
    unittest.main()
