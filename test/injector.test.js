'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const { spawn, spawnSync } = require('child_process');
const AdmZip = require('adm-zip');
const { buildFixtures, zipFolder } = require('./helpers');
const E = require('../src/injector/edits');
const { protectSite } = require('../src/injector');
const { protectMany, writeSiteReports } = require('../src/injector/bulk');
const { renderProtectText } = require('../src/injector/report');
const { scanSite } = require('../src/scanner');

const hasPhp = spawnSync('php', ['-v']).status === 0;
let tmp;
let dirs;
before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-inj-'));
  dirs = buildFixtures(path.join(tmp, 'sites'));
});
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const treeHash = (dir) => {
  const h = crypto.createHash('sha256');
  const walk = (d, rel) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = path.join(d, e.name);
      const r = rel + '/' + e.name;
      if (e.isDirectory()) walk(p, r);
      else h.update(r).update(fs.readFileSync(p));
    }
  };
  walk(dir, '');
  return h.digest('hex');
};
const unzipTo = (zip, dest) => {
  new AdmZip(zip).extractAllTo(dest, true);
  return dest;
};
const stripInserted = (t) => t.replace(/<!-- SpamGuard --><script[^>]*><\/script>\r?\n/g, '').replace(/(?:\r?\n| )\/\* SpamGuard:begin \*\/.*?\/\* SpamGuard:end \*\//g, '');

// ------------------------------------------------------------------ pure edits
test('guard spot: plain, BOM, CRLF, strict_types, namespace', () => {
  let g = E.planGuardEdit('<?php\n$a = 1;\n', 'inc', null);
  assert.equal(g.offset, 5);
  assert.match(g.insert, /^\nSpamGuard|^\n\/\* SpamGuard:begin \*\/ if \(is_file\(__DIR__ \. '\/inc\/spamguard\/spamguard\.php'\)\)/);
  const bom = '\xEF\xBB\xBF<?php\r\n$a=1;';
  g = E.planGuardEdit(bom, '', null);
  assert.equal(g.offset, 8);
  assert.ok(g.insert.startsWith('\r\n'), 'keeps CRLF');
  const strict = '<?php\ndeclare(strict_types=1);\nnamespace App\\Web;\n\nuse X;\n';
  g = E.planGuardEdit(strict, '', null);
  assert.equal(strict.slice(0, g.offset), '<?php\ndeclare(strict_types=1);\nnamespace App\\Web;');
  assert.match(g.insert, /\\SpamGuard::guard\(/, 'inside a namespace the class is called with a leading backslash');
  const out = E.applyInsertions(strict, [g]);
  assert.ok(out.indexOf('declare(strict_types=1)') < out.indexOf('SpamGuard:begin'), 'declare stays first');
});

test('guard spot: unsafe files are refused, never guessed', () => {
  assert.equal(E.planGuardEdit('<html>\n<?php echo 1;', '', null).error, 'php-not-at-top');
  assert.equal(E.planGuardEdit('<? echo 1;', '', null).error, 'short-open-tag');
  assert.equal(E.planGuardEdit('<?php\nnamespace A {\n}', '', null).error, 'bracketed-namespace');
  assert.equal(E.planGuardEdit('just html', '', null).error, 'no-php');
  assert.equal(E.planGuardEdit('<?php SpamGuard::guard();', '', null).error, 'already');
});

test('script tag: after the form, never inside a PHP block, once per file', () => {
  const html = '<body>\n<form>\n</form>\n<?php if (1): ?>\n<p>x</p>\n<?php endif; ?>\n</body>';
  const p = E.planScriptEdit(html, 3, '/spamguard/spamguard.js');
  assert.equal(p.offset, html.indexOf('<?php if'));
  const inside = '<?php\nif (1) {\n echo "x";\n}\n?>\n</body>';
  const q = E.planScriptEdit(inside, 3, '/spamguard/spamguard.js');
  assert.ok(q.offset > inside.indexOf('?>'), 'falls back to before </body>, outside PHP');
  assert.equal(E.planScriptEdit('<?php\nforeach($a as $b){\n', 2, '/s.js').error, 'script-position-unsafe');
  assert.equal(E.planScriptEdit('<script src="/spamguard/spamguard.js"></script>', 1, '/x').error, 'already');
});

test('override literal is escaped PHP', () => {
  assert.equal(E.phpInline({ success: { json: { status: "it's", n: 1, ok: true } } }), "['success' => ['json' => ['status' => 'it\\'s', 'n' => 1, 'ok' => true]]]");
  assert.equal(E.phpInline("a\\b'\nc"), "'a\\\\b\\'' . ''".slice(0, 0) + "'a\\\\b\\' c'");
});

// ------------------------------------------------------------------ whole-site protection
test('protects a classic site: only insertions, original untouched, backup + zip + reports', async () => {
  const before = treeHash(dirs['acme-dental']);
  const out = path.join(tmp, 'out-acme');
  const r = await protectSite(dirs['acme-dental'], { outDir: out, password: 'Secret-pass-1' });
  writeSiteReports(r, out);
  assert.equal(treeHash(dirs['acme-dental']), before, 'input folder must stay byte-identical');
  assert.equal(r.status, 'protected');
  assert.equal(r.summary.protected, 1);
  assert.equal(r.verification.rescan.formsProtectedAfter, 1);
  assert.ok(r.kit.installed);
  const prot = unzipTo(r.outputs.protectedZip, path.join(tmp, 'x-acme'));
  const bak = unzipTo(r.outputs.backupZip, path.join(tmp, 'x-acme-bak'));
  assert.equal(treeHash(bak), before, 'backup equals the original');
  assert.ok(fs.existsSync(path.join(prot, 'spamguard', 'spamguard.php')));
  assert.ok(fs.existsSync(path.join(prot, 'spamguard', 'config.php')));
  assert.ok(!fs.existsSync(path.join(prot, 'spamguard', 'tests')), 'tests are not shipped');
  for (const c of r.changes) {
    const was = fs.readFileSync(path.join(dirs['acme-dental'], c.file), 'latin1');
    const now = fs.readFileSync(path.join(prot, c.file), 'latin1');
    assert.equal(stripInserted(now), was, c.file + ': removing the inserted text gives the original back');
  }
  // every non-touched original file is identical in the protected copy
  const changed = new Set(r.changes.map((c) => c.file));
  for (const f of fs.readdirSync(dirs['acme-dental'])) {
    if (changed.has(f) || fs.statSync(path.join(dirs['acme-dental'], f)).isDirectory()) continue;
    assert.deepEqual(fs.readFileSync(path.join(prot, f)), fs.readFileSync(path.join(dirs['acme-dental'], f)), f);
  }
  const txt = fs.readFileSync(path.join(out, 'acme-dental', 'report.txt'), 'utf8');
  assert.match(txt, /PROTECTED/);
  assert.ok(!txt.includes('Secret-pass-1'), 'password is not in the shareable report');
  assert.ok(!fs.readFileSync(path.join(out, 'acme-dental', 'report.json'), 'utf8').includes('Secret-pass-1'));
  assert.match(fs.readFileSync(path.join(out, 'acme-dental', 'PRIVATE-login.txt'), 'utf8'), /Secret-pass-1/);
  assert.match(fs.readFileSync(path.join(prot, 'spamguard', 'config.php'), 'utf8'), /return \[/);
  assert.ok(!fs.readFileSync(path.join(prot, 'spamguard', 'config.php'), 'utf8').includes('Secret-pass-1'), 'only the bcrypt hash is stored');
});

test('running it again changes nothing (idempotent)', async () => {
  const out = path.join(tmp, 'out-idem');
  const r1 = await protectSite(dirs['quick-ajax'], { outDir: out, keepFolder: true });
  assert.equal(r1.status, 'protected');
  const r2 = await protectSite(r1.outputs.folder, { outDir: path.join(tmp, 'out-idem2') });
  assert.equal(r2.changes.length, 0);
  assert.equal(r2.status, 'already-protected');
  assert.deepEqual(r2.outputs, {});
});

test('AJAX handler: the fake answer for bots copies the handler\'s own success JSON', async () => {
  const r = await protectSite(dirs['quick-ajax'], { dryRun: true });
  const g = r.changes.find((c) => c.kind === 'guard-call');
  assert.match(g.text, /SpamGuard::guard\(\['success' => \['json' => \['status' => 'success'/);
});

test('forms the tool cannot handle are left alone and explained', async () => {
  for (const n of ['external-forms', 'wp-site', 'php-generated']) {
    const r = await protectSite(dirs[n], { outDir: path.join(tmp, 'out-' + n) });
    assert.equal(r.status, 'manual-only', n);
    assert.equal(r.changes.length, 0, n);
    assert.deepEqual(r.outputs, {}, n + ': no zip is made when nothing changed');
    assert.ok(r.forms.every((f) => f.outcome === 'manual' || f.outcome === 'skipped'));
  }
  const e = await protectSite(dirs['empty-site'], { dryRun: true });
  assert.equal(e.status, 'no-forms');
});

test('review forms are only patched when asked', async () => {
  const a = await protectSite(dirs['fetch-unknown'], { dryRun: true });
  assert.equal(a.changes.length, 0);
  assert.equal(a.summary.needsReview, 1);
  const b = await protectSite(dirs['fetch-unknown'], { dryRun: true, includeReview: true });
  assert.ok(b.changes.length >= 1);
  assert.equal(b.summary.needsReview, 0);
});

test('self-post page and shared include both get the right insert points', async () => {
  const s = await protectSite(dirs['self-post'], { dryRun: true });
  assert.equal(s.status, 'protected');
  assert.deepEqual(s.changes.map((c) => c.file).sort(), ['contact.php', 'contact.php']);
  const inc = await protectSite(dirs['include-form'], { dryRun: true });
  assert.equal(inc.status, 'protected');
  assert.ok(inc.changes.some((c) => c.file === 'footer.php' && c.kind === 'script-tag'));
  assert.ok(inc.changes.some((c) => c.file === 'lead-handler.php' && c.kind === 'guard-call'));
});

test('handler in a sub folder gets a ../ path to the kit', async () => {
  const d = path.join(tmp, 'sub');
  fs.mkdirSync(path.join(d, 'forms', 'deep'), { recursive: true });
  fs.writeFileSync(path.join(d, 'index.html'), '<html><head><title>S</title></head><body><form action="forms/deep/send.php" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form></body></html>');
  fs.writeFileSync(path.join(d, 'forms', 'deep', 'send.php'), "<?php\nmail('a@b.in','s',$_POST['message']);\n");
  const r = await protectSite(d, { dryRun: true });
  assert.equal(r.status, 'protected');
  assert.match(r.changes.find((c) => c.kind === 'guard-call').text, /__DIR__ \. '\/\.\.\/\.\.\/spamguard\/spamguard\.php'/);
});

test('zip input from a Mac (wrapper folder + junk) works and the result has no wrapper', async () => {
  const z = zipFolder(dirs['acme-dental'], path.join(tmp, 'acme.zip'));
  const r = await protectSite(z, { outDir: path.join(tmp, 'out-zip') });
  assert.equal(r.status, 'protected');
  const names = new AdmZip(r.outputs.protectedZip).getEntries().map((e) => e.entryName);
  assert.ok(names.includes('index.html') && names.includes('spamguard/config.php'));
  assert.ok(!names.some((n) => /__MACOSX|\.DS_Store|^acme-dental\//.test(n)));
  assert.deepEqual(fs.readFileSync(r.outputs.backupZip), fs.readFileSync(z), 'backup is the very zip that was given');
});

test('refuses an output folder inside the site folder; preserves empty folders and odd encodings', async () => {
  await assert.rejects(() => protectSite(dirs['acme-dental'], { outDir: path.join(dirs['acme-dental'], 'result') }), /andar nahi/);
  const d = path.join(tmp, 'enc');
  fs.mkdirSync(path.join(d, 'uploads'), { recursive: true });
  fs.writeFileSync(path.join(d, 'index.html'), Buffer.concat([Buffer.from('<html><head><title>Caf'), Buffer.from([0xe9]), Buffer.from('</title></head><body><form action="s.php" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form></body></html>')]));
  fs.writeFileSync(path.join(d, 's.php'), Buffer.concat([Buffer.from("<?php\n// caf"), Buffer.from([0xe9]), Buffer.from("\nmail('a@b.in','s',$_POST['message']);\n")]));
  const r = await protectSite(d, { outDir: path.join(tmp, 'out-enc') });
  const prot = unzipTo(r.outputs.protectedZip, path.join(tmp, 'x-enc'));
  assert.ok(fs.statSync(path.join(prot, 'uploads')).isDirectory(), 'empty uploads/ folder survives');
  assert.ok(fs.readFileSync(path.join(prot, 'index.html')).includes(Buffer.from([0xe9])), 'latin1 byte untouched');
  assert.ok(fs.readFileSync(path.join(prot, 's.php')).includes(Buffer.from([0xe9])));
});

test('symlinks in the site are never followed or copied', async () => {
  const d = path.join(tmp, 'sym');
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, 'index.html'), '<html><head><title>x</title></head><body><form action="s.php" method="post"><input name="n"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form></body></html>');
  fs.writeFileSync(path.join(d, 's.php'), "<?php\nmail('a@b.in','s',$_POST['message']);\n");
  fs.writeFileSync(path.join(tmp, 'outside-secret.txt'), 'TOP SECRET');
  fs.symlinkSync(path.join(tmp, 'outside-secret.txt'), path.join(d, 'leak.txt'));
  const r = await protectSite(d, { outDir: path.join(tmp, 'out-sym') });
  assert.ok(!new AdmZip(r.outputs.protectedZip).getEntries().some((e) => e.entryName === 'leak.txt'));
});

test('a PHP syntax error after patching rolls that file back (needs php)', { skip: !hasPhp && 'php not installed' }, async () => {
  const d = path.join(tmp, 'lint');
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, 'index.html'), '<html><head><title>x</title></head><body><form action="s.php" method="post"><input name="n"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form></body></html>');
  // a heredoc whose body contains our insertion point makes no difference; this file is already broken after the first line, so php -l fails with or without us
  fs.writeFileSync(path.join(d, 's.php'), "<?php\nmail('a@b.in','s',$_POST['message'] ;\n");
  const r = await protectSite(d, { dryRun: true });
  assert.equal(r.verification.rolledBack.length, 1);
  assert.equal(r.forms[0].outcome, 'failed');
  assert.equal(r.changes.some((c) => c.file === 's.php'), false);
});

// ------------------------------------------------------------------ bulk
test('bulk: many sites, one failure does not stop the batch, credentials stay private', async () => {
  const parent = path.join(tmp, 'many');
  fs.mkdirSync(parent, { recursive: true });
  for (const n of ['acme-dental', 'quick-ajax', 'wp-site', 'empty-site', 'include-form']) fs.cpSync(dirs[n], path.join(parent, n), { recursive: true });
  fs.writeFileSync(path.join(parent, 'broken.zip'), 'this is not a zip');
  const out = path.join(tmp, 'out-many');
  const b = await protectMany(parent, { outDir: out });
  assert.equal(b.totals.sites, 6);
  assert.equal(b.totals.protected, 3);
  assert.equal(b.totals.failed, 1);
  assert.equal(b.totals.untouched, 2);
  const cred = fs.readFileSync(path.join(out, 'PRIVATE-credentials.csv'), 'utf8');
  assert.equal(cred.trim().split('\n').length, 4, 'header + 3 protected sites');
  assert.ok(!fs.readFileSync(path.join(out, 'summary.csv'), 'utf8').match(/password/i));
  const pw = cred.trim().split('\n')[1].split(',')[2];
  assert.match(pw, /^[A-Za-z0-9]{16}$/, 'generated passwords are plain letters/digits');
  for (const n of ['acme-dental', 'quick-ajax', 'include-form']) assert.ok(fs.existsSync(path.join(out, n, n + '-protected.zip')), n);
  assert.ok(!fs.existsSync(path.join(out, 'wp-site', 'wp-site-protected.zip')));
  assert.throws(() => fs.accessSync(path.join(parent, 'acme-dental', 'spamguard')), 'input never modified');
});

// ------------------------------------------------------------------ the real thing: run the protected site under PHP
const startPhp = (docroot) =>
  new Promise((resolve, reject) => {
    const port = 20000 + Math.floor(Math.random() * 20000);
    const child = spawn('php', ['-S', `127.0.0.1:${port}`, '-t', docroot], { stdio: 'ignore' });
    const t0 = Date.now();
    const poll = () => {
      http.get({ host: '127.0.0.1', port, path: '/' }, (res) => { res.resume(); resolve({ port, stop: () => child.kill() }); }).on('error', () => {
        if (Date.now() - t0 > 8000) { child.kill(); reject(new Error('php server did not start')); } else setTimeout(poll, 100);
      });
    };
    poll();
  });
const req = (port, method, p, form, headers = {}) =>
  new Promise((resolve, reject) => {
    const body = form ? new URLSearchParams(form).toString() : null;
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: Object.assign(body ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {}, headers) }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });

test('REAL RUN under PHP: spam is blocked, a real person gets through, both with redirect and AJAX handlers', { skip: !hasPhp && 'php not installed', timeout: 60000 }, async () => {
  const d = path.join(tmp, 'live-src');
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, 'index.html'), '<html><head><title>Live</title></head><body><form action="contact.php" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form></body></html>');
  fs.writeFileSync(path.join(d, 'contact.php'), "<?php\nfile_put_contents(__DIR__ . '/received.log', $_POST['name'] . \"\\n\", FILE_APPEND);\nheader('Location: thank-you.html');\n");
  fs.writeFileSync(path.join(d, 'thank-you.html'), '<html><body>thanks</body></html>');
  fs.mkdirSync(path.join(d, 'ajax'), { recursive: true });
  fs.writeFileSync(path.join(d, 'ajax.html'), '<html><head><title>A</title></head><body><form id="f" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form><script src="js/ajax.js"></script></body></html>');
  fs.mkdirSync(path.join(d, 'js'), { recursive: true });
  fs.writeFileSync(path.join(d, 'js', 'ajax.js'), "$('#f').on('submit', function(e){ e.preventDefault(); $.ajax({ type:'POST', url:'ajax/save.php', data:$(this).serialize(), dataType:'json', success:function(res){ if(res.status=='OK'){ alert('sent'); } } }); });");
  fs.writeFileSync(path.join(d, 'ajax', 'save.php'), "<?php\nfile_put_contents(dirname(__DIR__) . '/ajax-received.log', $_POST['name'] . \"\\n\", FILE_APPEND);\nheader('Content-Type: application/json');\necho json_encode(['status' => 'OK', 'code' => 200]);\n");

  const r = await protectSite(d, { outDir: path.join(tmp, 'out-live'), keepFolder: true, password: 'Live-pass-123' });
  assert.equal(r.status, 'protected', JSON.stringify(r.forms));
  const site = r.outputs.folder;
  // control: the UNPROTECTED site really does let spam straight through
  const ctl = await startPhp(d);
  const spamBody = { name: 'SPAMBOT', email: 'x@mailinator.com', message: 'cheap seo http://a.com http://b.com http://c.com' };
  const c = await req(ctl.port, 'POST', '/contact.php', spamBody);
  ctl.stop();
  assert.equal(c.status, 302);
  assert.match(fs.readFileSync(path.join(d, 'received.log'), 'utf8'), /SPAMBOT/, 'control: unprotected site accepted the spam');
  fs.rmSync(path.join(d, 'received.log'));

  const srv = await startPhp(site);
  try {
    // the form page still loads, kit script tag is there
    const page = await req(srv.port, 'GET', '/index.html');
    assert.match(page.body, /spamguard\/spamguard\.js/);
    assert.equal((await req(srv.port, 'GET', '/spamguard/spamguard.js')).status, 200);
    // 1. spam: no token, honeypot filled -> looks like success, handler never runs
    const sp = await req(srv.port, 'POST', '/contact.php', Object.assign({ sg_website: 'http://spam', sg_i: '0' }, spamBody));
    assert.equal(sp.status, 303, 'bot is told "thanks" (redirect), not "blocked"');
    assert.match(sp.headers.location, /thank-you\.html/);
    assert.ok(!fs.existsSync(path.join(site, 'received.log')), 'spam never reached the original handler');
    // 2. AJAX spam gets the handler\'s own JSON shape
    const as = await req(srv.port, 'POST', '/ajax/save.php', Object.assign({ sg_website: 'x' }, spamBody), { 'X-Requested-With': 'XMLHttpRequest', Accept: 'application/json' });
    assert.deepEqual(JSON.parse(as.body), { status: 'OK', code: 200 });
    assert.ok(!fs.existsSync(path.join(site, 'ajax-received.log')));
    // 3. a real person: token from token.php, waits, then submits
    const tok = JSON.parse((await req(srv.port, 'GET', '/spamguard/token.php')).body).t;
    assert.ok(tok.length > 20);
    await new Promise((res) => setTimeout(res, 3300));
    const human = { name: 'Rahul Sharma', email: 'rahul.sharma@gmail.com', phone: '9876543210', message: 'I would like to know the price of a two bedroom flat and the possession date.', sg_t: tok, sg_i: '37', sg_website: '' };
    const ok = await req(srv.port, 'POST', '/contact.php', human, { 'User-Agent': 'Mozilla/5.0 (Macintosh) Safari/605' });
    assert.equal(ok.status, 302, 'real enquiry reaches the ORIGINAL handler (its own redirect)');
    assert.equal(fs.readFileSync(path.join(site, 'received.log'), 'utf8'), 'Rahul Sharma\n');
    const tok2 = JSON.parse((await req(srv.port, 'GET', '/spamguard/token.php')).body).t;
    await new Promise((res) => setTimeout(res, 3300));
    const ok2 = await req(srv.port, 'POST', '/ajax/save.php', Object.assign({}, human, { name: 'Priya Singh', email: 'priya.singh@gmail.com', sg_t: tok2 }), { 'X-Requested-With': 'XMLHttpRequest', Accept: 'application/json', 'User-Agent': 'Mozilla/5.0 (iPhone) Safari/604' });
    assert.deepEqual(JSON.parse(ok2.body), { status: 'OK', code: 200 });
    assert.equal(fs.readFileSync(path.join(site, 'ajax-received.log'), 'utf8'), 'Priya Singh\n');
    // 4. the admin page asks for a login and the password we set works
    const adm = await req(srv.port, 'GET', '/spamguard/spam-admin.php');
    assert.equal(adm.status, 200);
    assert.match(adm.body, /password/i);
  } finally {
    srv.stop();
  }
});

test('report text reads well and stays honest', async () => {
  const r = await protectSite(dirs['external-forms'], { dryRun: true });
  const t = renderProtectText(r);
  assert.match(t, /KUCH NAHI BADLA/);
  assert.match(t, /MANUAL BAAKI/);
  assert.ok(!/AB AAPKO KYA KARNA HAI/.test(t), 'no upload instructions when nothing changed');
});

test('site-wide hooks: one require line at the top of PHP pages, insertion-only, fail-open, idempotent', () => {
  const E = require('../src/injector/edits');
  const ap = (t, rel = '') => E.planApplyEdit(t, rel);
  const run = (t, rel) => { const p = ap(t, rel); assert.ok(!p.error, JSON.stringify(p)); return E.applyInsertions(t, [p]); };
  // starts with PHP
  let out = run('<?php\n$a = 1;\n?><html><head></head></html>');
  assert.match(out, /^<\?php\n\/\* SpamGuard:apply \*\/ if \(is_file\(__DIR__ \. '\/spamguard\/sg-apply\.php'\)\) \{ require_once __DIR__ \. '\/spamguard\/sg-apply\.php'; \} \/\* SpamGuard:apply-end \*\/\n\$a = 1;/);
  // declare + namespace stay first; BOM kept; CRLF kept
  out = run('\xEF\xBB\xBF<?php\r\ndeclare(strict_types=1);\r\nnamespace App;\r\necho 1;\r\n');
  assert.ok(out.startsWith('\xEF\xBB\xBF<?php\r\ndeclare(strict_types=1);\r\nnamespace App;\r\n/* SpamGuard:apply */'));
  // starts with HTML: a tiny PHP block in front, and the output of the page is byte-identical (PHP eats the one newline)
  out = run('<!doctype html>\n<html><head></head><body><?= $x ?></body></html>');
  assert.match(out, /^<\?php \/\* SpamGuard:apply \*\/.*\?>\n<!doctype html>\n/);
  // sub-folder pages climb to the site root
  assert.match(run('<html><head></head></html>', '../..'), /__DIR__ \. '\/..\/..\/spamguard\/sg-apply\.php'/);
  // idempotent
  assert.equal(ap(out).error, 'already');
  // refuse what we cannot do safely
  assert.equal(ap('<?php namespace A { echo 1; }').error, 'bracketed-namespace');
  assert.equal(ap('<? echo 1; ?><html></html>').error, 'short-open-tag');
  assert.equal(ap('<html></html><?php declare(strict_types=1);').error, 'declare-after-html');
  // contact.js goes before the last </body>, never inside PHP
  let j = E.planContactScriptEdit('<html><body>x</body></html>', '/spamguard/contact.js');
  assert.match(E.applyInsertions('<html><body>x</body></html>', [j]), /x\n<!-- SpamGuard:contact --><script src="\/spamguard\/contact\.js" defer><\/script>\n<\/body>/);
  assert.equal(E.planContactScriptEdit('<?php echo "</body>"; ?>', '/x.js').error, 'script-position-unsafe');
  assert.equal(E.planContactScriptEdit('<html></html>', '/x.js').error, 'no-body');
  assert.equal(E.planContactScriptEdit('<script src="/spamguard/contact.js"></script></body>', '/x.js').error, 'already');
});
