'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildFixtures, makeZip, zipFolder } = require('./helpers');
const { scanSite } = require('../src/scanner');
const { scanMany, writeBulkOutputs } = require('../src/scanner/bulk');
const { renderText, renderBulkText } = require('../src/scanner/report');
const { generateConfig, writeConfig, phpLit } = require('../src/config');

let tmp;
let dirs;
const cache = new Map();
const scan = async (name) => {
  if (!cache.has(name)) cache.set(name, await scanSite(dirs[name]));
  return cache.get(name);
};
const hasPhp = spawnSync('php', ['-v']).status === 0;

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-test-'));
  dirs = buildFixtures(path.join(tmp, 'sites'));
});
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

// ---------------------------------------------------------------- classic site
test('classic site: form, PHP handler, mail + MySQL, SQL dump, contacts, exposed backup', async () => {
  const r = await scan('acme-dental');
  assert.equal(r.site.platform, 'plain PHP');
  assert.equal(r.forms.length, 1);
  const f = r.forms[0];
  assert.equal(f.kind, 'enquiry');
  assert.equal(f.file, 'index.html');
  assert.equal(f.submitMode, 'classic');
  assert.deepEqual(f.fields.map((x) => x.name), ['name', 'email', 'phone', 'message']);
  assert.equal(f.handler.file, 'contact.php');
  assert.equal(f.plan.status, 'auto');
  assert.ok(f.handler.capabilities.sendsMail && f.handler.capabilities.usesDb);
  assert.deepEqual(f.handler.mailRecipients, ['owner@acmedental.in'], 'commented-out address must be ignored');
  assert.deepEqual(f.handler.tables.map((t) => t.table), ['enquiries']);
  assert.equal(f.handler.tables[0].inDump, 'backup/acme_db.sql');
  assert.equal(f.handler.response.redirect, 'thank-you.html');
  assert.ok(f.plan.actions.some((a) => a.type === 'add-script-tag' && a.file === 'index.html'));
  assert.ok(f.plan.actions.some((a) => a.type === 'add-guard-call' && a.file === 'contact.php'));

  assert.equal(r.database.used, true);
  assert.deepEqual(r.database.configFiles, ['inc/db.php']);
  assert.deepEqual(r.database.databaseNames, ['acme_db']);
  assert.equal(r.database.enquiryTables.length, 1);
  assert.equal(r.database.enquiryTables[0].name, 'enquiries');
  assert.ok(r.database.enquiryTables[0].columns.includes('email'));
  const users = r.database.sqlDumps[0].tables.find((t) => t.name === 'users');
  assert.equal(users.looksLikeEnquiries, false);

  assert.ok(r.security.exposedFiles.some((e) => e.file === 'backup/acme_db.sql' && e.kind === 'database-dump'));
  assert.equal(r.contacts.phones.length, 2, 'mobile and landline (0141 == +91 141) are two numbers');
  assert.ok(r.contacts.phones[0].count >= 3);
  assert.ok(r.contacts.emails.some((e) => e.value === 'info@acmedental.in'));
  const about = r.pages.find((p) => p.file === 'about.html');
  assert.equal(about.metaDescription, '');
  assert.equal(about.viewport, '');
  assert.equal(r.plan.siteActions.find((a) => a.type === 'write-config').notifyEmailGuess, 'owner@acmedental.in');
});

test('secrets and personal data never reach the report', async () => {
  for (const name of ['acme-dental', 'wp-site']) {
    const json = JSON.stringify(await scan(name)) + renderText(await scan(name));
    for (const secret of ['S3cretPass', 'wpSecret123', 'rahul.private', 'meena.secret', '9876500000']) {
      assert.ok(!json.includes(secret), `${name} report leaked ${secret}`);
    }
  }
});

// ---------------------------------------------------------------- zip handling
test('zip: Mac wrapper folder and __MACOSX junk are handled, result equals the folder scan', async () => {
  const zip = zipFolder(dirs['acme-dental'], path.join(tmp, 'acme-dental.zip'));
  const z = await scanSite(zip);
  const d = await scan('acme-dental');
  assert.equal(z.site.source, 'zip');
  assert.equal(z.site.files, d.site.files, 'junk files must not be counted');
  assert.deepEqual(z.summary, d.summary);
  assert.ok(z.warnings.some((w) => w.code === 'site-root-inside' && w.path === 'acme-dental'));
});

test('zip: path traversal, absolute paths and symlinks are refused and nothing is written outside', async () => {
  const id = 'sgevil' + process.pid + Date.now();
  const bad = makeZip([
    { name: `../${id}1.txt`, data: 'pwn' },
    { name: `../../${id}2.txt`, data: 'pwn' },
    { name: `sub/../../${id}3.txt`, data: 'pwn' },
    { name: `/tmp/${id}4.txt`, data: 'pwn' },
    { name: `C:\\win\\${id}5.txt`, data: 'pwn' },
    { name: 'link', data: '/etc/passwd', mode: 0o120777 },
    { name: 'site/index.html', data: '<html><body><h1>fine</h1><form><input name="email"><textarea name="m"></textarea></form></body></html>' },
  ]);
  const zp = path.join(tmp, 'evil.zip');
  fs.writeFileSync(zp, bad);
  const r = await scanSite(zp);
  assert.equal(r.site.files, 1);
  assert.ok(r.warnings.filter((w) => w.code === 'zip-unsafe-path').length >= 4, JSON.stringify(r.warnings));
  assert.ok(r.warnings.some((w) => w.code === 'zip-symlink-skipped'));
  for (const base of [os.tmpdir(), path.dirname(os.tmpdir()), '/tmp', tmp]) {
    for (let i = 1; i <= 5; i++) assert.equal(fs.existsSync(path.join(base, `${id}${i}.txt`)), false, `escaped to ${base}`);
  }
});

test('zip: extracted temp folder is cleaned up afterwards', async () => {
  const before = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('sg-scan-')).length;
  await scanSite(zipFolder(dirs['quick-ajax'], path.join(tmp, 'qa.zip')));
  const after = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('sg-scan-')).length;
  assert.equal(after, before);
});

test('bad input gives a clear error', async () => {
  await assert.rejects(scanSite(path.join(tmp, 'nope')), /Path nahi mila/);
  fs.writeFileSync(path.join(tmp, 'x.txt'), 'hi');
  await assert.rejects(scanSite(path.join(tmp, 'x.txt')), /folder ya \.zip/);
  fs.writeFileSync(path.join(tmp, 'garbage.zip'), 'not a zip at all');
  await assert.rejects(scanSite(path.join(tmp, 'garbage.zip')), /ZIP/);
});

// ---------------------------------------------------------------- AJAX
test('AJAX (jQuery): form linked to its ajax call, JSON success answer read from the handler, libraries ignored', async () => {
  const r = await scan('quick-ajax');
  const f = r.forms[0];
  assert.equal(f.submitMode, 'ajax');
  assert.equal(f.ajax.kind, 'jquery-ajax');
  assert.equal(f.ajax.confidence, 'high');
  assert.equal(f.handler.file, 'send.php', 'the minified jquery file must not be used');
  assert.deepEqual(f.handler.response.successJson, { status: 'success', message: 'Thanks, we will call you soon' });
  assert.equal(f.plan.status, 'auto');
  assert.ok(f.plan.actions.some((a) => a.type === 'set-success-response' && a.json.status === 'success'));
  assert.equal(r.database.used, false);
});

test('AJAX (fetch, external js): success answer unknown => needs review, not silently guessed', async () => {
  const f = (await scan('fetch-unknown')).forms[0];
  assert.equal(f.submitMode, 'ajax');
  assert.equal(f.ajax.kind, 'fetch');
  assert.equal(f.handler.file, 'process.php');
  assert.equal(f.plan.status, 'review');
  assert.ok(f.plan.reasons.some((x) => x.code === 'ajax-response-unknown'));
});

// ---------------------------------------------------------------- things that must not be touched
test('external services, mailto, login, search and action-less html forms are classified correctly', async () => {
  const r = await scan('external-forms');
  const by = (pred) => r.forms.find(pred);
  assert.equal(by((f) => f.action.service === 'Formspree').plan.status, 'manual');
  assert.equal(by((f) => f.action.service === 'Mailchimp').plan.status, 'manual');
  assert.equal(by((f) => f.action.type === 'mailto').plan.reasons[0].code, 'mailto-form');
  assert.equal(by((f) => f.kind === 'login').plan.status, 'skip');
  assert.equal(by((f) => f.kind === 'search').plan.status, 'skip');
  const none = by((f) => f.file === 'action-empty.html');
  assert.equal(none.plan.status, 'manual');
  assert.equal(none.plan.reasons[0].code, 'handler-not-php');
  assert.equal(r.summary.auto + r.summary.review, 0);
});

test('WordPress is recognised and left alone', async () => {
  const r = await scan('wp-site');
  assert.equal(r.site.platform, 'WordPress');
  assert.deepEqual(r.site.cmsFormPlugins, ['contact-form-7']);
  assert.ok(r.forms.every((f) => ['manual', 'skip'].includes(f.plan.status)));
  assert.ok(r.forms.some((f) => f.plan.reasons.some((x) => x.code === 'cms')));
});

test('form printed by PHP is manual, and site code is never executed', async () => {
  const r = await scan('php-generated');
  assert.equal(r.forms[0].plan.status, 'manual');
  assert.equal(r.forms[0].plan.reasons[0].code, 'php-generated');
  assert.equal(fs.existsSync(path.join(dirs['php-generated'], 'EXECUTED.txt')), false, 'scanner must never run PHP from the site');
});

// ---------------------------------------------------------------- other shapes
test('SpamGuard already installed is recognised as done, with nothing left to do', async () => {
  const r = await scan('already-protected');
  assert.equal(r.forms[0].plan.status, 'done');
  assert.deepEqual(r.forms[0].plan.actions, []);
  assert.equal(r.site.siteFiles.spamguardInstalled, true);
});

test('form that posts to its own page (PHP_SELF) uses that page as handler', async () => {
  const f = (await scan('self-post')).forms[0];
  assert.equal(f.action.type, 'self');
  assert.equal(f.handler.file, 'contact.php');
  assert.equal(f.plan.status, 'auto');
});

test('form inside a shared include: found once, pages that show it are listed, root-relative handler resolved', async () => {
  const r = await scan('include-form');
  assert.equal(r.forms.length, 1);
  const f = r.forms[0];
  assert.equal(f.file, 'footer.php');
  assert.deepEqual(f.pagesUsing.slice().sort(), ['about.php', 'index.php']);
  assert.equal(f.handler.file, 'lead-handler.php');
  assert.ok(f.handler.capabilities.writesFile);
  assert.equal(f.handler.response.redirect, '/index.php?sent=1');
  assert.equal(f.plan.status, 'auto');
  assert.equal(r.pages.length, 2, 'header/footer/handler are not counted as pages');
});

test('login + enquiry form sharing one handler needs review', async () => {
  const r = await scan('mixed-handler');
  const e = r.forms.find((f) => f.kind === 'enquiry');
  assert.equal(e.plan.status, 'review');
  assert.ok(e.plan.reasons.some((x) => x.code === 'shared-handler-multiple-forms'));
  assert.equal(r.forms.find((f) => f.kind === 'login').plan.status, 'skip');
});

test('site with nothing in it warns instead of crashing', async () => {
  const r = await scan('empty-site');
  assert.equal(r.forms.length, 0);
  assert.ok(r.warnings.some((w) => w.code === 'no-pages'));
});

// ---------------------------------------------------------------- report text
test('Hinglish report shows the important things in plain words', async () => {
  const t = renderText(await scan('acme-dental'));
  for (const s of ['AUTO', 'DATABASE: haan (mysqli)', 'Enquiry table: enquiries', 'bhejta hai: contact.php', 'mail bhejta hai', 'Database ka backup']) {
    assert.ok(t.includes(s), 'missing: ' + s);
  }
  assert.ok(renderText(await scan('external-forms')).includes('Formspree'));
});

// ---------------------------------------------------------------- bulk
test('bulk: folders + zips + a broken zip + a hostile folder name; one bad site never stops the batch', async () => {
  const parent = path.join(tmp, 'bulk');
  fs.mkdirSync(parent);
  for (const n of ['acme-dental', 'quick-ajax', 'external-forms', 'wp-site', 'empty-site']) fs.cpSync(dirs[n], path.join(parent, n), { recursive: true });
  zipFolder(dirs['self-post'], path.join(parent, 'self-post.zip'));
  fs.writeFileSync(path.join(parent, 'broken.zip'), 'this is not a zip');
  fs.mkdirSync(path.join(parent, '=evil'));
  fs.writeFileSync(path.join(parent, '=evil', 'index.html'), '<html><body><h1>x</h1></body></html>');
  const seen = [];
  const bulk = await scanMany(parent, { onProgress: (p) => seen.push(p.done + '/' + p.total) });
  assert.equal(bulk.totals.sites, 8);
  assert.equal(bulk.totals.failed, 1);
  assert.equal(bulk.totals.ok, 7);
  assert.equal(seen.length, 8);
  assert.equal(seen[7], '8/8');
  assert.equal(bulk.rows.find((r) => r.name === 'broken').status, 'failed');
  assert.equal(bulk.rows.find((r) => r.name === 'self-post').auto, 1);
  assert.equal(bulk.rows.find((r) => r.name === 'acme-dental').db, 'yes');
  assert.equal(bulk.totals.withExposed, 1);

  const out = path.join(tmp, 'bulk-out');
  writeBulkOutputs(bulk, out);
  const csv = fs.readFileSync(path.join(out, 'summary.csv'), 'utf8');
  assert.equal(csv.trim().split('\n').length, 9, 'header + 8 rows');
  assert.ok(csv.includes("'=evil"), 'spreadsheet formula injection must be neutralised');
  assert.ok(!csv.includes(',=evil,') && !/^=evil/m.test(csv));
  assert.ok(fs.existsSync(path.join(out, 'reports', 'quick-ajax.json')));
  assert.ok(fs.readFileSync(path.join(out, 'reports', 'broken.txt'), 'utf8').includes('FAIL'));
  assert.ok(renderBulkText(bulk).includes('BULK SCAN: 8 sites'));
});

test('bulk: pointing it at a single site folder warns', async () => {
  const b = await scanMany(dirs['acme-dental']);
  assert.ok(b.warnings.some((w) => w.code === 'parent-looks-like-site'));
});

// ---------------------------------------------------------------- config generator
test('phpLit writes valid PHP for tricky values', { skip: !hasPhp }, () => {
  const value = { a: "it's a \\ \"quote\" $notvar {$x}", b: [1, 2.5, true, false, null], c: { d: 'हिन्दी ✓', e: '' } };
  const r = spawnSync('php', ['-r', `echo json_encode(${phpLit(value)}, JSON_UNESCAPED_UNICODE);`]);
  assert.equal(r.status, 0, r.stderr.toString());
  assert.deepEqual(JSON.parse(r.stdout.toString()), value);
});

test('config: refuses weak password and accidental overwrite', () => {
  assert.throws(() => generateConfig({ password: 'short' }), /8 characters/);
  const f = path.join(tmp, 'cfg-overwrite', 'config.php');
  writeConfig(f, { siteId: 'x' });
  assert.throws(() => writeConfig(f, { siteId: 'x' }), /pehle se hai/);
  writeConfig(f, { siteId: 'x', force: true });
});

test('config.php made WITHOUT php works with the real PHP kit (password, portable data dir, real check)', { skip: !hasPhp }, () => {
  const site = path.join(tmp, 'cfgsite');
  fs.cpSync(path.join(__dirname, '..', 'kit', 'spamguard'), path.join(site, 'spamguard'), { recursive: true });
  const g = writeConfig(path.join(site, 'spamguard', 'config.php'), { siteId: 'Test Site', password: 'Test#Pass123', notifyEmail: 'o@x.in', quarantine: true });
  assert.equal(g.generatedPassword, false);
  const code = `
    require 'spamguard/spamguard.php';
    $c = SpamGuard::config();
    echo password_verify('Test#Pass123', $c['admin_password_hash']) ? "PW_OK\\n" : "PW_BAD\\n";
    echo password_verify('wrong', $c['admin_password_hash']) ? "WRONG_ACCEPTED\\n" : "WRONG_REJECTED\\n";
    echo strpos($c['data_dir'], __DIR__ . '/spamguard/sg-data-') === 0 ? "DIR_OK\\n" : "DIR_BAD " . $c['data_dir'] . "\\n";
    echo $c['suspicious_action'], "\\n";
    $t = SpamGuard::makeToken(time() - 20);
    $r = SpamGuard::check(['name' => 'A', 'email' => 'a@gmail.com', 'message' => 'Hello I need a price list for your services please', 'sg_t' => $t, 'sg_i' => '5'], ['REMOTE_ADDR' => '1.2.3.4', 'HTTP_USER_AGENT' => 'Mozilla/5.0 Safari']);
    echo $r['status'], ' ', $r['logged'] ? "LOGGED" : "NOT_LOGGED", "\\n";`;
  const r = spawnSync('php', ['-r', code], { cwd: site });
  const out = r.stdout.toString();
  assert.equal(r.status, 0, r.stderr.toString() + out);
  assert.match(out, /PW_OK/);
  assert.match(out, /WRONG_REJECTED/);
  assert.match(out, /DIR_OK/);
  assert.match(out, /quarantine/);
  assert.match(out, /real LOGGED/);
});

test('scanner recognises its own installed kit on a site that uses a Studio-made config', async () => {
  const site = path.join(tmp, 'cfgsite');
  if (!fs.existsSync(site)) return;
  fs.writeFileSync(path.join(site, 'index.html'), '<html><body><h1>hello there</h1></body></html>');
  const r = await scanSite(site);
  assert.equal(r.site.siteFiles.spamguardInstalled, true);
  assert.equal(r.forms.length, 0, 'the kit folder itself must not be scanned as customer forms');
});

test('regression: id-only inputs + long $.ajax options (real template pattern) still link to the PHP handler', async () => {
  const d = path.join(tmp, 'idajax');
  fs.mkdirSync(path.join(d, 'js'), { recursive: true });
  fs.mkdirSync(path.join(d, 'mail'), { recursive: true });
  fs.writeFileSync(path.join(d, 'index.html'), '<!DOCTYPE html><html><head><title>T</title></head><body><form id="contactForm" novalidate><input id="name" type="text"><input id="email" type="email"><textarea id="message"></textarea><button type="submit">Send</button></form><script src="js/contact_me.js"></script></body></html>');
  fs.writeFileSync(path.join(d, 'js', 'contact_me.js'), '$(function(){ $("input,textarea").jqBootstrapValidation({ submitSuccess: function($f, e){ e.preventDefault(); var name=$("input#name").val(); var email=$("input#email").val(); var message=$("textarea#message").val();\n$.ajax({ url: "././mail/contact_me.php", type: "POST", data: { name: name, email: email, message: message }, cache: false, success: function(){ $("#success").html("<div class=\'alert\'>"); $("#success > .alert").append("<strong>Your message has been sent.</strong>"); $("#contactForm").trigger("reset"); }, error: function(){ $("#success").html("<div>error</div>"); } }); } }); });');
  fs.writeFileSync(path.join(d, 'mail', 'contact_me.php'), '<?php\nif(empty($_POST[\'name\'])||empty($_POST[\'email\'])){ echo "No arguments Provided!"; return false; }\n$name = strip_tags($_POST[\'name\']);\nmail("me@x.in","Contact",$name);\nreturn true;\n');
  const r = await scanSite(d);
  const f = r.forms[0];
  assert.equal(f.submitMode, 'ajax');
  assert.equal(f.handler.file, 'mail/contact_me.php');
  assert.deepEqual(f.fields.map((x) => x.id), ['name', 'email', 'message']);
  assert.notEqual(f.plan.status, 'manual');
});
