'use strict';
/**
 * The whole chain on real software: Studio protects a site and registers it at the hub (real PHP + real MariaDB),
 * the protected site runs under PHP, a visitor sends spam and a real enquiry, and the hub shows the lead and the counts.
 * Skipped unless php>=8.1, a mysql/mariadb client with root access, and the hub sources (../spamguard-hub/hub) exist.
 */
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { protectSite } = require('../src/injector');
const { renderProtectText } = require('../src/injector/report');
const { provisionSite, normalizeUrl } = require('../src/hub');

const HUB_SRC = process.env.HUB_DIR || path.resolve(__dirname, '..', '..', 'spamguard-hub', 'hub');
const cli = ['mariadb', 'mysql'].find((c) => spawnSync(c, ['--version']).status === 0);
const phpOk = spawnSync('php', ['-r', 'exit(PHP_VERSION_ID >= 80100 ? 0 : 1);']).status === 0;
const SKIP = !cli || !phpOk || !fs.existsSync(path.join(HUB_SRC, 'install.php')) ? 'needs php>=8.1, mysql/mariadb root access and ../spamguard-hub/hub' : false;
const DBUSER = process.env.HUB_TEST_DB_USER || 'hub';
const DBPASS = process.env.HUB_TEST_DB_PASS || 'hubpass';
const DBNAME = 'hubtest_e2e_' + process.pid + '_' + Date.now().toString(36);
const sql = (q) => spawnSync(cli, ['-uroot', '-N', '-B', DBNAME, '-e', q], { encoding: 'utf8' }).stdout.trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let tmp, hubProc, siteProc, HUB, TOKEN;
const jar = {};
async function hubReq(method, p, form) {
  const h = {};
  if (Object.keys(jar).length) h.Cookie = Object.entries(jar).map(([k, v]) => k + '=' + v).join('; ');
  let body;
  if (form) { body = new URLSearchParams(form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; }
  const res = await fetch(HUB + p, { method, headers: h, body, redirect: 'manual' });
  for (const c of res.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); jar[kv.slice(0, i)] = kv.slice(i + 1); }
  return { status: res.status, text: await res.text() };
}
async function start(docroot) {
  const port = 20000 + Math.floor(Math.random() * 30000);
  const p = spawn('php', ['-S', `127.0.0.1:${port}`, '-t', docroot], { stdio: 'ignore' });
  for (let i = 0; i < 60; i++) { try { await fetch(`http://127.0.0.1:${port}/x`); break; } catch (e) { await sleep(100); } }
  return { port, p, base: `http://127.0.0.1:${port}` };
}

before(async () => {
  if (SKIP) return;
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-hube2e-'));
  const hubRoot = path.join(tmp, 'hub');
  fs.cpSync(HUB_SRC, hubRoot, { recursive: true });
  fs.rmSync(path.join(hubRoot, 'lib', 'config.php'), { force: true });
  spawnSync(cli, ['-uroot', '-e', `CREATE DATABASE \`${DBNAME}\` CHARACTER SET utf8mb4; GRANT ALL ON \`${DBNAME}\`.* TO '${DBUSER}'@'127.0.0.1'; GRANT ALL ON \`${DBNAME}\`.* TO '${DBUSER}'@'localhost';`]);
  const h = await start(hubRoot);
  hubProc = h.p;
  HUB = h.base;
  const page = await hubReq('GET', '/install.php');
  const csrf = /name="_csrf" value="([a-f0-9]+)"/.exec(page.text)[1];
  const r = await hubReq('POST', '/install.php', { _csrf: csrf, db_host: '127.0.0.1', db_name: DBNAME, db_user: DBUSER, db_pass: DBPASS, name: 'Admin', email: 'a@example.com', password: 'a-long-password-1', timezone: 'Asia/Kolkata' });
  TOKEN = /<code id="tok">([A-Za-z0-9]{40})<\/code>/.exec(r.text)[1];
});
after(() => {
  if (SKIP) return;
  hubProc && hubProc.kill();
  siteProc && siteProc.p.kill();
  spawnSync(cli, ['-uroot', '-e', `DROP DATABASE IF EXISTS \`${DBNAME}\``]);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('hub address rules: https only (http only for the local machine), no credentials, tidy path', () => {
  assert.equal(normalizeUrl('https://hub.example.com/'), 'https://hub.example.com');
  assert.equal(normalizeUrl('https://hub.example.com/panel/index.php'), 'https://hub.example.com/panel');
  assert.equal(normalizeUrl('http://127.0.0.1:8080'), 'http://127.0.0.1:8080');
  assert.throws(() => normalizeUrl('http://hub.example.com'), /https/);
  assert.throws(() => normalizeUrl('https://user:pw@hub.example.com'), /username/);
  assert.throws(() => normalizeUrl('not a url'), /galat/);
});

test('provisioning: wrong token, bad token shape and a dead address give readable errors', { skip: SKIP }, async () => {
  await assert.rejects(() => provisionSite({ url: HUB, token: 'A'.repeat(40) }, 'x'), /token nahi manaa/);
  await assert.rejects(() => provisionSite({ url: HUB, token: 'short' }, 'x'), /token galat/);
  await assert.rejects(() => provisionSite({ url: 'http://127.0.0.1:1', token: TOKEN }, 'x', { timeoutMs: 3000 }), /connect nahi hua/);
  assert.equal(sql('SELECT COUNT(*) FROM sites'), '0', 'nothing was created by the failed attempts');
});

let SITE_DIR, OUT, res;
test('Studio protects a site AND registers it at the hub; config carries the keys', { skip: SKIP, timeout: 60000 }, async () => {
  SITE_DIR = path.join(tmp, 'sites', 'acmedental.in');
  fs.mkdirSync(SITE_DIR, { recursive: true });
  fs.writeFileSync(path.join(SITE_DIR, 'index.html'), '<html><head><title>Acme</title></head><body><p>Call <span id="ph">98765 43210</span> or <a id="tl" href="tel:+919876543210">tap to call</a></p><form action="contact.php" method="post"><input name="name"><input type="email" name="email"><input name="phone"><textarea name="message"></textarea><button>Send</button></form></body></html>');
  fs.writeFileSync(path.join(SITE_DIR, 'contact.php'), "<?php\nfile_put_contents(__DIR__ . '/received.log', $_POST['name'] . \"\\n\", FILE_APPEND);\nheader('Location: thank-you.html');\n");
  fs.writeFileSync(path.join(SITE_DIR, 'about.php'), '<?php $x = 1; ?>\n<!doctype html>\n<html><head><title>About us</title><meta name="description" content="old description"></head><body><h1>About</h1><p>Call 98765 43210 or write to old@acme.in. We are at 5 Old Street, Jaipur.</p><a href="tel:+919876543210">Phone</a></body></html>\n');
  fs.writeFileSync(path.join(SITE_DIR, 'thank-you.html'), '<html><body>thanks</body></html>');
  OUT = path.join(tmp, 'out');

  const dry = await protectSite(SITE_DIR, { dryRun: true, hub: { url: HUB, token: TOKEN } });
  assert.equal(dry.hub.status, 'dry-run');
  assert.equal(sql('SELECT COUNT(*) FROM sites'), '0', 'a dry run never registers anything');

  res = await protectSite(SITE_DIR, { outDir: OUT, keepFolder: true, hub: { url: HUB, token: TOKEN } });
  assert.equal(res.status, 'protected');
  assert.equal(res.hub.status, 'connected');
  assert.equal(sql('SELECT COUNT(*) FROM sites'), '1');
  assert.equal(sql('SELECT name FROM sites'), 'acmedental.in');
  assert.equal(sql('SELECT domain FROM sites'), 'acmedental.in', 'a folder named like a domain fills the domain');
  const cfg = fs.readFileSync(path.join(res.outputs.folder, 'spamguard', 'config.php'), 'utf8');
  assert.match(cfg, /'hub' => \[/);
  assert.match(cfg, new RegExp(`'url' => '${HUB.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&')}'`));
  assert.match(cfg, /'site_key' => '[A-Za-z0-9]{24}'/);
  assert.match(cfg, /'secret' => '[a-f0-9]{48}'/);
  assert.ok(!JSON.stringify(res).includes(TOKEN), 'the provision token is nowhere in the result');
  assert.match(renderProtectText(res), /HUB: connect ho gaya/);
  const again = await protectSite(res.outputs.folder, { outDir: path.join(tmp, 'out2'), hub: { url: HUB, token: TOKEN } });
  assert.equal(again.changes.length, 0);
  assert.equal(sql('SELECT COUNT(*) FROM sites'), '1', 're-running on an already protected site creates no duplicate hub entry');
});

test('a hub failure never blocks protection; the report says exactly what to do', { skip: SKIP }, async () => {
  const r = await protectSite(SITE_DIR, { dryRun: false, outDir: path.join(tmp, 'out3'), hub: { url: HUB, token: 'B'.repeat(40) } });
  assert.equal(r.status, 'protected');
  assert.equal(r.hub.status, 'failed');
  assert.match(renderProtectText(r), /HUB: connect NAHI hua.*Site protect ho gayi hai/s);
  const zip = new (require('adm-zip'))(r.outputs.protectedZip);
  assert.ok(!/'hub' => \[\s*'url' => 'http/.test(zip.readAsText('spamguard/config.php')), 'config has no half-filled hub block');
  assert.equal(sql('SELECT COUNT(*) FROM sites'), '1');
});

test('LIVE: protected site runs under PHP; spam is blocked; the real enquiry reaches the hub; counts + status show up', { skip: SKIP, timeout: 90000 }, async () => {
  const dir = res.outputs.folder;
  siteProc = await start(dir);
  const S = siteProc.base;
  const site = () => sql("SELECT CONCAT(IFNULL(kit_version,''),'|',IFNULL(php_version,''),'|',IFNULL(storage,'')) FROM sites ORDER BY id LIMIT 1");
  assert.equal(sql('SELECT last_seen_at IS NULL FROM sites ORDER BY id LIMIT 1'), '1', 'before any visit the hub has never heard from the site');

  // a page view asks token.php for a token: that is the heartbeat clock
  const tok = JSON.parse(await (await fetch(S + '/spamguard/token.php')).text()).t;
  assert.ok(tok.length > 20);
  await sleep(500);
  assert.match(site(), /^1\.4\.0\|8\./, 'first heartbeat arrived: kit version + php version');
  assert.equal(sql('SELECT last_seen_at IS NOT NULL FROM sites ORDER BY id LIMIT 1'), '1');

  // a real person
  await sleep(3300);
  const human = await fetch(S + '/contact.php', { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0 (Macintosh) Safari/605' },
    body: new URLSearchParams({ name: 'Rahul Sharma', email: 'rahul.sharma@gmail.com', phone: '9876543210', message: 'Price of the two bedroom flat and the possession date please.', sg_t: tok, sg_i: '37', sg_website: '', sg_page: 'https://acmedental.in/contact', sg_utm_source: 'google', sg_gclid: 'G123' }) });
  assert.equal(human.status, 302, 'the original handler answered (its own redirect)');
  assert.equal(fs.readFileSync(path.join(dir, 'received.log'), 'utf8'), 'Rahul Sharma\n');

  // spam: honeypot filled, no token
  for (let i = 0; i < 3; i++) {
    const r = await fetch(S + '/contact.php', { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/8' }, body: new URLSearchParams({ name: 'SPAMBOT' + i, email: `b${i}@mailinator.com`, message: 'cheap seo http://a.com http://b.com', sg_website: 'http://spam' }) });
    assert.equal(r.status, 303);
  }
  assert.equal(fs.readFileSync(path.join(dir, 'received.log'), 'utf8'), 'Rahul Sharma\n', 'spam never reached the original handler');

  await sleep(500);

  // the lead is at the hub, with everything the owner needs
  assert.equal(sql('SELECT COUNT(*) FROM leads'), '1', 'exactly one lead: the real one');
  assert.equal(sql('SELECT CONCAT(name,"|",email,"|",phone,"|",status,"|",utm_source,"|",gclid) FROM leads'), 'Rahul Sharma|rahul.sharma@gmail.com|9876543210|real|google|G123');
  assert.ok(!sql('SELECT GROUP_CONCAT(message) FROM leads').includes('SPAMBOT'));
  assert.equal(sql("SELECT COUNT(*) FROM leads WHERE page LIKE '%/contact'"), '1');

  // force the next heartbeat (as if 6 hours passed) and check the daily counts
  const dataDir = fs.readdirSync(path.join(dir, 'spamguard')).find((n) => n.startsWith('sg-data-'));
  fs.rmSync(path.join(dir, 'spamguard', dataDir, 'hub.beat'), { force: true });
  await fetch(S + '/spamguard/token.php');
  await sleep(500);
  assert.equal(sql('SELECT CONCAT(SUM(real_n),"/",SUM(spam_n)) FROM daily_stats'), '1/3', 'hub knows: 1 real, 3 spam blocked');

  // and the owner sees it in the dashboard
  const login = await hubReq('GET', '/login.php');
  const csrf = /name="_csrf" value="([a-f0-9]+)"/.exec(login.text)[1];
  await hubReq('POST', '/login.php', { _csrf: csrf, email: 'a@example.com', password: 'a-long-password-1' });
  const dash = await hubReq('GET', '/index.php');
  assert.match(dash.text, /Rahul Sharma/);
  assert.match(dash.text, /Spam roka/);
  const sites = await hubReq('GET', '/sites.php');
  assert.match(sites.text, /acmedental\.in/);
  assert.match(sites.text, />Live</);
  assert.match(sites.text, />ON</);
});

test('LIVE: site-wide hooks were added; contact details and SEO edits made at the hub reach the real pages', { skip: SKIP, timeout: 120000 }, async () => {
  const dir = res.outputs.folder;
  const S = siteProc.base;
  // what Studio put into the site
  const about = fs.readFileSync(path.join(dir, 'about.php'), 'utf8');
  assert.match(about, /^<\?php \/\* SpamGuard:apply \*\/.*\$x = 1; \?>/, 'about.php already started with PHP: the line goes right after <?php');
  assert.match(about, /SpamGuard:apply \*\/ if \(is_file\(__DIR__ \. '\/spamguard\/sg-apply\.php'\)\)/);
  assert.match(fs.readFileSync(path.join(dir, 'index.html'), 'utf8'), /<!-- SpamGuard:contact --><script src="\/spamguard\/contact\.js" defer><\/script>\s*<\/body>/);
  assert.ok(res.siteWide.enabled && res.siteWide.phpPages >= 1 && res.siteWide.jsPages >= 2, JSON.stringify(res.siteWide));
  assert.match(renderProtectText(res), /HUB se jude hooks/);
  assert.ok(!fs.readFileSync(path.join(dir, 'spamguard', 'sg-apply.php'), 'utf8').includes('<?php\n// '), 'kit has the apply file');
  assert.equal(fs.readFileSync(path.join(dir, 'thank-you.html'), 'utf8').includes('contact.js'), true, 'every HTML page gets the contact script');
  const sp = fs.readFileSync(path.join(dir, 'spamguard', 'sg-apply.php'), 'utf8');
  assert.match(sp, /SgApply::start\(\)/);

  // nothing at the hub yet: the page is served exactly as before
  const before = await (await fetch(S + '/about.php')).text();
  assert.match(before, /<title>About us<\/title>/);
  assert.match(before, /Call 98765 43210/);

  // the owner edits contact details + one page's SEO at the hub
  const sid = sql('SELECT id FROM sites LIMIT 1');
  const form = async (p, data, from = p) => {
    const pg = await hubReq('GET', from);
    const csrf = /name="_csrf" value="([a-f0-9]+)"/.exec(pg.text)[1];
    return hubReq('POST', p, Object.assign({ _csrf: csrf }, data));
  };
  let r = await form('/contact-edit.php', { id: sid, f_phone: '+91 99999 11111', f_whatsapp: '+919999911111', f_email: 'hello@acmedental.in', f_address: '12 New Road, Jaipur', old_phone: '98765 43210', old_email: 'old@acme.in', old_address: '5 Old Street, Jaipur', custom: 'rera=P5210' }, `/contact-edit.php?id=${sid}`);
  assert.equal(r.status, 303);
  await form('/seo-site.php', { id: sid, do: 'addpage', path: '/about.php' }, `/seo-site.php?id=${sid}`);
  const h = require('crypto').createHash('md5').update('/about.php').digest('hex');
  r = await form('/seo-page.php', { id: sid, h, do: 'ovr', title: 'About Acme Dental | Jaipur', description: 'Family dentist in Jaipur. Book your visit today.', og_image: 'https://acmedental.in/og.jpg', canonical: '', robots: 'index,follow', schema_json: '{"@context":"https://schema.org","@type":"Dentist","name":"Acme Dental","telephone":"98765 43210"}' }, `/seo-page.php?id=${sid}&h=${h}`);
  assert.equal(r.status, 303);

  // the site picks it up on its own (no cron): the contact endpoint is the page-view clock
  const dataDir = fs.readdirSync(path.join(dir, 'spamguard')).find((n) => n.startsWith('sg-data-'));
  fs.rmSync(path.join(dir, 'spamguard', dataDir, 'hub.sync'), { force: true });
  await fetch(S + '/spamguard/contact.php');
  await sleep(800);
  const c = await (await fetch(S + '/spamguard/contact.php')).json();
  assert.equal(c.v, 1);
  assert.equal(c.f.phone, '+91 99999 11111');
  assert.equal(c.custom.rera, 'P5210');
  assert.deepEqual(c.legacy.phone, ['98765 43210']);
  assert.ok(fs.existsSync(path.join(dir, 'spamguard', dataDir, 'seo.json')));
  assert.match(fs.readFileSync(path.join(dir, 'spamguard', '.htaccess'), 'utf8'), /sg-apply/, 'apply file is not downloadable');

  // the real page, rewritten on its way out (SEO + contact), valid HTML kept
  const after = await (await fetch(S + '/about.php')).text();
  assert.match(after, /<title>About Acme Dental \| Jaipur<\/title>/);
  assert.equal((after.match(/<title>/g) || []).length, 1);
  assert.match(after, /<meta name="description" content="Family dentist in Jaipur\. Book your visit today\.">/);
  assert.ok(!after.includes('old description'));
  assert.match(after, /property="og:image" content="https:\/\/acmedental\.in\/og\.jpg"/);
  assert.match(after, /"@type":"Dentist"/);
  assert.match(after, /Call \+91 99999 11111 or write to hello@acmedental\.in\. We are at 12 New Road, Jaipur\./);
  assert.match(after, /href="tel:\+919999911111"/);
  assert.ok(!after.includes('98765 43210') || /"telephone":"\+91 99999 11111"/.test(after), 'the phone inside the schema is swapped too');
  // other pages and the form handler are untouched
  assert.equal(await (await fetch(S + '/thank-you.html')).text().then((t) => t.includes('thanks')), true);
  const post = await fetch(S + '/contact.php', { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/8' }, body: new URLSearchParams({ name: 'X', sg_website: 'bot' }) });
  assert.equal(post.status, 303, 'forms still work through the guard');

  // the hub shows "laga hua" for both
  await sleep(300);
  assert.match((await hubReq('GET', `/contact-edit.php?id=${sid}`)).text, /Site par laga hai \(v1\)/);
  assert.equal(sql(`SELECT ovr_synced_version FROM seo_sites WHERE site_id=${sid}`), '1');

  // a browser: contact.js swaps old numbers in the static page and on tel: links
  let chromium;
  try { chromium = require('playwright').chromium; } catch (e) { return; }
  const b = await chromium.launch({ executablePath: fs.existsSync('/opt/pw-browsers/chromium') ? undefined : undefined, args: ['--no-sandbox'] }).catch(() => null);
  if (!b) return;
  try {
    const pg = await b.newPage();
    const errs = [];
    pg.on('pageerror', (e) => errs.push(String(e)));
    await pg.goto(S + '/index.html');
    await pg.waitForFunction(() => document.getElementById('ph').textContent.includes('99999'), null, { timeout: 8000 });
    assert.equal(await pg.textContent('#ph'), '+91 99999 11111');
    assert.equal(await pg.getAttribute('#tl', 'href'), 'tel:+919999911111');
    assert.deepEqual(errs, []);
  } finally { await b.close(); }
});
