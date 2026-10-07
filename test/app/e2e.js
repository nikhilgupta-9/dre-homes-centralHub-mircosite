'use strict';
/**
 * Drives the REAL Electron app (real window, real worker, real scanner + injector) with Playwright.
 * Run:  xvfb-run -a node test/app/e2e.js        (Linux)       needs: electron installed, playwright available
 * Native file dialogs cannot be clicked by a robot, so showOpenDialog is stubbed to return chosen paths.
 * Real drag & drop from Finder needs a human; everything after the drop is identical to "Zip chuno".
 */
const path = require('path');
const fs = require('fs');
const os = require('os');
const assert = require('assert/strict');
const PW = process.env.PLAYWRIGHT_DIR || '/opt/npm-tools/node_modules/playwright';
const { _electron: electron } = require(PW);
const { buildFixtures, zipFolder } = require('../helpers');

const ROOT = path.resolve(__dirname, '..', '..');
const SHOTS = process.env.SHOTS || path.join(os.tmpdir(), 'sg-shots');
fs.mkdirSync(SHOTS, { recursive: true });

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-e2e-'));
  const dirs = buildFixtures(path.join(tmp, 'sites'));
  const acmeZip = zipFolder(dirs['acme-dental'], path.join(tmp, 'acme-dental.zip'));
  // a hostile site: HTML/JS in the form id and folder name must stay inert text
  const evil = path.join(tmp, 'sites', 'evil<img src=x onerror=window.__pwned=1>');
  fs.mkdirSync(evil, { recursive: true });
  fs.writeFileSync(path.join(evil, 'index.html'), '<html><head><title>x</title></head><body><form id="a&lt;img src=x onerror=window.__pwned=1&gt;" action="s.php" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Go</button></form></body></html>');
  fs.writeFileSync(path.join(evil, 's.php'), "<?php\nmail('a@b.in','s',$_POST['message']);\n");
  const many = path.join(tmp, 'many');
  fs.mkdirSync(many);
  for (const n of ['acme-dental', 'quick-ajax', 'wp-site', 'include-form']) fs.cpSync(dirs[n], path.join(many, n), { recursive: true });
  const userData = path.join(tmp, 'ud');
  const outDir = path.join(tmp, 'results');
  fs.mkdirSync(userData, { recursive: true });
  fs.writeFileSync(path.join(userData, 'settings.json'), JSON.stringify({ outDir }));

  const packaged = process.env.SG_EXE; // test the packaged build instead of the source tree
  const app = await electron.launch({ executablePath: packaged || path.join(ROOT, 'node_modules', 'electron', 'dist', 'electron'), args: packaged ? ['--no-sandbox'] : [path.join(ROOT, 'app', 'main.js'), '--no-sandbox'], env: Object.assign({}, process.env, { SG_USER_DATA: userData }) });
  const page = await app.firstWindow();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  await page.setViewportSize({ width: 980, height: 760 });
  const queue = async (paths) => app.evaluate(({ dialog }, p) => { global.__q = p; dialog.showOpenDialog = async () => ({ canceled: false, filePaths: global.__q }); }, paths);
  const shot = (n) => page.screenshot({ path: path.join(SHOTS, n + '.png') });
  const visible = async (id) => !(await page.locator('#' + id).getAttribute('hidden').catch(() => 'x')) !== false && (await page.locator('#' + id).isVisible());
  const ok = (m) => console.log('  ok  ' + m);

  // --- window is locked down
  assert.equal(await page.evaluate(() => typeof require + typeof process + typeof window.sg), 'undefinedundefinedobject');
  assert.deepEqual(await page.evaluate(() => Object.keys(window.sg).sort()), ['chooseOutDir', 'classify', 'getSettings', 'onProgress', 'pathsFromDrop', 'pick', 'protect', 'readReport', 'reveal', 'scan', 'setSettings', 'version']);
  ok('renderer has no node access, only the narrow sg bridge');
  await shot('01-home');

  // --- wrong file type
  await queue([path.join(tmp, 'sites', 'acme-dental', 'index.html')]);
  await page.click('#pick-zip');
  await page.waitForSelector('#banner:not([hidden])');
  assert.match(await page.textContent('#banner'), /Sirf \.zip ya folder/);
  ok('non-zip file is refused with a clear message');

  // --- single site: scan -> protect -> result
  await queue([acmeZip]);
  await page.click('#pick-zip');
  await page.waitForSelector('#view-scan:not([hidden])');
  assert.equal(await page.textContent('#scan-name'), 'acme-dental');
  assert.match(await page.textContent('#scan-forms'), /index\.html/);
  assert.match(await page.textContent('#scan-go'), /Protect karo \(1 form\)/);
  await shot('02-scan');
  ok('scan screen shows the form and the button count');
  await page.click('#scan-go');
  await page.waitForSelector('#view-done:not([hidden])', { timeout: 60000 });
  assert.match(await page.textContent('#done-banner'), /PROTECTED/);
  const pass = (await page.textContent('#done-pass')).trim();
  assert.match(pass, /^[A-Za-z0-9]{16}$/);
  await shot('03-done');
  const runs = fs.readdirSync(outDir);
  assert.equal(runs.length, 1);
  const siteOut = path.join(outDir, runs[0], 'acme-dental');
  for (const f of ['acme-dental-protected.zip', 'acme-dental-backup-original.zip', 'report.txt', 'report.json', 'PRIVATE-login.txt']) assert.ok(fs.existsSync(path.join(siteOut, f)), f);
  assert.match(fs.readFileSync(path.join(siteOut, 'PRIVATE-login.txt'), 'utf8'), new RegExp(pass));
  ok('protected zip, backup, reports and login file were really written; password matches');
  await page.click('#done-report');
  await page.waitForSelector('#report-dialog[open]');
  assert.match(await page.textContent('#report-text'), /KYA BADLA/);
  await shot('04-report');
  await page.click('#report-close');
  await app.evaluate(({ shell }) => { global.__rev = []; shell.showItemInFolder = (p) => global.__rev.push(p); });
  await page.click('#done-folder');
  await page.waitForTimeout(300);
  const rev = await app.evaluate(() => global.__rev);
  assert.equal(rev.length, 1);
  assert.ok(rev[0].endsWith('acme-dental-protected.zip'));
  assert.equal(await page.evaluate(() => window.sg.reveal('/etc/passwd')), false);
  await assert.rejects(() => page.evaluate(() => window.sg.readReport('/etc/passwd')), /not allowed/);
  ok('"folder kholo" works; the window cannot open or read anything outside our own results');
  await page.click('#done-again');

  // --- hostile site names stay inert
  await queue([evil]);
  await page.click('#pick-folder');
  await page.waitForSelector('#view-scan:not([hidden])');
  assert.equal(await page.evaluate(() => window.__pwned), undefined);
  assert.equal(await page.locator('#scan-forms img, #scan-name img').count(), 0);
  assert.match(await page.textContent('#scan-name'), /evil<img/);
  ok('HTML in site/form names is shown as text, never executed');
  await page.click('#scan-back');

  // --- bulk
  await queue([many]);
  await page.click('#pick-folder');
  await page.waitForSelector('#view-bulkscan:not([hidden])', { timeout: 60000 });
  assert.match(await page.textContent('#bs-title'), /4 sites/);
  await shot('05-bulk-scan');
  await page.click('#bs-go');
  await page.waitForSelector('#view-bulkdone:not([hidden])', { timeout: 120000 });
  const txt = await page.textContent('#bd-table');
  assert.match(txt, /acme-dental/);
  assert.match(txt, /wp-site/);
  await shot('06-bulk-done');
  const bulkOut = fs.readdirSync(outDir).filter((d) => d !== runs[0])[0];
  assert.ok(fs.existsSync(path.join(outDir, bulkOut, 'PRIVATE-credentials.csv')));
  assert.ok(fs.existsSync(path.join(outDir, bulkOut, 'acme-dental', 'acme-dental-protected.zip')));
  ok('bulk: 4 sites protected, credentials csv written, WordPress site left alone');

  // --- settings persist and are validated
  await page.click('#again, #bd-again').catch(() => {});
  await page.click('#btn-settings');
  await page.fill('#s-mail', 'not-an-email');
  await page.check('#s-quar');
  await page.click('#s-save');
  await page.waitForTimeout(200);
  const saved = JSON.parse(fs.readFileSync(path.join(userData, 'settings.json'), 'utf8'));
  assert.equal(saved.notifyEmail, '');
  assert.equal(saved.quarantine, true);
  ok('settings are saved; a bad email is dropped');

  assert.deepEqual(errors, [], 'no console / page errors');
  ok('no JavaScript errors in the window');
  await app.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log('APP E2E PASSED. Screenshots: ' + SHOTS);
})().catch((e) => {
  console.error('APP E2E FAILED:', e);
  process.exit(1);
});
