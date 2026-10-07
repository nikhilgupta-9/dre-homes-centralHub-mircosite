'use strict';
/** Real browser (Chromium) against the real local server: upload a zip + a folder, scan, protect, see results. */
const path = require('path');
const fs = require('fs');
const os = require('os');
const assert = require('assert/strict');
const http = require('http');
const PW = process.env.PLAYWRIGHT_DIR || '/opt/npm-tools/node_modules/playwright';
const { chromium } = require(PW);
const { buildFixtures, zipFolder } = require('./helpers');
const { createStudio } = require('../src/web/server');

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-web-'));
  const dirs = buildFixtures(path.join(tmp, 'sites'));
  const zip = zipFolder(dirs['acme-dental'], path.join(tmp, 'acme-dental.zip'));
  const outDir = path.join(tmp, 'results');
  const studio = createStudio({ home: path.join(tmp, 'home'), docs: tmp, noOpen: true });
  fs.mkdirSync(path.join(tmp, 'home'));
  fs.writeFileSync(path.join(tmp, 'home', 'settings.json'), JSON.stringify({ outDir }));
  const { url, port } = await studio.listen(0);
  const ok = (m) => console.log('  ok  ' + m);

  // --- security: wrong Host, no token
  const raw = (opts) => new Promise((res) => { const r = http.request(Object.assign({ host: '127.0.0.1', port }, opts), (x) => { let b = ''; x.on('data', (c) => (b += c)); x.on('end', () => res({ code: x.statusCode, b })); }); r.end(opts.body); });
  assert.equal((await raw({ path: '/', headers: { Host: 'evil.com' } })).code, 403);
  assert.equal((await raw({ path: '/api/settings/get', method: 'POST' })).code, 403);
  assert.equal((await raw({ path: '/../package.json' })).code, 404);
  ok('wrong Host / missing token / path tricks are refused');

  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const page = await browser.newPage({ viewport: { width: 980, height: 760 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  await page.goto(url);
  await page.waitForSelector('#drop');
  ok('page loads (CSP ok)');

  // single zip via the "Zip chuno" button (file chooser)
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('#pick-zip')]);
  await fc.setFiles(zip);
  await page.waitForSelector('#view-scan:not([hidden])', { timeout: 30000 });
  ok('zip uploaded + scanned: ' + (await page.locator('#view-scan').innerText()).split('\n').slice(0, 3).join(' | '));
  await page.click('#scan-go');
  await page.waitForSelector('#view-done:not([hidden])', { timeout: 60000 });
  const runs = fs.readdirSync(outDir);
  assert.equal(runs.length, 1);
  const sub = fs.readdirSync(path.join(outDir, runs[0]))[0];
  const files = fs.readdirSync(path.join(outDir, runs[0], sub));
  assert.ok(files.some((f) => f.endsWith('.zip')), 'protected zip written: ' + files);
  assert.ok(files.includes('report.txt'));
  ok('protected zip + report written to ' + runs[0]);
  await page.click('#done-report').catch(() => {});
  await page.screenshot({ path: path.join(os.tmpdir(), 'sg-web-done.png') });

  // folder via "Folder chuno"
  await page.reload();
  await page.waitForSelector('#drop');
  const [fc2] = await Promise.all([page.waitForEvent('filechooser'), page.click('#pick-folder')]);
  await fc2.setFiles(dirs['quick-ajax']);
  await page.waitForSelector('#view-scan:not([hidden])', { timeout: 30000 });
  ok('folder uploaded + scanned');

  // a path outside uploads must be refused by the API
  const tok = await page.evaluate(() => document.querySelector('meta[name=sg-token]').content);
  const bad = await page.evaluate(async (t) => (await (await fetch('/api/scan', { method: 'POST', headers: { 'X-SG-Token': t }, body: JSON.stringify({ kind: 'site', input: '/etc', name: 'x' }) })).json()), tok);
  assert.equal(bad.ok, false);
  ok('arbitrary paths (/etc) refused');

  assert.deepEqual(errors, []);
  await browser.close();
  studio.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log('WEB E2E PASSED');
})().catch((e) => { console.error(e); process.exit(1); });
