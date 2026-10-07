'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { buildFixtures, zipFolder } = require('./helpers');
const svc = require('../src/app/service');

let tmp, dirs;
before(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-svc-')); dirs = buildFixtures(path.join(tmp, 'sites')); });
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

test('drop: one zip / one site folder = one site; a folder of sites or several items = bulk', () => {
  const z = zipFolder(dirs['acme-dental'], path.join(tmp, 'a.zip'));
  assert.equal(svc.classifyDrop([z]).kind, 'site');
  assert.equal(svc.classifyDrop([dirs['acme-dental']]).kind, 'site');
  assert.equal(svc.classifyDrop([path.join(tmp, 'sites')]).kind, 'bulk');
  assert.equal(svc.classifyDrop([dirs['acme-dental'], z]).kind, 'bulk');
  assert.equal(svc.classifyDrop([path.join(tmp, 'sites')]).count >= 10, true);
});

test('drop: a Mac wrapper folder (site one level down) is still ONE site', () => {
  const w = path.join(tmp, 'wrapper');
  fs.mkdirSync(w);
  fs.cpSync(dirs['acme-dental'], path.join(w, 'public_html'), { recursive: true });
  assert.equal(svc.classifyDrop([w]).kind, 'site');
});

test('drop: bad input gives friendly messages; .sql travels with its site', () => {
  assert.match(svc.classifyDrop([]).reason, /Kuch nahi/);
  assert.match(svc.classifyDrop([path.join(tmp, 'nope.zip')]).reason, /nahi khul/);
  const txt = path.join(tmp, 'x.txt'); fs.writeFileSync(txt, 'x');
  assert.match(svc.classifyDrop([txt]).reason, /Sirf \.zip/);
  const sql = path.join(tmp, 'd.sql'); fs.writeFileSync(sql, '--');
  assert.match(svc.classifyDrop([sql]).reason, /saath hi dalo/);
  const c = svc.classifyDrop([dirs['acme-dental'], sql]);
  assert.equal(c.kind, 'site');
  assert.deepEqual(c.sqlFiles, [sql]);
});

test('ui views are plain data and carry the reasons as readable text', async () => {
  const s = await svc.scan(dirs['external-forms']);
  assert.ok(s.ui.forms.every((f) => Array.isArray(f.notes)));
  assert.ok(s.ui.forms.some((f) => f.notes.some((n) => /server par aata hi nahi|mailto/.test(n))));
  JSON.stringify(s.ui); // must be structured-clone / JSON safe for the window
  const p = await svc.protect(dirs['quick-ajax'], { outDir: path.join(tmp, 'o') });
  assert.equal(p.ui.status, 'protected');
  assert.equal(p.ui.steps.length, 4);
  assert.match(p.ui.login.password, /^[A-Za-z0-9]{16}$/);
});

test('bulk of loose dropped items works and leaves no temp folder behind', async () => {
  const before = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('sg-drop-')).length;
  const z = zipFolder(dirs['quick-ajax'], path.join(tmp, 'q.zip'));
  const drop = svc.classifyDrop([dirs['acme-dental'], z]);
  const r = await svc.protectBulk(drop, { outDir: path.join(tmp, 'o2') });
  assert.equal(r.totals.protected, 2);
  assert.equal(fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('sg-drop-')).length, before);
});
