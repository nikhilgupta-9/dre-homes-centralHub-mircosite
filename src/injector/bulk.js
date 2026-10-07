'use strict';
const fs = require('fs');
const path = require('path');
const { protectSite, safeName } = require('./index');
const { renderProtectText, renderLoginText, renderProtectBulk } = require('./report');
const { SKIP_DIRS } = require('../scanner/util');

const csvCell = (v) => {
  const s = v === undefined || v === null ? '' : String(v);
  const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  return /[",\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
};

// passwords are written verbatim (an apostrophe prefix would corrupt them); generated ones never start with a symbol
const rawCell = (v) => (/[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v));

/** Write report.txt / report.json (+ PRIVATE-login.txt) for one site next to its zips. */
function writeSiteReports(r, outDir) {
  const dir = r.outputs && r.outputs.dir ? r.outputs.dir : path.join(outDir, safeName(r.site.name));
  fs.mkdirSync(dir, { recursive: true });
  const pub = JSON.parse(JSON.stringify(r));
  if (pub.login) delete pub.login.password; // the password lives only in PRIVATE-login.txt
  fs.writeFileSync(path.join(dir, 'report.txt'), renderProtectText(r));
  fs.writeFileSync(path.join(dir, 'report.json'), JSON.stringify(pub, null, 2));
  const login = renderLoginText(r);
  if (login) fs.writeFileSync(path.join(dir, 'PRIVATE-login.txt'), login, { mode: 0o600 });
  return dir;
}

/** Protect many sites: every sub-folder / .zip in `parent` is one site. One failure never stops the rest. */
async function protectMany(parent, opts = {}) {
  const abs = path.resolve(parent);
  const ents = fs.readdirSync(abs, { withFileTypes: true });
  const items = [];
  for (const e of ents) {
    if (e.name.startsWith('.') || SKIP_DIRS.has(e.name)) continue;
    if (e.isDirectory()) items.push({ name: e.name, input: path.join(abs, e.name) });
    else if (e.isFile() && /\.zip$/i.test(e.name)) items.push({ name: e.name.replace(/\.zip$/i, ''), input: path.join(abs, e.name) });
  }
  items.sort((a, b) => a.name.localeCompare(b.name));
  if (!items.length) throw new Error('Is folder mein koi site folder ya .zip nahi mila: ' + parent);
  const outAbs = path.resolve(opts.outDir);
  if (outAbs === abs || outAbs.startsWith(abs + path.sep)) throw new Error('Output folder sites wale folder ke andar nahi ho sakta.');
  const rows = [];
  const creds = [];
  const used = new Set();
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    let n = safeName(it.name);
    for (let k = 2; used.has(n.toLowerCase()); k++) n = safeName(it.name) + '_' + k;
    used.add(n.toLowerCase());
    let row;
    try {
      const r = await protectSite(it.input, Object.assign({}, opts, { name: n, siteId: n, sqlFiles: undefined }));
      if (!opts.dryRun) writeSiteReports(r, outAbs);
      const s = r.summary;
      row = { name: n, status: r.status, protectedForms: s.protected, openForms: s.needsReview + s.manual + s.failed, filesChanged: s.filesChanged, hub: r.hub ? r.hub.status : '', error: r.hub && r.hub.status === 'failed' ? 'Hub: ' + r.hub.error : '' };
      if (r.login) creds.push({ site: n, adminPath: r.login.adminPath, password: r.login.password, selftestPath: r.login.selftestPath });
    } catch (e) {
      row = { name: n, status: 'failed', protectedForms: 0, openForms: 0, filesChanged: 0, error: e.message };
    }
    rows.push(row);
    if (opts.onProgress) opts.onProgress({ done: i + 1, total: items.length, name: n, status: row.status });
    await new Promise((r) => setImmediate(r));
  }
  const cnt = (st) => rows.filter((r) => r.status === st).length;
  const bulk = {
    totals: {
      sites: rows.length,
      protected: cnt('protected'),
      partial: cnt('partial'),
      already: cnt('already-protected'),
      failed: cnt('failed'),
      untouched: rows.filter((r) => ['manual-only', 'nothing-to-do', 'no-forms'].includes(r.status)).length,
      formsProtected: rows.reduce((a, r) => a + r.protectedForms, 0),
      formsOpen: rows.reduce((a, r) => a + r.openForms, 0),
    },
    rows,
  };
  if (!opts.dryRun) {
    fs.mkdirSync(outAbs, { recursive: true });
    const cols = ['name', 'status', 'protectedForms', 'openForms', 'filesChanged', 'hub', 'error'];
    fs.writeFileSync(path.join(outAbs, 'summary.csv'), '﻿' + [cols.join(',')].concat(rows.map((r) => cols.map((c) => csvCell(r[c])).join(','))).join('\n') + '\n');
    fs.writeFileSync(path.join(outAbs, 'summary.json'), JSON.stringify(bulk, null, 2));
    fs.writeFileSync(path.join(outAbs, 'report.txt'), renderProtectBulk(bulk));
    if (creds.length) {
      const c = ['site', 'adminPath', 'password', 'selftestPath'];
      fs.writeFileSync(path.join(outAbs, 'PRIVATE-credentials.csv'), '﻿' + [c.join(',')].concat(creds.map((r) => c.map((k) => (k === 'password' ? rawCell(r[k]) : csvCell(r[k]))).join(','))).join('\n') + '\n', { mode: 0o600 });
    }
  }
  return bulk;
}

module.exports = { protectMany, writeSiteReports };
