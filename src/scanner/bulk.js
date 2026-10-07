'use strict';
const fs = require('fs');
const path = require('path');
const { scanSite } = require('./index');
const { renderText, renderBulkText } = require('./report');
const { SKIP_DIRS } = require('./util');

function rowOf(name, status, report, error) {
  if (status === 'failed') return { name, status, error };
  const s = report.summary;
  return {
    name,
    status,
    source: report.site.source,
    platform: report.site.platform,
    db: report.database.used ? 'yes' : 'no',
    pages: s.pages,
    forms: s.forms,
    enquiryForms: s.enquiryForms,
    auto: s.auto,
    review: s.review,
    manual: s.manual,
    skip: s.skip,
    done: s.done,
    exposedFiles: s.exposedFiles,
    phones: report.contacts.phones.length,
    emails: report.contacts.emails.length,
    warnings: report.warnings.length,
  };
}

/**
 * Scan many sites in one go: every sub-folder and every .zip inside `parent` is one site.
 * A broken site never stops the batch, it is reported as "failed".
 * @param opts.onProgress ({done,total,name,status}) => void
 */
async function scanMany(parent, opts = {}) {
  const abs = path.resolve(parent);
  let ents;
  try {
    ents = fs.readdirSync(abs, { withFileTypes: true });
  } catch (e) {
    throw new Error('Folder nahi khula: ' + parent);
  }
  const items = [];
  for (const e of ents) {
    if (e.name.startsWith('.') || SKIP_DIRS.has(e.name)) continue;
    if (e.isDirectory()) items.push({ name: e.name, input: path.join(abs, e.name) });
    else if (e.isFile() && /\.zip$/i.test(e.name)) items.push({ name: e.name.replace(/\.zip$/i, ''), input: path.join(abs, e.name) });
  }
  items.sort((a, b) => a.name.localeCompare(b.name));
  if (!items.length) throw new Error('Is folder mein koi site folder ya .zip nahi mila: ' + parent);
  const looksLikeSingleSite = ents.some((e) => e.isFile() && /^index\.(html?|php)$/i.test(e.name));

  const results = [];
  const rows = [];
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    let status = 'ok';
    let report = null;
    let error = null;
    try {
      report = await scanSite(it.input, opts);
      report.site.name = it.name;
    } catch (e) {
      status = 'failed';
      error = e.message;
    }
    results.push({ name: it.name, input: it.input, status, report, error });
    rows.push(rowOf(it.name, status, report, error));
    if (opts.onProgress) opts.onProgress({ done: i + 1, total: items.length, name: it.name, status });
    await new Promise((r) => setImmediate(r)); // keep the app responsive
  }
  const ok = rows.filter((r) => r.status === 'ok');
  const sum = (k) => ok.reduce((a, r) => a + (r[k] || 0), 0);
  return {
    parent: abs,
    warnings: looksLikeSingleSite ? [{ code: 'parent-looks-like-site', level: 'warn' }] : [],
    totals: {
      sites: rows.length,
      ok: ok.length,
      failed: rows.length - ok.length,
      forms: sum('enquiryForms'),
      auto: sum('auto'),
      review: sum('review'),
      manual: sum('manual'),
      done: sum('done'),
      withDb: ok.filter((r) => r.db === 'yes').length,
      withExposed: ok.filter((r) => r.exposedFiles > 0).length,
    },
    rows,
    results,
  };
}

const csvCell = (v) => {
  const s = v === undefined || v === null ? '' : String(v);
  // spreadsheet formula injection guard + quoting
  const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  return /[",\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
};

/** Write summary.csv, summary.json, report.txt, plus one json + txt report per site. */
function writeBulkOutputs(bulk, outDir) {
  fs.mkdirSync(path.join(outDir, 'reports'), { recursive: true });
  const used = new Set();
  const fileFor = (name) => {
    let base = name.replace(/[^\w.\-]+/g, '_').slice(0, 80) || 'site';
    let n = base;
    for (let i = 2; used.has(n.toLowerCase()); i++) n = base + '_' + i;
    used.add(n.toLowerCase());
    return n;
  };
  for (const r of bulk.results) {
    const f = fileFor(r.name);
    if (r.report) {
      fs.writeFileSync(path.join(outDir, 'reports', f + '.json'), JSON.stringify(r.report, null, 2));
      fs.writeFileSync(path.join(outDir, 'reports', f + '.txt'), renderText(r.report));
    } else {
      fs.writeFileSync(path.join(outDir, 'reports', f + '.txt'), `SITE: ${r.name}\nSCAN FAIL HUA: ${r.error}\n`);
    }
  }
  const cols = ['name', 'status', 'source', 'platform', 'db', 'pages', 'forms', 'enquiryForms', 'auto', 'review', 'manual', 'skip', 'done', 'exposedFiles', 'phones', 'emails', 'warnings', 'error'];
  fs.writeFileSync(path.join(outDir, 'summary.csv'), '﻿' + [cols.join(',')].concat(bulk.rows.map((r) => cols.map((c) => csvCell(r[c])).join(','))).join('\n') + '\n');
  fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify({ totals: bulk.totals, rows: bulk.rows, warnings: bulk.warnings }, null, 2));
  fs.writeFileSync(path.join(outDir, 'report.txt'), renderBulkText(bulk));
  return outDir;
}

module.exports = { scanMany, writeBulkOutputs };
