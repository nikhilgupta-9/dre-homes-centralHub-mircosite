'use strict';
/**
 * Everything the desktop app (and any future UI) needs, in one place, with plain-data in and out.
 * No Electron in here, so it is fully testable with node.
 */
const fs = require('fs');
const path = require('path');
const { scanSite } = require('../scanner');
const { scanMany, writeBulkOutputs } = require('../scanner/bulk');
const { renderText, REASON } = require('../scanner/report');
const { protectSite } = require('../injector');
const { protectMany, writeSiteReports } = require('../injector/bulk');
const { renderProtectText, STATUS_LINE, OUTCOME, ERR, WAHAN } = require('../injector/report');
const { SKIP_DIRS } = require('../scanner/util');

const isSiteDir = (d) => {
  try {
    return fs.readdirSync(d).some((n) => /^index\.(html?|php)$/i.test(n));
  } catch (e) {
    return false;
  }
};

/**
 * What did the user drop?
 *   one .zip                      -> one site
 *   a folder with index.* inside  -> one site
 *   a folder of sites / many zips -> bulk
 *   several dropped items         -> bulk (each item is a site)
 */
function classifyDrop(paths) {
  const all = (paths || []).filter((p) => typeof p === 'string' && p && !path.basename(p).startsWith('.'));
  const sqlFiles = all.filter((p) => /\.sql$/i.test(p));
  const list = all.filter((p) => !/\.sql$/i.test(p));
  if (sqlFiles.length && !list.length) return { kind: 'invalid', reason: 'Ye database (.sql) file hai. Isse site ke zip/folder ke saath hi dalo.' };
  const withSql = (r) => (sqlFiles.length && r.kind === 'site' ? Object.assign(r, { sqlFiles }) : r);
  return withSql(classifyDrop1(list, sqlFiles));
}

function classifyDrop1(list, sqlFiles) {
  if (!list.length) return { kind: 'invalid', reason: 'Kuch nahi mila. Zip ya folder dalo.' };
  const items = [];
  for (const p of list) {
    let st;
    try {
      st = fs.statSync(p);
    } catch (e) {
      return { kind: 'invalid', reason: 'Ye file/folder nahi khul raha: ' + path.basename(p) };
    }
    if (st.isFile()) {
      if (!/\.zip$/i.test(p)) {
        if (/\.sql$/i.test(p)) return { kind: 'invalid', reason: 'Ye database (.sql) file hai. Pehle site ka zip ya folder dalo, database baad mein.' };
        return { kind: 'invalid', reason: 'Sirf .zip ya folder chalega: ' + path.basename(p) };
      }
      items.push({ name: path.basename(p).replace(/\.zip$/i, ''), input: p, type: 'zip' });
    } else if (st.isDirectory()) {
      items.push({ name: path.basename(p), input: p, type: 'folder' });
    }
  }
  if (items.length === 1) {
    const it = items[0];
    if (it.type === 'folder' && !isSiteDir(it.input)) {
      // a folder of sites? (>= 2 children that are zips or site folders)
      const kids = [];
      try {
        for (const e of fs.readdirSync(it.input, { withFileTypes: true })) {
          if (e.name.startsWith('.') || SKIP_DIRS.has(e.name)) continue;
          const full = path.join(it.input, e.name);
          if (e.isFile() && /\.zip$/i.test(e.name)) kids.push(full);
          else if (e.isDirectory() && (isSiteDir(full) || fs.readdirSync(full, { withFileTypes: true }).some((x) => x.isDirectory() && isSiteDir(path.join(full, x.name))))) kids.push(full);
        }
      } catch (e) {
        /* fall through: treat as a single site */
      }
      if (kids.length >= 2) {
        // the batch processes EVERY sub-folder and zip, so that is the number to show
        const all = fs.readdirSync(it.input, { withFileTypes: true }).filter((e) => !e.name.startsWith('.') && !SKIP_DIRS.has(e.name) && (e.isDirectory() || (e.isFile() && /\.zip$/i.test(e.name))));
        return { kind: 'bulk', parent: it.input, name: it.name, count: all.length };
      }
    }
    return { kind: 'site', input: it.input, name: it.name, type: it.type };
  }
  // several things dropped together: bulk over exactly those items
  return { kind: 'bulk', items, count: items.length, name: items.length + ' sites' };
}

const notesOf = (reasons) =>
  (reasons || [])
    .filter((r) => r.level === 'warn' && REASON[r.code])
    .map((r) => REASON[r.code](r));

/** Compact view of a scan for the screen (the full report stays available for "report dekho"). */
function uiScan(report) {
  return {
    name: report.site.name,
    platform: report.site.platform,
    summary: report.summary,
    database: { used: report.database.used, engines: report.database.engines || [] },
    forms: report.forms.map((f) => ({
      file: f.file,
      line: f.line,
      kind: f.kind,
      label: f.label,
      status: f.plan.status,
      handler: f.handler && f.handler.exists ? f.handler.file : null,
      submitMode: f.submitMode,
      notes: notesOf(f.plan.reasons),
    })),
    exposed: report.security.exposedFiles.length,
    contacts: { phones: report.contacts.phones.length, emails: report.contacts.emails.length },
  };
}

/** Compact view of a protect result for the screen. The password is included on purpose (it is shown once to the user). */
function uiProtect(r) {
  return {
    name: r.site.name,
    status: r.status,
    statusText: STATUS_LINE[r.status] || r.status,
    summary: r.summary,
    kit: r.kit,
    hub: r.hub,
    outputs: r.outputs,
    login: r.login ? { password: r.login.password, adminPath: r.login.adminPath, selftestPath: r.login.selftestPath } : null,
    changed: r.changes.length > 0,
    forms: r.forms
      .filter((f) => f.outcome !== 'skipped')
      .map((f) => ({
        file: f.file,
        line: f.line,
        label: f.label,
        outcome: f.outcome,
        outcomeText: OUTCOME[f.outcome],
        handler: f.handler,
        notes: f.errors.map((e) => ERR[e.code] || e.code).concat(f.outcome === 'manual' || f.outcome === 'needs-review' ? notesOf(f.reasons) : []),
      })),
    steps: r.changes.length ? WAHAN : [],
    rolledBack: r.verification.rolledBack,
  };
}

async function scan(input, opts = {}) {
  const report = await scanSite(input, { sqlFiles: opts.sqlFiles || [] });
  return { ui: uiScan(report), text: renderText(report), report };
}

const protectOpts = (o) => ({
  outDir: o.outDir,
  sqlFiles: o.sqlFiles || [],
  includeReview: !!o.includeReview,
  quarantine: !!o.quarantine,
  notifyEmail: o.notifyEmail || undefined,
  timezone: o.timezone || undefined,
  password: o.password || undefined,
  dryRun: !!o.dryRun,
  hub: o.hub && o.hub.url && o.hub.token ? { url: o.hub.url, token: o.hub.token } : undefined,
});

async function protect(input, opts = {}) {
  if (!opts.outDir && !opts.dryRun) throw new Error('Result kahan save karna hai? Folder chuno.');
  const r = await protectSite(input, protectOpts(opts));
  if (!opts.dryRun) writeSiteReports(r, path.resolve(opts.outDir));
  return { ui: uiProtect(r), text: renderProtectText(r) };
}

/** items: [{name,input}] or a parent folder. Each site is isolated; one failure never stops the rest. */
async function protectBulk(drop, opts = {}, onProgress) {
  if (!opts.outDir && !opts.dryRun) throw new Error('Result kahan save karna hai? Folder chuno.');
  let parent = drop.parent;
  let staging = null;
  if (!parent) {
    // several loose items: link them into a temp parent folder (symlinks are not followed by the tools, so copy zips / reference folders by copy)
    const os = require('os');
    staging = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-drop-'));
    const used = new Set();
    for (const it of drop.items) {
      let n = it.name;
      for (let k = 2; used.has(n.toLowerCase()); k++) n = it.name + '_' + k;
      used.add(n.toLowerCase());
      if (it.type === 'zip') fs.copyFileSync(it.input, path.join(staging, n + '.zip'));
      else fs.cpSync(it.input, path.join(staging, n), { recursive: true, dereference: false });
    }
    parent = staging;
  }
  try {
    const bulk = await protectMany(parent, Object.assign(protectOpts(opts), { onProgress }));
    return bulk;
  } finally {
    if (staging) fs.rmSync(staging, { recursive: true, force: true });
  }
}

async function scanBulk(drop, onProgress) {
  let parent = drop.parent;
  let staging = null;
  if (!parent) {
    const os = require('os');
    staging = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-drop-'));
    for (const it of drop.items) {
      if (it.type === 'zip') fs.copyFileSync(it.input, path.join(staging, it.name + '.zip'));
      else fs.cpSync(it.input, path.join(staging, it.name), { recursive: true });
    }
    parent = staging;
  }
  try {
    const bulk = await scanMany(parent, { onProgress });
    return { totals: bulk.totals, rows: bulk.rows };
  } finally {
    if (staging) fs.rmSync(staging, { recursive: true, force: true });
  }
}

module.exports = { classifyDrop, scan, protect, protectBulk, scanBulk, uiScan, uiProtect };
