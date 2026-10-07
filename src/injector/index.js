'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const AdmZip = require('adm-zip');
const { spawnSync } = require('child_process');
const { scanSite } = require('../scanner');
const { prepareInput } = require('../scanner/loader');
const { SKIP_FILE } = require('../scanner/util');
const { generateConfig } = require('../config');
const { provisionSite } = require('../hub');
const E = require('./edits');

const KIT_DIR = path.resolve(__dirname, '..', '..', 'kit', 'spamguard');
const MAX_SITE_BYTES = 1.5 * 1024 * 1024 * 1024;
const safeName = (n) => String(n).replace(/[^\w.\-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 80) || 'site';
const posix = (p) => p.split(path.sep).join('/');

let phpAvail;
function hasPhp() {
  if (phpAvail === undefined) phpAvail = spawnSync('php', ['-v'], { timeout: 10000 }).status === 0;
  return phpAvail;
}

/** Every regular file + directory under root (symlinks and Mac junk are never followed or copied). */
function listTree(root) {
  const files = [];
  const dirs = [];
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    let ents;
    try {
      ents = fs.readdirSync(path.join(root, rel), { withFileTypes: true });
    } catch (e) {
      continue;
    }
    for (const e of ents) {
      if (e.isSymbolicLink()) continue;
      const r = rel ? rel + '/' + e.name : e.name;
      if (e.isDirectory()) {
        if (e.name === '__MACOSX') continue;
        dirs.push(r);
        stack.push(r);
      } else if (e.isFile() && !SKIP_FILE.test(e.name)) {
        files.push({ rel: r, size: fs.statSync(path.join(root, r)).size });
      }
    }
  }
  files.sort((a, b) => a.rel.localeCompare(b.rel));
  dirs.sort();
  return { files, dirs };
}

function copyTree(src, dest, tree) {
  fs.mkdirSync(dest, { recursive: true });
  for (const d of tree.dirs) fs.mkdirSync(path.join(dest, d), { recursive: true });
  for (const f of tree.files) fs.copyFileSync(path.join(src, f.rel), path.join(dest, f.rel));
}

/** Zip a folder; empty folders (like uploads/) are kept. */
function zipFolder(dir, outZip) {
  const zip = new AdmZip();
  const tree = listTree(dir);
  for (const d of tree.dirs) zip.addFile(d + '/', Buffer.alloc(0));
  for (const f of tree.files) zip.addLocalFile(path.join(dir, f.rel), path.dirname(f.rel) === '.' ? '' : path.dirname(f.rel));
  fs.mkdirSync(path.dirname(outZip), { recursive: true });
  zip.writeZip(outZip);
  return tree.files.length;
}

const readLatin = (p) => fs.readFileSync(p).toString('latin1');
const writeLatin = (p, t) => fs.writeFileSync(p, Buffer.from(t, 'latin1'));

function relToRoot(file) {
  const depth = file.split('/').length - 1;
  return depth === 0 ? '' : Array(depth).fill('..').join('/');
}

/**
 * Protect one site.
 * @param input   .zip or folder
 * @param opts.outDir        where backup / protected zip / reports go
 * @param opts.includeReview also patch forms marked "review" (default: only "auto")
 * @param opts.dryRun        do everything in a temp folder, write nothing to outDir
 * @param opts.password, notifyEmail, quarantine, timezone, turnstile  -> spamguard/config.php
 * @param opts.basePath      URL folder the site lives in ('/' for a domain of its own)
 */
async function protectSite(input, opts = {}) {
  const outDirAbs = opts.outDir ? path.resolve(opts.outDir) : null;
  if (!outDirAbs && !opts.dryRun) throw new Error('outDir chahiye (ya dryRun)');
  const loaded = prepareInput(input);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-protect-'));
  try {
    if (outDirAbs && loaded.source === 'folder') {
      const inAbs = fs.realpathSync(path.resolve(input));
      if (outDirAbs === inAbs || outDirAbs.startsWith(inAbs + path.sep)) throw new Error('Output folder site ke folder ke andar nahi ho sakta. Koi aur folder chuno.');
    }
    const tree = listTree(loaded.root);
    const total = tree.files.reduce((a, f) => a + f.size, 0);
    if (total > MAX_SITE_BYTES) throw new Error('Site bahut badi hai (' + Math.round(total / 1048576) + ' MB). Pehle badi videos/backups hata do.');

    const siteDir = path.join(work, 'site');
    copyTree(loaded.root, siteDir, tree);
    const scan = await scanSite(siteDir, { sqlFiles: opts.sqlFiles || [] });
    const name = opts.name || loaded.name;
    const result = {
      tool: 'spamguard-studio/injector',
      site: { name, source: loaded.source, platform: scan.site.platform, rootInsideInput: loaded.rootRel || '' },
      status: 'nothing-to-do',
      options: { includeReview: !!opts.includeReview, dryRun: !!opts.dryRun, quarantine: !!opts.quarantine },
      forms: [],
      changes: [],
      kit: { installed: false, alreadyPresent: false },
      verification: { rescan: null, phpLint: hasPhp() ? 'ran' : 'skipped (PHP is computer par nahi hai)', rolledBack: [] },
      outputs: {},
      login: null,
      warnings: scan.warnings.map((w) => w.code || String(w)),
    };

    const applicable = (f) => f.plan.status === 'auto' || (opts.includeReview && f.plan.status === 'review');
    const targets = scan.forms.filter(applicable);
    const alreadyDone = scan.forms.filter((f) => f.plan.status === 'done');

    // ---- decide every edit (per file), nothing is written yet
    const fileEdits = new Map(); // rel -> [{offset, insert, kind, formKeys}]
    const original = new Map();
    const formState = new Map(); // form -> {ok:boolean, errors:[], files:Set}
    const text = (rel) => {
      if (!original.has(rel)) original.set(rel, readLatin(path.join(siteDir, rel)));
      return original.get(rel);
    };
    const addEdit = (rel, edit) => {
      if (!fileEdits.has(rel)) fileEdits.set(rel, []);
      fileEdits.get(rel).push(edit);
    };
    const scriptSrc = (opts.basePath ? opts.basePath.replace(/\/*$/, '/') : '/') + 'spamguard/spamguard.js';
    const guardPlanned = new Map(); // handler file -> edit (shared by forms)
    const scriptPlanned = new Set();

    for (const f of targets) {
      const st = { errors: [], files: new Set(), actions: [] };
      formState.set(f, st);
      for (const a of f.plan.actions) {
        if (a.type === 'add-script-tag') {
          st.files.add(a.file);
          if (scriptPlanned.has(a.file)) continue;
          const p = E.planScriptEdit(text(a.file), a.afterLine, scriptSrc);
          if (p.error === 'already') continue;
          if (p.error) {
            st.errors.push({ code: p.error, file: a.file, action: a.type });
            continue;
          }
          scriptPlanned.add(a.file);
          addEdit(a.file, Object.assign({ kind: 'script-tag', file: a.file }, p));
        } else if (a.type === 'add-guard-call') {
          st.files.add(a.file);
          if (guardPlanned.has(a.file)) continue;
          const resp = f.plan.actions.find((x) => x.type === 'set-success-response');
          const override = {};
          if (resp) {
            const succ = {};
            if (resp.json) succ.json = resp.json;
            else if (resp.text) succ.text = resp.text;
            if (resp.redirect) succ.redirect = resp.redirect;
            if (Object.keys(succ).length) override.success = succ;
          }
          const p = E.planGuardEdit(text(a.file), relToRoot(a.file), override);
          if (p.error === 'already') continue;
          if (p.error) {
            st.errors.push({ code: p.error, file: a.file, action: a.type });
            continue;
          }
          guardPlanned.set(a.file, true);
          addEdit(a.file, Object.assign({ kind: 'guard-call', file: a.file }, p));
        }
      }
    }

    // ---- write the edited files into the working copy
    const touched = new Set();
    for (const [rel, edits] of fileEdits) {
      const out = E.applyInsertions(text(rel), edits);
      writeLatin(path.join(siteDir, rel), out);
      touched.add(rel);
      for (const e of edits) {
        const lead = e.insert.startsWith('\r\n') ? 2 : e.insert.startsWith('\n') ? 1 : 0;
        result.changes.push({ file: rel, kind: e.kind, line: E.lineOfOffset(original.get(rel), e.offset) + (lead ? 1 : 0), text: e.insert.trim() });
      }
    }

    // ---- PHP syntax check (when PHP exists); a file that fails is restored to the original
    const lintFailed = new Set();
    if (hasPhp()) {
      for (const rel of touched) {
        if (!/\.(php|phtml|inc)$/i.test(rel)) continue;
        const r = spawnSync('php', ['-l', path.join(siteDir, rel)], { timeout: 20000, encoding: 'utf8' });
        if (r.status !== 0) {
          writeLatin(path.join(siteDir, rel), original.get(rel));
          lintFailed.add(rel);
          result.verification.rolledBack.push({ file: rel, why: ((r.stdout || '') + (r.stderr || '')).trim().split('\n')[0] });
        }
      }
      result.changes = result.changes.filter((c) => !lintFailed.has(c.file));
    }

    // ---- install the kit (only if at least one form got protected)
    const anyApplied = result.changes.length > 0 || alreadyDone.length > 0;
    const kitTarget = path.join(siteDir, 'spamguard');
    const hubWanted = !!(opts.hub && opts.hub.url && opts.hub.token) && opts.siteWide !== false && scan.site.platform !== 'wordpress';
    if (result.changes.length > 0 || hubWanted) {
      if (fs.existsSync(kitTarget)) {
        result.kit.alreadyPresent = true;
      } else {
        copyTree(KIT_DIR, kitTarget, listTree(KIT_DIR));
        result.kit.installed = true;
      }
      if (!fs.existsSync(path.join(kitTarget, 'config.php'))) {
        let extra;
        if (opts.hub && opts.hub.url && opts.hub.token) {
          if (opts.dryRun) {
            result.hub = { status: 'dry-run' };
          } else {
            try {
              const p = await provisionSite(opts.hub, name);
              extra = { hub: { url: p.hub_url, site_key: p.site_key, secret: p.secret } };
              result.hub = { status: 'connected', siteId: p.site_id };
            } catch (e) {
              result.hub = { status: 'failed', error: e.message };
            }
          }
        }
        const gen = generateConfig({
          extra,
          siteId: opts.siteId || safeName(name),
          password: opts.password,
          notifyEmail: opts.notifyEmail,
          timezone: opts.timezone,
          quarantine: opts.quarantine,
          turnstile: opts.turnstile,
        });
        fs.writeFileSync(path.join(kitTarget, 'config.php'), gen.php);
        result.login = { adminPath: '/spamguard/spam-admin.php', selftestPath: `/spamguard/selftest.php?key=${gen.selftestKey}`, password: gen.password, passwordWasGenerated: gen.generatedPassword };
      }
    }

    // ---- site-wide hooks (only for sites that are connected to the hub): central SEO + contact details
    result.siteWide = { enabled: false, phpPages: 0, jsPages: 0, skipped: [] };
    const hubOk = result.hub && (result.hub.status === 'connected' || result.hub.status === 'dry-run');
    const cfgFile = path.join(kitTarget, 'config.php');
    const existingHub = !result.hub && fs.existsSync(cfgFile) && /'hub'\s*=>/.test(fs.readFileSync(cfgFile, 'latin1'));
    if ((hubOk || existingHub) && opts.siteWide !== false && scan.site.platform !== 'wordpress' && fs.existsSync(kitTarget)) {
      result.siteWide.enabled = true;
      const SKIP_DIR = /(^|\/)(spamguard|vendor|node_modules|\.git|admin|administrator|wp-admin|wp-includes|phpmyadmin)\//i;
      const jsSrc = (opts.basePath ? opts.basePath.replace(/\/*$/, '/') : '/') + 'spamguard/contact.js';
      const swTree = listTree(siteDir);
      const snapshot = new Map();
      const swEdits = new Map();
      for (const f of swTree.files) {
        if (SKIP_DIR.test(f.rel + '') || !/\.(php|phtml|html?)$/i.test(f.rel) || f.size > 1500000) continue;
        const isPhp = /\.(php|phtml)$/i.test(f.rel);
        const cur = readLatin(path.join(siteDir, f.rel));
        const edits = [];
        const hasPage = /<html[\s>]|<head[\s>]|<\/body>/i.test(cur);
        if (!hasPage) continue;
        if (isPhp && /<html[\s>]|<head[\s>]/i.test(cur)) {
          const a = E.planApplyEdit(cur, relToRoot(f.rel));
          if (a.error && a.error !== 'already') result.siteWide.skipped.push({ file: f.rel, why: a.error });
          else if (!a.error) edits.push(Object.assign({ kind: 'sg-apply', file: f.rel }, a));
        }
        const j = E.planContactScriptEdit(cur, jsSrc);
        if (j.error && !['already', 'no-body'].includes(j.error)) result.siteWide.skipped.push({ file: f.rel, why: j.error });
        else if (!j.error) edits.push(Object.assign({ kind: 'contact-js', file: f.rel }, j));
        if (edits.length) { snapshot.set(f.rel, cur); swEdits.set(f.rel, edits); }
      }
      const swFailed = new Set();
      for (const [rel, edits] of swEdits) {
        writeLatin(path.join(siteDir, rel), E.applyInsertions(snapshot.get(rel), edits));
        if (hasPhp() && /\.(php|phtml)$/i.test(rel)) {
          const r = spawnSync('php', ['-l', path.join(siteDir, rel)], { timeout: 20000, encoding: 'utf8' });
          if (r.status !== 0) {
            writeLatin(path.join(siteDir, rel), snapshot.get(rel)); // back to how it was before this step
            swFailed.add(rel);
            result.siteWide.skipped.push({ file: rel, why: 'php-syntax-check-failed' });
            continue;
          }
        }
        for (const e of edits) {
          const lead = e.insert.startsWith('\r\n') ? 2 : e.insert.startsWith('\n') ? 1 : 0;
          result.changes.push({ file: rel, kind: e.kind, line: E.lineOfOffset(snapshot.get(rel), e.offset) + (lead ? 1 : 0), text: e.insert.trim() });
          if (e.kind === 'sg-apply') result.siteWide.phpPages++; else result.siteWide.jsPages++;
        }
      }
    }

    // ---- verify by scanning the protected copy again
    const after = await scanSite(siteDir, { sqlFiles: opts.sqlFiles || [] });
    const keyOf = (f, i, list) => f.file + '#' + list.filter((x, j) => x.file === f.file && j < i).length;
    const afterMap = new Map(after.forms.map((f, i) => [keyOf(f, i, after.forms), f]));
    scan.forms.forEach((f, i) => {
      const key = keyOf(f, i, scan.forms);
      const st = formState.get(f);
      const aft = afterMap.get(key);
      const rec = {
        file: f.file,
        line: f.line,
        label: f.label,
        kind: f.kind,
        handler: f.handler && f.handler.exists ? f.handler.file : null,
        submitMode: f.submitMode,
        planBefore: f.plan.status,
        reasons: f.plan.reasons,
        outcome: null,
        errors: [],
      };
      if (f.plan.status === 'skip') rec.outcome = 'skipped';
      else if (f.plan.status === 'done') rec.outcome = 'already-protected';
      else if (!st) rec.outcome = f.plan.status === 'review' ? 'needs-review' : 'manual';
      else {
        rec.errors = st.errors.slice();
        for (const rel of st.files) if (lintFailed.has(rel)) rec.errors.push({ code: 'php-syntax-check-failed', file: rel });
        const verified = aft && aft.plan.status === 'done';
        rec.outcome = !rec.errors.length && verified ? 'protected' : 'failed';
        if (!rec.errors.length && !verified) rec.errors.push({ code: 'verification-failed' });
      }
      result.forms.push(rec);
    });
    const count = (o) => result.forms.filter((f) => f.outcome === o).length;
    const nProt = count('protected');
    const nOpen = result.forms.filter((f) => ['manual', 'needs-review', 'failed'].includes(f.outcome)).length;
    result.summary = {
      forms: result.forms.length,
      enquiryForms: result.forms.filter((f) => f.outcome !== 'skipped').length,
      protected: nProt,
      alreadyProtected: count('already-protected'),
      needsReview: count('needs-review'),
      manual: count('manual'),
      failed: count('failed'),
      filesChanged: new Set(result.changes.map((c) => c.file)).size,
    };
    result.verification.rescan = { formsProtectedAfter: after.forms.filter((f) => f.plan.status === 'done').length, autoLeft: after.summary.auto, reviewLeft: after.summary.review };
    result.status = !anyApplied ? (nOpen ? 'manual-only' : 'nothing-to-do') : nOpen ? 'partial' : 'protected';
    if (result.summary.enquiryForms === 0) result.status = 'no-forms';
    if (result.changes.length === 0 && result.summary.alreadyProtected && !nOpen) result.status = 'already-protected';

    // ---- outputs
    if (!opts.dryRun && result.changes.length > 0) {
      const base = path.join(outDirAbs, safeName(name));
      fs.mkdirSync(base, { recursive: true });
      const backup = path.join(base, safeName(name) + '-backup-original.zip');
      if (loaded.source === 'zip') fs.copyFileSync(path.resolve(input), backup);
      else zipFolder(loaded.root, backup);
      const prot = path.join(base, safeName(name) + '-protected.zip');
      zipFolder(siteDir, prot);
      result.outputs = { dir: base, backupZip: backup, protectedZip: prot };
      if (opts.keepFolder) {
        const keep = path.join(base, 'protected-site');
        fs.rmSync(keep, { recursive: true, force: true });
        copyTree(siteDir, keep, listTree(siteDir));
        result.outputs.folder = keep;
      }
    }
    return result;
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
    loaded.cleanup();
  }
}

module.exports = { protectSite, zipFolder, listTree, safeName, relToRoot };
