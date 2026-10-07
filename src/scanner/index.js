'use strict';
const fs = require('fs');
const path = require('path');
const { prepareInput } = require('./loader');
const { walk, readText, resolveRel, LIMITS } = require('./util');
const { splitPhp, phpGeneratedForms } = require('./phpmask');
const { parseHtml, externalService } = require('./forms');
const { extractContacts, newContactAcc, finishContacts } = require('./contacts');
const { analyzePhp, guessSuccessJson } = require('./php');
const { isLibraryJs, linkAjax } = require('./ajax');
const { parseDump } = require('./sql');
const { planForm } = require('./plan');

const VERSION = '0.2.0';
const MARKUP_EXT = new Set(['.html', '.htm', '.shtml', '.php', '.phtml', '.inc']);
const PHP_EXT = new Set(['.php', '.phtml', '.inc']);
const NON_PHP_HANDLER = /\.(asp|aspx|cgi|pl|py|rb|jsp|cfm|html?|shtml)$/i;
const NOT_A_PAGE_DIR = /(^|\/)(inc|includes?|lib|libs|classes|class|config|configs|functions|partials|templates?|layouts?|vendor|admin\/inc|src)\//i;
const CMS_FORM_PLUGINS = /^wp-content\/plugins\/(contact-form-7|wpforms(-lite)?|ninja-forms|gravityforms|formidable|forminator|fluentform|everest-forms|weforms|jetpack|elementor|ultimate-addons)/;

function detectPlatform(files) {
  const has = (re) => files.some((f) => re.test(f.rel));
  if (has(/^wp-config(-sample)?\.php$|^wp-content\/|^wp-includes\//)) return { name: 'WordPress', cms: true };
  if (has(/^administrator\/index\.php$/) && has(/^configuration\.php$/)) return { name: 'Joomla', cms: true };
  if (has(/^core\/lib\/Drupal\.php$|^sites\/default\//)) return { name: 'Drupal', cms: true };
  if (has(/^artisan$/) && has(/^composer\.json$/)) return { name: 'Laravel', cms: true };
  if (has(/^system\/core\/CodeIgniter\.php$/)) return { name: 'CodeIgniter', cms: true };
  if (has(/^app\/Mage\.php$|^app\/etc\/env\.php$/)) return { name: 'Magento', cms: true };
  if (has(/^catalog\/controller\//)) return { name: 'OpenCart', cms: true };
  if (files.some((f) => PHP_EXT.has(f.ext))) return { name: 'plain PHP', cms: false };
  return { name: 'static HTML', cms: false };
}

const EXPOSED = [
  [/\.sql(\.gz)?$/i, 'database-dump'],
  [/\.(bak|old|orig|save|swp)$/i, 'backup-copy'],
  [/(^|\/)\.env(\.[\w-]+)?$/i, 'env-file'],
  [/\.(zip|tar|tgz|tar\.gz|rar|7z)$/i, 'archive'],
  [/(^|\/)(phpinfo|info|test|phpmyadmin|adminer)\.php$/i, 'info-script'],
  [/(^|\/)(error_log|php_errors\.log|debug\.log)$/i, 'log-file'],
  [/(^|\/)(\.htpasswd|id_rsa|credentials\.json)$/i, 'secret-file'],
];

/** `action="<?php echo $_SERVER['PHP_SELF']; ?>"` is a form posting to itself, not an unknown dynamic action. */
function normalizeSelfAction(text) {
  return text.replace(
    /(\baction\s*=\s*)(["'])\s*<\?(?:php|=)[^?]*?(?:PHP_SELF|REQUEST_URI|SCRIPT_NAME|__FILE__)[^?]*?\?>\s*\2/gi,
    (m, a, q) => a + q + q + '\n'.repeat((m.match(/\n/g) || []).length)
  );
}

const emptyCaps = () => ({
  readsPost: false, sendsMail: false, usesDb: false, writesFile: false, acceptsUpload: false, guardCalled: false,
  mailVia: [], mailRecipients: [], dbEngines: [], insertTables: [], verifiesCaptcha: [], postFields: [], dbNames: [],
  configFiles: [], files: [],
});
const uniq = (a) => Array.from(new Set(a));

function mergeCaps(into, an, rel) {
  for (const k of ['readsPost', 'sendsMail', 'usesDb', 'writesFile', 'acceptsUpload', 'guardCalled']) into[k] = into[k] || an[k];
  into.mailVia = uniq(into.mailVia.concat(an.mailVia));
  into.mailRecipients = uniq(into.mailRecipients.concat(an.mailRecipients));
  into.dbEngines = uniq(into.dbEngines.concat(an.dbEngines));
  into.verifiesCaptcha = uniq(into.verifiesCaptcha.concat(an.verifiesCaptcha));
  into.postFields = uniq(into.postFields.concat(an.postFields));
  if (an.dbName) into.dbNames = uniq(into.dbNames.concat(an.dbName));
  if (an.definesDbConnection) into.configFiles = uniq(into.configFiles.concat(rel));
  for (const t of an.insertTables) {
    const cur = into.insertTables.find((x) => x.table === t.table);
    if (!cur) into.insertTables.push({ table: t.table, columns: t.columns.slice() });
    else if (t.columns.length > cur.columns.length) cur.columns = t.columns.slice();
  }
  into.files.push(rel);
}

async function scanLoaded(loaded, opts) {
  const t0 = Date.now();
  const root = loaded.root;
  const warnings = loaded.warnings.map((w) => Object.assign({ level: 'warn' }, w));
  const files = walk(root);
  if (files.truncated) warnings.push({ code: 'files-truncated', level: 'warn', limit: LIMITS.maxFiles });
  if (loaded.rootRel) warnings.push({ code: 'site-root-inside', level: 'info', path: loaded.rootRel });

  const byRel = new Map(files.map((f) => [f.rel, f]));
  const byLower = new Map(files.map((f) => [f.rel.toLowerCase(), f.rel]));
  const exists = (rel) => (byRel.has(rel) ? rel : byLower.get(rel.toLowerCase()) || null);
  const platform = detectPlatform(files);

  const skipAnalysis = (rel) =>
    /(^|\/)vendor\//.test(rel) ||
    /(^|\/)spamguard\//.test(rel) ||
    (platform.name === 'WordPress' && /^(wp-admin|wp-includes)\/|^wp-content\/(plugins|uploads|cache|upgrade)\//.test(rel));

  // ------------------------------------------------------------ pass 1: read every page-like file
  const pages = new Map(); // rel -> info
  const phpInfo = new Map(); // rel -> analyzePhp
  const incTargets = new Map(); // rel -> [target rel]
  const contactAcc = newContactAcc();
  const allScripts = [];
  const rawIncludes = [];
  let analyzed = 0;
  for (const f of files) {
    if (!MARKUP_EXT.has(f.ext) || skipAnalysis(f.rel) || f.size > LIMITS.maxTextBytes) continue;
    if (platform.name === 'WordPress' && ++analyzed > 600) continue;
    const text = readText(path.join(root, f.rel));
    if (text === null) continue;
    const hasPhpTag = /<\?(?!xml)/i.test(text);
    const sp = hasPhpTag ? splitPhp(normalizeSelfAction(text)) : { html: text, php: '', blocks: [], hasPhp: false };
    const parsed = parseHtml(f.rel, sp.html);
    const gen = hasPhpTag ? phpGeneratedForms(sp.blocks) : [];
    extractContacts(f.rel, sp.html, contactAcc);
    if (sp.hasPhp) {
      const an = analyzePhp(sp.php);
      phpInfo.set(f.rel, an);
      for (const inc of an.includes) rawIncludes.push({ from: f.rel, inc });
    }
    for (const s of parsed.scripts.inline) allScripts.push({ file: f.rel, line: s.line, text: s.text, kind: 'inline' });
    const visible = sp.html.replace(/\{\{PHP\}\}/g, '').replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, '').replace(/<[^>]*>/g, '').trim().length;
    pages.set(f.rel, { rel: f.rel, parsed, phpGeneratedForms: gen, hasPhp: sp.hasPhp, visibleLength: visible });
  }
  for (const f of files) {
    if (f.ext !== '.js' || isLibraryJs(f.rel) || f.size > 300 * 1024 || skipAnalysis(f.rel)) continue;
    const text = readText(path.join(root, f.rel), 300 * 1024);
    if (text !== null) allScripts.push({ file: f.rel, line: null, text, kind: 'file' });
  }

  // ------------------------------------------------------------ include graph
  const resolveInclude = (from, inc) => {
    const p = inc.path;
    const cands = [];
    if (inc.base === 'root') cands.push(resolveRel('', p));
    else if (inc.base === 'dir') cands.push(resolveRel(from, p.replace(/^\/+/, '')));
    else {
      cands.push(resolveRel(from, p));
      cands.push(resolveRel('', p));
    }
    for (const c of cands) {
      if (c === null) continue;
      const hit = exists(c);
      if (hit) return hit;
    }
    return null;
  };
  const rinc = new Map();
  for (const { from, inc } of rawIncludes) {
    const t = resolveInclude(from, inc);
    if (!t) continue;
    if (!incTargets.has(from)) incTargets.set(from, []);
    incTargets.get(from).push(t);
    if (!rinc.has(t)) rinc.set(t, new Set());
    rinc.get(t).add(from);
  }
  const closure = (start, graph, maxDepth) => {
    const out = new Set();
    const walkG = (n, d) => {
      if (d > maxDepth) return;
      const next = graph instanceof Map && graph.get(n);
      if (!next) return;
      for (const x of next) {
        if (!out.has(x)) {
          out.add(x);
          walkG(x, d + 1);
        }
      }
    };
    walkG(start, 0);
    return out;
  };
  const effectiveCache = new Map();
  const effective = (rel) => {
    if (effectiveCache.has(rel)) return effectiveCache.get(rel);
    const caps = emptyCaps();
    const direct = phpInfo.get(rel);
    if (direct) mergeCaps(caps, direct, rel);
    for (const t of closure(rel, incTargets, 3)) {
      const an = phpInfo.get(t);
      if (an) mergeCaps(caps, an, t);
    }
    effectiveCache.set(rel, caps);
    return caps;
  };

  // pages (SEO snapshot) — a "page" is something a visitor can open and read
  const isPage = (p) => {
    if (['.html', '.htm', '.shtml'].includes(path.extname(p.rel).toLowerCase())) return true;
    if (NOT_A_PAGE_DIR.test(p.rel) || p.visibleLength < 20) return false;
    return p.parsed.snapshot.hasHtmlShell || p.parsed.snapshot.h1Count > 0 || p.parsed.forms.length > 0;
  };
  const pagesList = [];
  const clientScriptFiles = new Set(); // files that load spamguard.js, directly
  for (const p of pages.values()) {
    if (p.parsed.snapshot.hasSpamGuardScript) clientScriptFiles.add(p.rel);
  }
  const hasClient = (formRel) => {
    if (clientScriptFiles.has(formRel)) return true;
    for (const x of closure(formRel, rinc, 3)) if (clientScriptFiles.has(x)) return true; // a page that includes the form
    for (const x of closure(formRel, incTargets, 3)) if (clientScriptFiles.has(x)) return true; // an include with the script
    return false;
  };
  for (const p of pages.values()) {
    if (!isPage(p)) continue;
    pagesList.push(Object.assign({ file: p.rel, formCount: p.parsed.forms.length, includes: (incTargets.get(p.rel) || []).slice(0, 10) }, p.parsed.snapshot));
  }

  // ------------------------------------------------------------ resolve where a form posts to
  const resolveTarget = (fromRel, raw) => {
    const r = { raw: raw === undefined ? null : raw, type: 'none', rel: null, exists: false, service: null, note: null };
    const s = (raw || '').trim();
    if (raw === undefined || s === '' || s === '#') {
      r.type = 'self';
      r.rel = fromRel;
      r.exists = true;
      return r;
    }
    if (/^mailto:/i.test(s)) return Object.assign(r, { type: 'mailto' });
    if (/^javascript:/i.test(s)) return Object.assign(r, { type: 'js' });
    if (s.includes('{{PHP}}')) return Object.assign(r, { type: 'dynamic' });
    let p = s;
    if (/^(https?:)?\/\//i.test(s)) {
      const svc = externalService(s);
      if (svc) return Object.assign(r, { type: 'external', service: svc });
      try {
        p = new URL(s.startsWith('//') ? 'https:' + s : s).pathname;
        r.note = 'absolute-url';
      } catch (e) {
        return Object.assign(r, { type: 'external' });
      }
      const local = exists(resolveRel('', p) || '');
      if (!local) return Object.assign(r, { type: 'external', service: null });
    }
    p = p.replace(/[?#].*$/, '');
    if (p === '') {
      r.type = 'self';
      r.rel = fromRel;
      r.exists = true;
      return r;
    }
    let cands = [resolveRel(fromRel, p), resolveRel('', p)];
    if (p.endsWith('/')) cands = cands.map((c) => (c === null ? null : (c ? c + '/' : '') + 'index.php'));
    for (const c of cands) {
      if (c === null) continue;
      const hit = exists(c);
      if (hit) {
        r.type = 'local';
        r.rel = hit;
        r.exists = true;
        if (hit !== c) r.note = 'case-mismatch';
        return r;
      }
    }
    r.type = 'local';
    r.rel = cands.find((c) => c !== null) || p;
    r.exists = false;
    return r;
  };

  // ------------------------------------------------------------ pass 2: build the forms
  const forms = [];
  const formsByHandler = new Map();
  for (const p of pages.values()) {
    const using = Array.from(closure(p.rel, rinc, 3)).filter((x) => pages.has(x) && isPage(pages.get(x)));
    const ctxFiles = new Set([p.rel, ...closure(p.rel, rinc, 3)]);
    for (const x of Array.from(ctxFiles)) for (const y of closure(x, incTargets, 3)) ctxFiles.add(y);
    const generalScripts = allScripts.filter((s) => ctxFiles.has(s.file));
    const pf = p.parsed.forms.map((f) => ({ f, generated: false }));
    for (const g of p.phpGeneratedForms) pf.push({ f: null, generated: true, line: g.line });
    for (const entry of pf) {
      if (entry.generated) {
        const rec = {
          id: p.rel + ':' + entry.line, file: p.rel, line: entry.line, endLine: null, label: 'form printed by PHP code', kind: 'enquiry',
          protectable: true, generatedByPhp: true, attrs: {}, fields: [], submitMode: 'classic',
          action: { raw: null, type: 'dynamic', rel: null, exists: false, service: null, note: null }, ajax: null, handler: null,
          existing: { captcha: [], csrf: false, honeypot: false, clientScript: false },
        };
        rec.plan = planForm(rec, { platform, handlerMixedKinds: new Map() });
        forms.push(rec);
        continue;
      }
      const f = entry.f;
      const protectable = ['enquiry', 'newsletter', 'callback'].includes(f.kind);
      const rec = {
        id: f.file + ':' + f.line,
        file: f.file,
        line: f.line,
        endLine: f.endLine,
        label: f.attrs.id || f.attrs.name || f.submitText || 'form',
        kind: f.kind,
        protectable,
        generatedByPhp: false,
        attrs: { id: f.attrs.id, name: f.attrs.name, class: f.attrs.class, method: f.attrs.method, action: f.attrs.action === undefined ? null : f.attrs.action },
        fields: f.fields.filter((x) => x.tag !== 'button' && !['submit', 'button', 'image', 'reset'].includes(x.type)).map((x) => ({ name: x.name, id: x.id, type: x.type, required: x.required })),
        hasFileUpload: f.hasFileUpload,
        submitMode: 'classic',
        action: null,
        ajax: null,
        handler: null,
        pagesUsing: using,
        existing: { captcha: f.captcha, csrf: f.hasCsrf, honeypot: f.hasHoneypot, clientScript: f.hasSgFields || hasClient(f.file) },
      };
      rec.action = resolveTarget(f.file, f.attrs.action);
      let target = rec.action;
      if (protectable && !rec.action.type.match(/^(external|mailto)$/)) {
        const aj = linkAjax(Object.assign({}, f, { fieldIds: f.fields.map((x) => x.id).filter(Boolean) }), allScripts, generalScripts);
        if (aj) {
          rec.submitMode = 'ajax';
          rec.ajax = { url: aj.url, usesFormAction: aj.usesFormAction, confidence: aj.confidence, file: aj.file, line: aj.line, kind: aj.kind, expects: aj.expects };
          if (aj.url && !aj.usesFormAction) target = resolveTarget(f.file, aj.url);
        }
      }
      if (protectable && target.type !== 'external' && target.type !== 'mailto') {
        const hrel = target.rel && target.exists ? target.rel : null;
        const isPhp = !!hrel && PHP_EXT.has(path.extname(hrel).toLowerCase()) && !NON_PHP_HANDLER.test(hrel);
        if (hrel) {
          const caps = effective(hrel);
          const direct = phpInfo.get(hrel);
          const jsonGuess = direct ? guessSuccessJson(direct) : null;
          const expects = rec.ajax ? rec.ajax.expects : null;
          let successJson = null;
          let successText = null;
          let conf = null;
          if (rec.submitMode === 'ajax') {
            if (jsonGuess) {
              successJson = jsonGuess.json;
              conf = 'high';
            } else if (expects && expects.hints.some((h) => h.key && h.op === '==' && h.value)) {
              successJson = {};
              for (const h of expects.hints) if (h.key && h.op === '==' && h.value && !(h.key in successJson)) successJson[h.key] = /^(true|false)$/.test(h.value) ? h.value === 'true' : /^\d+$/.test(h.value) ? Number(h.value) : h.value;
              conf = 'medium';
            }
            if (!successJson && direct && direct.textResponses.length) {
              const want = expects ? expects.hints.filter((h) => !h.key).map((h) => h.value.toLowerCase()) : [];
              const t = direct.textResponses.find((x) => want.includes(x.text.toLowerCase())) || direct.textResponses.find((x) => /^(ok|success|sent|1|true|thank.*)$/i.test(x.text));
              if (t) {
                successText = t.text;
                conf = want.includes(t.text.toLowerCase()) ? 'high' : 'medium';
              }
            }
          }
          const redirect = (direct ? direct.redirects : []).find((r) => r && !/[$]/.test(r)) || null;
          rec.handler = {
            file: hrel,
            path: hrel,
            exists: true,
            isPhp,
            capabilities: {
              readsPost: caps.readsPost, sendsMail: caps.sendsMail, mailVia: caps.mailVia, usesDb: caps.usesDb, dbEngines: caps.dbEngines,
              writesFile: caps.writesFile, acceptsUpload: caps.acceptsUpload, verifiesCaptcha: caps.verifiesCaptcha, guardCalled: caps.guardCalled,
            },
            postFields: caps.postFields,
            mailRecipients: caps.mailRecipients,
            tables: caps.insertTables,
            includedFiles: caps.files.filter((x) => x !== hrel),
            response: { successJson, successText, redirect, confidence: conf },
            injection: direct ? { firstPhpLine: direct.firstPhpLine, hasDeclareStrict: direct.hasDeclareStrict, hasNamespace: direct.hasNamespace } : null,
          };
          if (!formsByHandler.has(hrel)) formsByHandler.set(hrel, []);
          formsByHandler.get(hrel).push(rec);
        } else {
          rec.handler = { file: target.rel, path: target.rel || target.raw, exists: false, isPhp: false };
        }
      }
      forms.push(rec);
    }
  }
  // one handler shared by an enquiry form AND something else (login etc.) => a person should look
  const handlerMixedKinds = new Map();
  for (const [h, list] of formsByHandler) {
    const sameFile = pages.get(h);
    if (sameFile && sameFile.parsed.forms.length > 1) {
      const kinds = new Set(sameFile.parsed.forms.map((x) => (['enquiry', 'newsletter', 'callback'].includes(x.kind) ? 'e' : x.kind)));
      if (kinds.size > 1) handlerMixedKinds.set(h, true);
    }
  }
  for (const rec of forms) if (!rec.plan) rec.plan = planForm(rec, { platform, handlerMixedKinds });

  // ------------------------------------------------------------ database + SQL dumps
  const dumps = [];
  const dumpFiles = files.filter((f) => /\.sql(\.gz)?$/i.test(f.rel) && f.size < 2 * 1024 * 1024 * 1024).slice(0, 6).map((f) => ({ rel: f.rel, abs: path.join(root, f.rel), size: f.size }));
  for (const x of opts.sqlFiles || []) {
    try {
      const st = fs.statSync(x);
      dumpFiles.push({ rel: path.basename(x), abs: path.resolve(x), size: st.size, external: true });
    } catch (e) {
      warnings.push({ code: 'sql-file-missing', level: 'warn', path: x });
    }
  }
  for (const d of dumpFiles) {
    try {
      const res = await parseDump(d.abs);
      dumps.push({ file: d.rel, sizeBytes: d.size, external: !!d.external, tables: res.tables });
    } catch (e) {
      warnings.push({ code: 'sql-unreadable', level: 'warn', path: d.rel, message: e.message });
    }
  }
  const allCaps = emptyCaps();
  for (const [rel, an] of phpInfo) mergeCaps(allCaps, an, rel);
  const dumpTable = (name) => {
    for (const d of dumps) {
      const t = d.tables.find((x) => x.name.toLowerCase() === name.toLowerCase());
      if (t) return { dump: d.file, table: t };
    }
    return null;
  };
  for (const rec of forms) {
    if (rec.handler && rec.handler.exists) {
      rec.handler.tables = rec.handler.tables.map((t) => {
        const hit = dumpTable(t.table);
        return Object.assign({}, t, hit ? { inDump: hit.dump, dumpColumns: hit.table.columns.map((c) => c.name), insertStatements: hit.table.insertStatements } : { inDump: null });
      });
    }
  }
  const enquiryTables = [];
  const seenT = new Set();
  for (const d of dumps) {
    for (const t of d.tables) {
      if (t.looksLikeEnquiries && !seenT.has(t.name)) {
        seenT.add(t.name);
        const handlers = uniq(forms.filter((r) => r.handler && r.handler.exists && r.handler.tables.some((x) => x.table.toLowerCase() === t.name.toLowerCase())).map((r) => r.handler.file));
        enquiryTables.push({ name: t.name, source: 'dump', dump: d.file, columns: t.columns.map((c) => c.name), insertStatements: t.insertStatements, hasStatusColumn: t.hasStatusColumn, hasDateColumn: t.hasDateColumn, handlers });
      }
    }
  }
  for (const rec of forms) {
    if (!rec.handler || !rec.handler.exists) continue;
    for (const t of rec.handler.tables) {
      if (!seenT.has(t.table) && /enquir|inquir|contact|lead|quer|message|submission|request|booking|feedback/i.test(t.table)) {
        seenT.add(t.table);
        enquiryTables.push({ name: t.table, source: 'handler-code', columns: t.columns, insertStatements: null, handlers: [rec.handler.file] });
      }
    }
  }
  const database = {
    used: allCaps.usesDb || dumps.length > 0,
    engines: allCaps.dbEngines,
    configFiles: allCaps.configFiles,
    databaseNames: allCaps.dbNames,
    sqlDumps: dumps.map((d) => ({ file: d.file, sizeBytes: d.sizeBytes, tableCount: d.tables.length, tables: d.tables.map((t) => ({ name: t.name, columns: t.columns.length, rows: t.insertStatements > 0 ? 'has-data' : 'empty', looksLikeEnquiries: t.looksLikeEnquiries })) })),
    enquiryTables,
    note: 'Passwords and row data are never read or stored.',
  };

  // ------------------------------------------------------------ misc: security quick-look, SEO files, CMS forms
  const exposedFiles = [];
  for (const f of files) {
    for (const [re, kind] of EXPOSED) {
      if (re.test(f.rel)) {
        if (kind === 'archive' && f.size < 1024) break;
        exposedFiles.push({ file: f.rel, kind, sizeBytes: f.size });
        break;
      }
    }
  }
  if (fs.existsSync(path.join(root, '.git'))) exposedFiles.push({ file: '.git/', kind: 'git-folder', sizeBytes: 0 });
  const cmsForms = platform.cms ? uniq(files.map((f) => (f.rel.match(CMS_FORM_PLUGINS) || [])[1]).filter(Boolean)) : [];
  const siteFiles = {
    robotsTxt: byRel.has('robots.txt'),
    sitemapXml: byRel.has('sitemap.xml') || files.some((f) => /^sitemap.*\.xml$/i.test(f.rel)),
    htaccess: byRel.has('.htaccess'),
    spamguardInstalled: files.some((f) => /(^|\/)spamguard\/spamguard\.php$/.test(f.rel)),
  };

  // ------------------------------------------------------------ summary
  const count = (s) => forms.filter((f) => f.plan.status === s).length;
  const protectable = forms.filter((f) => f.protectable);
  const summary = {
    forms: forms.length,
    enquiryForms: protectable.length,
    auto: count('auto'),
    review: count('review'),
    manual: count('manual'),
    skip: count('skip'),
    done: count('done'),
    ajaxForms: forms.filter((f) => f.submitMode === 'ajax').length,
    pages: pagesList.length,
    exposedFiles: exposedFiles.length,
  };
  if (!pagesList.length && !forms.length) warnings.push({ code: 'no-pages', level: 'warn' });
  const mailGuess = uniq(forms.filter((f) => f.handler && f.handler.exists).flatMap((f) => f.handler.mailRecipients));
  const siteActions = [];
  if (summary.auto + summary.review > 0) {
    siteActions.push({ type: 'install-kit', to: 'spamguard/', alreadyThere: siteFiles.spamguardInstalled });
    siteActions.push({ type: 'write-config', siteId: loaded.name.toLowerCase().replace(/[^a-z0-9._-]+/g, '-'), notifyEmailGuess: mailGuess[0] || null });
  }
  return {
    scanner: { version: VERSION, scannedAt: new Date().toISOString(), durationMs: Date.now() - t0 },
    site: {
      name: loaded.name,
      source: loaded.source,
      platform: platform.name,
      cms: platform.cms,
      cmsFormPlugins: cmsForms,
      files: files.length,
      sizeBytes: files.reduce((a, f) => a + f.size, 0),
      phpFiles: files.filter((f) => PHP_EXT.has(f.ext)).length,
      htmlFiles: files.filter((f) => ['.html', '.htm', '.shtml'].includes(f.ext)).length,
      jsFiles: files.filter((f) => f.ext === '.js').length,
      siteFiles,
    },
    summary,
    database,
    forms,
    pages: pagesList,
    contacts: finishContacts(contactAcc),
    security: { exposedFiles },
    plan: { siteActions },
    warnings,
  };
}

/** Scan one site: a folder or a .zip. Never executes anything from the site. */
async function scanSite(input, opts = {}) {
  const loaded = prepareInput(input);
  try {
    return await scanLoaded(loaded, opts);
  } finally {
    loaded.cleanup();
  }
}

module.exports = { scanSite, VERSION };
