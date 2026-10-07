'use strict';

/** Plain-language (Hinglish) report for non-technical users. The JSON report stays the source of truth. */

const STATUS = {
  auto: 'AUTO   - apne aap protect ho jayega',
  review: 'REVIEW - ek baar dekhna padega',
  manual: 'MANUAL - haath se karna padega',
  skip: 'SKIP   - enquiry form nahi hai',
  done: 'DONE   - pehle se protected hai',
};

const KIND = { login: 'login', search: 'search', other: 'koi aur', newsletter: 'newsletter', callback: 'call-back', enquiry: 'enquiry' };

const REASON = {
  'not-enquiry': (r) => `Ye ${KIND[r.kind] || r.kind} form hai, enquiry form nahi, isliye chhod diya.`,
  cms: (r) => `${r.cms} site hai. Yahan forms plugin/theme se bante hain, tool se sahi protect nahi honge.`,
  'php-generated': () => 'Form PHP code ke andar echo se ban raha hai. Tool ise safe tarah edit nahi kar sakta.',
  'external-service': (r) => `Form ka data ${r.service} ko jata hai, aapke server par aata hi nahi. Server-side protection mumkin nahi.`,
  'mailto-form': () => 'Form "mailto:" use karta hai (user ka email app khulta hai). Isse spam rok nahi sakte, PHP handler banana padega.',
  'dynamic-action': () => 'Form ka action PHP se banta hai, pata nahi chal raha ki data kahan jata hai.',
  'js-action': () => 'Form javascript: se submit hota hai aur handler nahi mila.',
  'handler-missing': (r) => `Form jis file par data bhejta hai (${r.path || '?'}) wo zip/folder mein nahi mili.`,
  'handler-not-php': (r) => `Handler (${r.path}) PHP file nahi hai.`,
  'handler-no-post': (r) => `${r.file} mein form ka data padhne ka code nahi dikha (shayad kisi aur file mein hai).`,
  'ajax-link-uncertain': () => 'Form AJAX se submit hota hai, par JS aur form ka jod pakka nahi hua.',
  'ajax-response-unknown': () => 'AJAX form hai, par handler ka "success" jawab samajh nahi aaya. Spam par nakli success kaisa bhejna hai ye dekhna padega.',
  'ajax-response-found': (r) => `AJAX form hai, handler ka success jawab mil gaya${r.json ? ' (JSON)' : ' (text)'}.`,
  'shared-handler-multiple-forms': (r) => `${r.file} par ek se zyada tarah ke forms hain (jaise login + enquiry), dhyan se lagana padega.`,
  'existing-captcha': (r) => `Pehle se ${r.types.join(', ')} laga hai. Ye extra layer rahegi.`,
  'file-upload': () => 'Form mein file upload bhi hai.',
  'form-in-include': (r) => `Ye form shared file mein hai, ${r.pages} page(s) par dikhta hai.`,
  'self-post': () => 'Form usi page par submit hota hai.',
  'already-protected': () => 'SpamGuard pehle se laga hai.',
  'client-script-missing': () => 'Server side guard laga hai, par page par script tag nahi hai.',
  'guard-missing': () => 'Page par script hai, par handler mein guard nahi hai.',
};

const EXPOSED = {
  'database-dump': 'Database ka backup (.sql) site folder mein pada hai. Server par public ho to koi bhi download kar sakta hai. Hata do.',
  'backup-copy': 'Purani/backup copy ki file hai (.bak/.old). Code ya password leak kar sakti hai. Hata do.',
  'env-file': '.env file hai, isme secret keys hoti hain. Public nahi honi chahiye.',
  archive: 'Zip/archive file site folder mein hai. Hata do.',
  'info-script': 'phpinfo/test/adminer jaisi file hai, hackers ke kaam aati hai. Hata do.',
  'log-file': 'Error log file hai, andar server ke raaz ho sakte hain.',
  'secret-file': 'Secret/password file mili. Turant hata do.',
  'git-folder': '.git folder hai, poora source code bahar nikal sakta hai.',
};

const WARN = {
  'no-pages': () => 'Koi page ya form nahi mila. Shayad galat folder diya hai?',
  'files-truncated': (w) => `Bahut zyada files hain, sirf pehli ${w.limit} scan hui.`,
  'site-root-inside': (w) => `Site ka asli folder "${w.path}" ke andar mila, wahin se scan kiya.`,
  'zip-unsafe-path': (w) => `ZIP mein khatarnak path wali file thi, use chhod diya (${w.file}).`,
  'zip-symlink-skipped': (w) => `ZIP mein shortcut (symlink) thi, chhod di (${w.file}).`,
  'zip-file-too-large': (w) => `Bahut badi file chhod di (${w.file}).`,
  'zip-entry-unreadable': (w) => `ZIP ki ek file padh nahi paye (${w.file}).`,
  'sql-file-missing': (w) => `SQL file nahi mili: ${w.path}`,
  'sql-unreadable': (w) => `SQL dump padh nahi paye (${w.path}).`,
};

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

function handlerLine(h) {
  const parts = [];
  if (h.capabilities.sendsMail) parts.push(`mail bhejta hai (${h.capabilities.mailVia.join(', ')})`);
  if (h.capabilities.usesDb) {
    const t = h.tables.map((x) => x.table);
    parts.push('database mein save karta hai' + (t.length ? ` (table: ${t.join(', ')})` : ''));
  }
  if (h.capabilities.writesFile) parts.push('file mein likhta hai');
  if (!parts.length) parts.push('koi mail/database ka code nahi dikha');
  return parts.join(', ');
}

function actionLine(a) {
  if (a.type === 'add-script-tag') return `page par script tag lagegi (${a.file})`;
  if (a.type === 'add-guard-call') return `${a.file} ke top par guard line lagegi`;
  if (a.type === 'set-success-response') {
    if (a.json) return `spam par bot ko ye nakli success jayega: ${JSON.stringify(a.json)}`;
    if (a.text) return `spam par bot ko ye nakli success jayega: "${a.text}"`;
    if (a.redirect) return `spam par bot "${a.redirect}" par bheja jayega`;
  }
  return a.type;
}

function renderText(r) {
  const L = [];
  const bar = '='.repeat(64);
  const s = r.summary;
  L.push(bar);
  L.push(`SITE: ${r.site.name}   (${r.site.source}, ${r.site.platform})`);
  L.push(`Files: ${r.site.files}  (PHP ${r.site.phpFiles}, HTML ${r.site.htmlFiles}, JS ${r.site.jsFiles})`);
  L.push(bar);
  L.push(`Kul forms: ${s.forms}   |   protect ho sakte hain: ${s.enquiryForms}`);
  L.push(`AUTO ${s.auto}  |  REVIEW ${s.review}  |  MANUAL ${s.manual}  |  SKIP ${s.skip}  |  DONE ${s.done}`);
  L.push('');

  const d = r.database;
  if (d.used) {
    L.push(`DATABASE: haan${d.engines.length ? ' (' + d.engines.join(', ') + ')' : ''}`);
    if (d.configFiles.length) L.push(`  Connection file: ${d.configFiles.join(', ')}`);
    for (const dump of d.sqlDumps) L.push(`  SQL dump: ${dump.file} (${plural(dump.tableCount, 'table', 'tables')})`);
    for (const t of d.enquiryTables) {
      L.push(`  Enquiry table: ${t.name}  [${t.columns.slice(0, 8).join(', ')}${t.columns.length > 8 ? ', ...' : ''}]` + (t.handlers.length ? `  <- ${t.handlers.join(', ')}` : ''));
    }
  } else {
    L.push('DATABASE: nahi mila (is site mein enquiry mail ya file se jaati hai). SpamGuard apna chhota SQLite use karega.');
  }
  L.push('');

  if (r.forms.length) {
    L.push('FORMS:');
    r.forms.forEach((f, i) => {
      L.push(` ${i + 1}. ${f.file}:${f.line || '?'}  [${KIND[f.kind] || f.kind}]  "${f.label}"`);
      if (f.fields && f.fields.length) L.push(`    fields: ${f.fields.filter((x) => x.type !== 'hidden').map((x) => x.name || x.id || '(naam nahi)').join(', ') || '-'}`);
      if (f.handler && f.handler.exists) {
        L.push(`    bhejta hai: ${f.handler.file}  (${f.submitMode === 'ajax' ? 'AJAX' : 'normal submit'})`);
        L.push(`    handler: ${handlerLine(f.handler)}`);
      }
      L.push(`    ${STATUS[f.plan.status]}`);
      for (const reason of f.plan.reasons) {
        const fn = REASON[reason.code];
        if (fn && reason.code !== 'already-protected') L.push(`      - ${fn(reason)}`);
      }
      if (['auto', 'review'].includes(f.plan.status)) for (const a of f.plan.actions) L.push(`      > ${actionLine(a)}`);
    });
    L.push('');
  }

  const notes = [];
  for (const e of r.security.exposedFiles) notes.push(`${e.file}: ${EXPOSED[e.kind] || e.kind}`);
  const c = r.contacts;
  if (c.phones.length || c.emails.length) {
    notes.push(`Contact details mile: ${plural(c.phones.length, 'phone number', 'phone numbers')}, ${plural(c.emails.length, 'email', 'emails')} (hub se ek jagah se badal sakte honge).`);
  }
  const pg = r.pages;
  if (pg.length) {
    const noDesc = pg.filter((p) => !p.metaDescription && !p.titleDynamic).length;
    const noTitle = pg.filter((p) => !p.title && !p.titleDynamic).length;
    const noVp = pg.filter((p) => !p.viewport && p.hasHtmlShell).length;
    if (noTitle) notes.push(`${plural(noTitle, 'page', 'pages')} mein title nahi hai (SEO ke liye zaroori).`);
    if (noDesc) notes.push(`${plural(noDesc, 'page', 'pages')} mein meta description nahi hai.`);
    if (noVp) notes.push(`${plural(noVp, 'page', 'pages')} mein mobile viewport tag nahi hai (mobile par kharab dikh sakta hai).`);
  }
  if (!r.site.siteFiles.robotsTxt) notes.push('robots.txt nahi hai.');
  if (!r.site.siteFiles.sitemapXml) notes.push('sitemap.xml nahi hai (Google ko pages dhoondhne mein dikkat).');
  for (const w of r.warnings) {
    const fn = WARN[w.code];
    notes.push(fn ? fn(w) : w.code);
  }
  if (notes.length) {
    L.push('DHYAN DENE WALI BAATEIN:');
    for (const n of notes) L.push(` * ${n}`);
    L.push('');
  }
  L.push(`Note: ${r.database.note} Scan mein site ka koi code chalaya nahi gaya.`);
  return L.join('\n') + '\n';
}

function renderBulkText(b) {
  const L = [];
  const t = b.totals;
  L.push('='.repeat(72));
  L.push(`BULK SCAN: ${b.totals.sites} sites  |  scan ho gayi: ${t.ok}  |  fail: ${t.failed}`);
  L.push('='.repeat(72));
  L.push(`Kul forms: ${t.forms}  |  AUTO ${t.auto}  |  REVIEW ${t.review}  |  MANUAL ${t.manual}  |  DONE ${t.done}`);
  L.push(`Sites jisme database hai: ${t.withDb}   |   jisme exposed (khatarnak) files hain: ${t.withExposed}`);
  L.push('');
  const pad = (s, n) => (String(s).length > n ? String(s).slice(0, n - 1) + '~' : String(s).padEnd(n));
  L.push(`${pad('SITE', 28)} ${pad('PLATFORM', 12)} ${pad('FORMS', 6)} ${pad('AUTO', 5)} ${pad('REVW', 5)} ${pad('MANL', 5)} NOTE`);
  for (const row of b.rows) {
    if (row.status === 'failed') {
      L.push(`${pad(row.name, 28)} ${pad('-', 12)} ${pad('-', 6)} ${pad('-', 5)} ${pad('-', 5)} ${pad('-', 5)} FAIL: ${row.error}`);
      continue;
    }
    const note = [row.db === 'yes' ? 'DB' : null, row.exposedFiles ? `${row.exposedFiles} exposed` : null, row.enquiryForms === 0 ? 'no enquiry form' : null].filter(Boolean).join(', ');
    L.push(`${pad(row.name, 28)} ${pad(row.platform, 12)} ${pad(row.enquiryForms, 6)} ${pad(row.auto, 5)} ${pad(row.review, 5)} ${pad(row.manual, 5)} ${note}`);
  }
  L.push('');
  L.push('FORMS = protect ho sakne wale (enquiry) forms. Har site ki poori report reports/ folder mein hai.');
  return L.join('\n') + '\n';
}

module.exports = { renderText, renderBulkText, REASON, KIND };
