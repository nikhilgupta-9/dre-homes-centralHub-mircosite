'use strict';
const { REASON, KIND } = require('../scanner/report');

const STATUS_LINE = {
  protected: 'PROTECTED - sabhi enquiry forms protect ho gaye.',
  partial: 'PARTIAL - kuch forms protect hue, kuch ko haath se ya review ke baad karna hai (neeche list hai).',
  'manual-only': 'KUCH NAHI BADLA - jo forms mile unhe tool apne aap safe tarah protect nahi kar sakta (neeche wajah likhi hai).',
  'nothing-to-do': 'KUCH NAHI BADLA - protect karne layak koi form nahi mila.',
  'no-forms': 'KUCH NAHI BADLA - is site mein enquiry form hi nahi mila.',
  'already-protected': 'PEHLE SE PROTECTED - SpamGuard pehle se laga hua hai.',
  failed: 'FAIL - is site par kaam nahi ho paya.',
};

const OUTCOME = {
  protected: 'PROTECTED',
  'already-protected': 'PEHLE SE PROTECTED',
  'needs-review': 'REVIEW BAAKI (tool ne chhoda)',
  manual: 'MANUAL BAAKI',
  failed: 'FAIL',
  skipped: 'SKIP (enquiry form nahi)',
};

const ERR = {
  'php-not-at-top': 'handler file ke upar HTML hai, PHP baad mein shuru hota hai (guard sahi jagah nahi laga sakte)',
  'short-open-tag': 'handler "<?" jaisa short tag use karta hai',
  'bracketed-namespace': 'handler mein namespace { } hai',
  'no-php': 'handler mein PHP code hi nahi mila',
  'script-position-unsafe': 'script tag lagane ki surakshit jagah nahi mili',
  'php-syntax-check-failed': 'badlav ke baad PHP syntax check fail hua, file wapas original kar di',
  'verification-failed': 'badlav ke baad dobara scan mein form protected nahi dikha',
};

const WAHAN = [
  'ZIP ko khol kar uske andar ki saari files apni site ke folder (public_html) mein upload karo. Purani files overwrite hone do.',
  'Browser mein selftest kholo (link PRIVATE-login.txt mein hai). Sab kuch hara (PASS) dikhna chahiye. Phir server se selftest.php delete kar do.',
  'Site par ek test enquiry bhejo. Fir /spamguard/spam-admin.php kholo, wahan wo "Real" mein dikhni chahiye.',
  'Kuch galat lage to backup ZIP wapas upload kar do, site pehle jaisi ho jayegi.',
];

function manualHowTo(f) {
  if (!f.handler) return null;
  return `Haath se karna ho to: (1) page ${f.file} mein </body> se pehle <script src="/spamguard/spamguard.js" defer></script> lagao. (2) ${f.handler} ke bilkul upar <?php ke baad: require_once __DIR__ . '/spamguard/spamguard.php'; SpamGuard::guard();  (path folder ke hisaab se ../ badlo)`;
}

function renderProtectText(r) {
  const L = [];
  const bar = '='.repeat(64);
  L.push(bar, `SITE: ${r.site.name}   (${r.site.source}, ${r.site.platform || 'plain PHP'})`, bar);
  L.push(STATUS_LINE[r.status] || r.status);
  if (r.options && r.options.dryRun) L.push('(DRY RUN: sirf dikhaya gaya, koi file nahi likhi gayi)');
  L.push('');
  const s = r.summary;
  if (s) {
    L.push(`Enquiry forms: ${s.enquiryForms}   |   Protected: ${s.protected}   |   Pehle se: ${s.alreadyProtected}   |   Review baaki: ${s.needsReview}   |   Manual: ${s.manual}   |   Fail: ${s.failed}`);
    L.push(`Files jinme badlav hua: ${s.filesChanged}   |   Kit: ${r.kit.installed ? 'naya lagaya' : r.kit.alreadyPresent ? 'pehle se tha' : 'nahi lagaya'}`);
  }
  if (r.outputs && r.outputs.protectedZip) {
    L.push('', 'OUTPUT:', `  Protected site : ${r.outputs.protectedZip}`, `  Backup (asli)  : ${r.outputs.backupZip}`);
    if (r.outputs.folder) L.push(`  Folder         : ${r.outputs.folder}`);
  }
  if (r.hub) {
    const h = r.hub;
    L.push(h.status === 'connected' ? `HUB: connect ho gaya (hub mein site #${h.siteId}). Site pehli enquiry/page-view ke baad "Live" dikhegi.`
      : h.status === 'failed' ? `HUB: connect NAHI hua: ${h.error} Site protect ho gayi hai, par hub mein nahi judi. Hub se keys lekar spamguard/config.php mein 'hub' wala hissa jodo.`
      : h.status === 'dry-run' ? 'HUB: asli run mein site hub mein register hogi.' : '');
  }
  L.push('');

  if (r.changes.length) {
    L.push('KYA BADLA (sirf jodi gayi lines, kuch delete ya rewrite nahi hua):');
    for (const c of r.changes.filter((x) => x.kind === 'guard-call' || x.kind === 'script-tag')) L.push(`  + ${c.file}  (line ~${c.line})  [${c.kind === 'guard-call' ? 'guard' : 'script'}]`, `      ${c.text}`);
    if (r.siteWide && r.siteWide.enabled) {
      L.push(`  + HUB se jude hooks: ${r.siteWide.phpPages} PHP page(s) mein 1 line (central SEO + contact badlav), ${r.siteWide.jsPages} page(s) mein contact.js ka <script> tag.`);
      for (const k of r.siteWide.skipped.slice(0, 8)) L.push(`      chhoda: ${k.file} (${k.why})`);
      if (r.siteWide.skipped.length > 8) L.push(`      ... aur ${r.siteWide.skipped.length - 8} files`);
    }
    if (r.kit.installed) L.push('  + spamguard/  (kit ka folder + config.php, naya)');
    L.push('');
  }

  const rest = r.forms.filter((f) => f.outcome !== 'skipped');
  if (rest.length) {
    L.push('FORMS:');
    rest.forEach((f, i) => {
      L.push(` ${i + 1}. ${f.file}:${f.line || '?'}  [${KIND[f.kind] || f.kind}]  "${f.label}"  ->  ${OUTCOME[f.outcome]}`);
      if (f.handler) L.push(`    handler: ${f.handler}${f.submitMode === 'ajax' ? '  (AJAX)' : ''}`);
      for (const e of f.errors) L.push(`    ! ${ERR[e.code] || e.code}`);
      if (['manual', 'needs-review'].includes(f.outcome)) {
        for (const reason of f.reasons) {
          const fn = REASON[reason.code];
          if (fn && reason.level === 'warn') L.push(`    - ${fn(reason)}`);
        }
        if (f.outcome === 'needs-review') L.push('    (Ye form tab patch hoga jab --include-review use karoge, ya haath se.)');
        const how = manualHowTo(f);
        if (how && f.outcome !== 'manual') L.push(`    ${how}`);
      }
    });
    L.push('');
  }
  if (r.verification.rolledBack.length) {
    L.push('WAPAS ORIGINAL KIYE GAYE (PHP syntax error aaya):');
    for (const x of r.verification.rolledBack) L.push(`  ${x.file}: ${x.why}`);
    L.push('');
  }
  if (r.changes.length) {
    L.push('JAANCH:', `  Badlav ke baad site dobara scan hui: ${r.verification.rescan.formsProtectedAfter} form(s) "protected" dikh rahe hain.`, `  PHP syntax check: ${r.verification.phpLint === 'ran' ? 'har badli hui PHP file par chala, sab theek' : r.verification.phpLint}`);
    L.push('', 'AB AAPKO KYA KARNA HAI:');
    WAHAN.forEach((t, i) => L.push(`  ${i + 1}. ${t}`));
    L.push('', 'DHYAN: SpamGuard ko PHP 7.1 ya usse naya chahiye. Purane server par selftest hi sabse pehle batayega.');
    if (r.login) L.push('Admin password aur selftest link: PRIVATE-login.txt mein (isse kisi ko mat bhejo).');
  }
  L.push('');
  return L.join('\n');
}

function renderLoginText(r, siteHost) {
  if (!r.login) return null;
  const h = siteHost || 'https://<aapki-site>';
  return [
    `SpamGuard login: ${r.site.name}`,
    'PRIVATE - ye file kisi ko forward mat karo.',
    '',
    `Admin page : ${h}${r.login.adminPath}`,
    `Password   : ${r.login.password}${r.login.passwordWasGenerated ? '   (apne aap banaya gaya)' : ''}`,
    `Selftest   : ${h}${r.login.selftestPath}`,
    '',
    'Selftest ke baad server se selftest.php delete kar do.',
    '',
  ].join('\n');
}

function renderProtectBulk(b) {
  const L = [];
  const t = b.totals;
  L.push('=== BULK PROTECT ===');
  L.push(`Sites: ${t.sites}  |  Protected: ${t.protected}  |  Partial: ${t.partial}  |  Kuch nahi badla: ${t.untouched}  |  Pehle se: ${t.already}  |  Fail: ${t.failed}`);
  L.push(`Forms protected: ${t.formsProtected}  |  Haath se baaki: ${t.formsOpen}`);
  L.push('');
  for (const r of b.rows) L.push(`${r.name.padEnd(36)} ${String(r.status).padEnd(18)} protected ${r.protectedForms}  baaki ${r.openForms}` + (r.error ? `  ERROR: ${r.error}` : ''));
  L.push('');
  return L.join('\n');
}

module.exports = { renderProtectText, renderLoginText, renderProtectBulk, STATUS_LINE, OUTCOME, ERR, WAHAN };
