'use strict';
const { stripPhpComments } = require('./phpmask');
const { lineAt } = require('./util');

/** Parse the literal key => value pairs of a simple PHP array expression. */
function parsePairs(body) {
  const pairs = {};
  const re = /['"]([\w\-]+)['"]\s*=>\s*(true|false|null|-?\d+(?:\.\d+)?|'((?:[^'\\]|\\.)*)'|"((?:[^"\\$]|\\.)*)")/gi;
  let m;
  while ((m = re.exec(body))) {
    const raw = m[2];
    let v;
    if (/^true$/i.test(raw)) v = true;
    else if (/^false$/i.test(raw)) v = false;
    else if (/^null$/i.test(raw)) v = null;
    else if (/^-?\d/.test(raw)) v = Number(raw);
    else v = (m[3] !== undefined ? m[3] : m[4]).replace(/\\(['"\\])/g, '$1');
    pairs[m[1]] = v;
  }
  return pairs;
}

/**
 * Static analysis of one PHP file (never executed). `code` is the PHP-only view of the file.
 * Passwords and other secrets are deliberately never captured.
 */
function analyzePhp(code) {
  const c = stripPhpComments(code);
  const a = {
    readsPost: false,
    postFields: [],
    sendsMail: false,
    mailVia: [],
    mailRecipients: [],
    usesDb: false,
    dbEngines: [],
    dbName: '',
    definesDbConnection: false,
    insertTables: [],
    writesFile: false,
    acceptsUpload: false,
    redirects: [],
    jsonResponses: [],
    textResponses: [],
    includes: [],
    dynamicIncludes: 0,
    verifiesCaptcha: [],
    guardCalled: false,
    hasDeclareStrict: false,
    hasNamespace: false,
    firstPhpLine: null,
  };

  const open = code.search(/<\?(?:php\b|=)?/i);
  a.firstPhpLine = open === -1 ? null : lineAt(code, open);

  // --- input
  const fields = new Set();
  for (const m of c.matchAll(/\$_(?:POST|REQUEST)\s*\[\s*['"]([^'"]+)['"]\s*\]/g)) fields.add(m[1]);
  for (const m of c.matchAll(/filter_input\s*\(\s*INPUT_POST\s*,\s*['"]([^'"]+)['"]/g)) fields.add(m[1]);
  a.postFields = Array.from(fields);
  a.readsPost =
    fields.size > 0 ||
    /\$_(?:POST|REQUEST)\b/.test(c) ||
    /\$_SERVER\s*\[\s*['"]REQUEST_METHOD['"]\s*\]\s*={2,3}\s*['"]POST['"]/i.test(c) ||
    /file_get_contents\s*\(\s*['"]php:\/\/input['"]/.test(c);
  a.acceptsUpload = /\$_FILES\b/.test(c);

  // --- mail
  if (/(?<![\w>:$])mail\s*\(/.test(c)) {
    a.sendsMail = true;
    a.mailVia.push('mail()');
  }
  if (/new\s+\\?PHPMailer\b|PHPMailer\\PHPMailer/i.test(c)) {
    a.sendsMail = true;
    a.mailVia.push('PHPMailer');
  }
  if (/Swift_Mailer|Symfony\\Component\\Mailer/.test(c)) {
    a.sendsMail = true;
    a.mailVia.push('SwiftMailer/Symfony');
  }
  if (/\bwp_mail\s*\(|mb_send_mail\s*\(/.test(c)) {
    a.sendsMail = true;
    a.mailVia.push('wp_mail');
  }
  if (/api\.sendgrid\.com|api\.mailgun\.net|api\.postmarkapp\.com|api\.brevo\.com|api\.sendinblue\.com/i.test(c)) {
    a.sendsMail = true;
    a.mailVia.push('mail API');
  }
  const rec = new Set();
  for (const m of c.matchAll(/(?<![\w>:$])mail\s*\(\s*['"]([^'"]+@[^'"]+)['"]/g)) rec.add(m[1].toLowerCase());
  for (const m of c.matchAll(/\$(?:to|recipient|recipients|email_to|admin_email|mailto|send_to|to_email|receiver)\s*=\s*['"]([^'"$]+@[^'"$]+)['"]/gi)) rec.add(m[1].toLowerCase());
  for (const m of c.matchAll(/addAddress\s*\(\s*['"]([^'"]+@[^'"]+)['"]/g)) rec.add(m[1].toLowerCase());
  a.mailRecipients = Array.from(rec).filter((e) => !/\$/.test(e));

  // --- database
  const eng = new Set();
  if (/mysqli_connect\s*\(|new\s+\\?mysqli\s*\(|mysqli_query\s*\(|mysqli_prepare\s*\(|->real_escape_string/.test(c)) eng.add('mysqli');
  if (/\bmysql_(?:connect|query|select_db)\s*\(/.test(c)) eng.add('mysql (old)');
  if (/new\s+\\?PDO\s*\(\s*['"]mysql:/i.test(c)) eng.add('PDO-mysql');
  else if (/new\s+\\?PDO\s*\(\s*['"]sqlite:/i.test(c)) eng.add('PDO-sqlite');
  else if (/new\s+\\?PDO\s*\(\s*['"]pgsql:/i.test(c)) eng.add('PDO-pgsql');
  else if (/new\s+\\?PDO\s*\(/.test(c)) eng.add('PDO');
  if (/\$wpdb\b/.test(c)) eng.add('wpdb');
  a.dbEngines = Array.from(eng);
  a.usesDb = eng.size > 0 || /\bINSERT\s+INTO\b/i.test(c);
  a.definesDbConnection =
    /mysqli_connect\s*\(|new\s+\\?mysqli\s*\(|mysql_connect\s*\(|new\s+\\?PDO\s*\(\s*['"](?:mysql|pgsql):/i.test(c) ||
    /define\s*\(\s*['"]DB_(?:HOST|NAME|USER)['"]/.test(c);
  // database NAME only (never user/password)
  const dn = c.match(/define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]+)['"]/) || c.match(/(?:mysqli_connect|new\s+\\?mysqli)\s*\(\s*(?:[^,()]+,){3}\s*['"]([^'"]+)['"]/) || c.match(/dbname=([\w\-]+)/i);
  if (dn) a.dbName = dn[1];
  const tables = new Map();
  for (const m of c.matchAll(/INSERT\s+(?:IGNORE\s+)?INTO\s+[`"']?(\w+)[`"']?\s*(?:\(([^)]*)\))?/gi)) {
    const cols = m[2] ? m[2].split(',').map((x) => x.replace(/[`"'\s]/g, '')).filter(Boolean) : [];
    const prev = tables.get(m[1]);
    if (!prev || cols.length > prev.columns.length) tables.set(m[1], { table: m[1], columns: cols });
  }
  a.insertTables = Array.from(tables.values());

  // --- other effects
  a.writesFile = /\b(?:file_put_contents|fputcsv|fwrite)\s*\(/.test(c) || /\bfopen\s*\([^)]*['"][aw]\+?b?['"]/.test(c);
  for (const m of c.matchAll(/header\s*\(\s*['"]Location:\s*([^'"]*)['"]/gi)) a.redirects.push(m[1].trim());

  // --- what the handler answers (matters for AJAX forms)
  for (const m of c.matchAll(/json_encode\s*\(\s*(?:array\s*\(|\[)([\s\S]{0,500}?)(?:\)|\])\s*\)/g)) {
    const pairs = parsePairs(m[1]);
    if (Object.keys(pairs).length) a.jsonResponses.push({ line: lineAt(c, m.index), pairs });
  }
  for (const m of c.matchAll(/\b(?:echo|print|die|exit)\s*\(?\s*(['"])([^'"$\\]{1,40})\1\s*\)?\s*;/g)) {
    a.textResponses.push({ line: lineAt(c, m.index), text: m[2] });
  }

  // --- includes (static only)
  for (const m of c.matchAll(/\b(?:include|require)(?:_once)?\s*\(?\s*((?:__DIR__|dirname\s*\(\s*__FILE__\s*\)|\$_SERVER\s*\[\s*['"]DOCUMENT_ROOT['"]\s*\])\s*\.\s*)?(['"])([^'"]+\.(?:php|inc|phtml|html?))\2/gi)) {
    a.includes.push({ path: m[3], base: m[1] ? (/DOCUMENT_ROOT/.test(m[1]) ? 'root' : 'dir') : 'plain' });
  }
  for (const m of c.matchAll(/\b(?:include|require)(?:_once)?\s*\(?\s*(\$|[A-Za-z_]+\s*\()/g)) {
    if (!/^\s*(?:__DIR__|dirname)/.test(m[1])) a.dynamicIncludes++;
  }

  // --- existing protections
  if (/recaptcha\/api\/siteverify|google\.com\/recaptcha/i.test(c)) a.verifiesCaptcha.push('recaptcha');
  if (/hcaptcha\.com\/siteverify/i.test(c)) a.verifiesCaptcha.push('hcaptcha');
  if (/turnstile\/v0\/siteverify/i.test(c)) a.verifiesCaptcha.push('turnstile');
  a.guardCalled = /SpamGuard\s*::\s*guard\s*\(/.test(c);

  // --- facts the injector needs
  a.hasDeclareStrict = /^\s*declare\s*\(\s*strict_types\s*=\s*1\s*\)/m.test(c);
  a.hasNamespace = /^\s*namespace\s+[\w\\]+\s*[;{]/m.test(c);
  return a;
}

/** Pick the most likely "success" answer out of a handler's json_encode calls. */
function guessSuccessJson(an) {
  const score = (p) => {
    let s = 0;
    for (const [k, v] of Object.entries(p.pairs)) {
      if (/^(status|success|result|ok|code|error)$/i.test(k)) {
        if (v === true || /^(success|ok|sent|true|1|200)$/i.test(String(v))) s += 3;
        if (v === false || /^(error|fail|failed|false|0)$/i.test(String(v))) s -= 3;
        if (/^error$/i.test(k) && (v === false || v === 0 || v === '')) s += 4;
      }
      if (/thank|sent|success|received/i.test(String(v))) s += 1;
      if (/error|fail|invalid|please|required|wrong/i.test(String(v))) s -= 1;
    }
    return s;
  };
  let best = null;
  for (const p of an.jsonResponses) {
    const s = score(p);
    if (s > 0 && (!best || s > best.s)) best = { s, pairs: p.pairs, line: p.line };
  }
  return best ? { json: best.pairs, line: best.line } : null;
}

module.exports = { analyzePhp, guessSuccessJson, parsePairs };
