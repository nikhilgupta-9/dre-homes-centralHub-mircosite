'use strict';
/**
 * Pure text edits for the injector. Files are handled as latin1 strings (byte-for-byte), so
 * non-UTF8 pages survive untouched. Every edit is an INSERTION: the original text is never rewritten,
 * which lets us prove "remove the inserted text => original file" for every file we touch.
 */

const GUARD_BEGIN = '/* SpamGuard:begin */';
const GUARD_END = '/* SpamGuard:end */';
const SCRIPT_MARK = '<!-- SpamGuard -->';

const detectEol = (t) => (t.includes('\r\n') ? '\r\n' : '\n');

/** PHP literal on one line (for the per-handler success override). */
function phpInline(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return Number.isFinite(v) ? String(v) : 'null';
  if (typeof v === 'string') return "'" + v.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/[\r\n]+/g, ' ') + "'";
  if (Array.isArray(v)) return '[' + v.map(phpInline).join(', ') + ']';
  return '[' + Object.entries(v).map(([k, x]) => phpInline(String(k)) + ' => ' + phpInline(x)).join(', ') + ']';
}

/** The text of the guard, ready to be placed after `<?php`. relDir = path from the handler's folder to the site root. */
function guardCode(relToRoot, override, namespaced) {
  const p = (relToRoot ? relToRoot.replace(/\/+$/, '') + '/' : '') + 'spamguard/spamguard.php';
  const file = `__DIR__ . '/${p}'`;
  const arg = override && Object.keys(override).length ? phpInline(override) : '';
  const cls = namespaced ? '\\SpamGuard' : 'SpamGuard';
  // is_file(): if the kit folder is ever missing the site keeps working (fail-open), it never crashes.
  return `${GUARD_BEGIN} if (is_file(${file})) { require_once ${file}; ${cls}::guard(${arg}); } ${GUARD_END}`;
}

/** Where PHP starts and which leading declare/namespace statements must stay first. */
function findGuardSpot(text) {
  const bom = text.startsWith('\xEF\xBB\xBF') ? 3 : 0;
  const firstTag = text.slice(bom).search(/<\?/);
  if (firstTag === -1) return { error: 'no-php' };
  const open = bom + firstTag;
  if (text.slice(bom, open).trim() !== '') return { error: 'php-not-at-top' };
  const m = /^<\?php(?=[\s]|$)/i.exec(text.slice(open));
  if (!m) return { error: 'short-open-tag' };
  let pos = open + m[0].length;
  let namespaced = false;
  let spot = pos;
  let after = false;
  for (let guard = 0; guard < 50; guard++) {
    const rest = text.slice(pos);
    const ws = /^(?:\s+|\/\/[^\r\n]*|#(?!\[)[^\r\n]*|\/\*[\s\S]*?\*\/)+/.exec(rest);
    if (ws) pos += ws[0].length;
    const r2 = text.slice(pos);
    let d;
    if ((d = /^declare\s*\([^)]*\)\s*;/i.exec(r2))) {
      pos += d[0].length;
      spot = pos;
      after = true;
      continue;
    }
    if ((d = /^namespace\s+[\w\\]+\s*;/i.exec(r2))) {
      pos += d[0].length;
      spot = pos;
      after = true;
      namespaced = true;
      continue;
    }
    if (/^namespace\b/i.test(r2)) return { error: 'bracketed-namespace' };
    break;
  }
  return { offset: spot, afterDirective: after, namespaced };
}

/** Build the guard insertion. Returns {offset, insert} or {error}. */
function planGuardEdit(text, relToRoot, override) {
  if (/SpamGuard\s*::\s*guard\s*\(/.test(text)) return { error: 'already' };
  const spot = findGuardSpot(text);
  if (spot.error) return spot;
  const eol = detectEol(text);
  const code = guardCode(relToRoot, override, spot.namespaced);
  const restOfLine = /^[^\r\n]*/.exec(text.slice(spot.offset))[0];
  const insert = restOfLine.trim() === '' ? eol + code : ' ' + code;
  return { offset: spot.offset, insert };
}

/** Is `offset` inside a <?php ... ?> region? (naive tag walk, good enough to refuse unsafe spots) */
function inPhpAt(text, offset) {
  const re = /<\?(?:php\b|=)?|\?>/gi;
  let inPhp = false;
  let m;
  while ((m = re.exec(text)) && m.index < offset) {
    if (m[0] === '?>') inPhp = false;
    else inPhp = true;
  }
  return inPhp;
}

/** Build the <script> insertion: after the form's last line (or before </body> as a fallback). */
function planScriptEdit(text, afterLine, tagSrc) {
  if (/spamguard\.js/i.test(text)) return { error: 'already' };
  const eol = detectEol(text);
  const tag = `${SCRIPT_MARK}<script src="${tagSrc}" defer></script>`;
  const lineEnd = (n) => {
    let idx = -1;
    for (let i = 0; i < n; i++) {
      idx = text.indexOf('\n', idx + 1);
      if (idx === -1) return text.length;
    }
    return idx + 1;
  };
  const place = (offset) => {
    const needsEol = offset > 0 && text[offset - 1] !== '\n';
    return { offset, insert: (needsEol ? eol : '') + tag + eol };
  };
  if (afterLine && afterLine > 0) {
    const off = lineEnd(afterLine);
    if (!inPhpAt(text, off)) return place(off);
  }
  const body = text.toLowerCase().lastIndexOf('</body>');
  if (body !== -1 && !inPhpAt(text, body)) return place(body);
  return { error: 'script-position-unsafe' };
}

/** Apply insertions (never overlapping) from the end of the file to the start. */
function applyInsertions(text, edits) {
  const sorted = edits.slice().sort((a, b) => b.offset - a.offset);
  let out = text;
  for (const e of sorted) out = out.slice(0, e.offset) + e.insert + out.slice(e.offset);
  // Safety proof: taking the inserted text back out gives exactly the original.
  const asc = edits.slice().sort((a, b) => a.offset - b.offset);
  const pieces = [];
  let cursor = 0;
  let shift = 0;
  for (const e of asc) {
    const at = e.offset + shift;
    pieces.push(out.slice(cursor, at));
    cursor = at + e.insert.length;
    shift += e.insert.length;
  }
  pieces.push(out.slice(cursor));
  const back = pieces.join('');
  if (back !== text) throw new Error('internal: edit verification failed');
  return out;
}

/** 1-based line number of an offset. */
const lineOfOffset = (text, offset) => text.slice(0, offset).split('\n').length;

module.exports = { planGuardEdit, planScriptEdit, applyInsertions, phpInline, guardCode, lineOfOffset, detectEol, GUARD_BEGIN, GUARD_END, SCRIPT_MARK };
