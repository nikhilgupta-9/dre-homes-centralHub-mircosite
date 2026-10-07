'use strict';

const BAD_EMAIL_TLD = /\.(png|jpe?g|gif|svg|webp|css|js|ico|woff2?|ttf)$/i;
const EMAIL_RE = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}/g;
// Indian mobiles (with/without +91), landlines with STD code, and generic international numbers
const PHONE_RE = /(?:\+?91[\s\-]?)?(?:[6-9]\d{4}[\s\-]?\d{5}|0\d{2,4}[\s\-]?\d{6,8})|\+\d{1,3}[\s\-]?\d[\d\s\-]{7,13}\d/g;

function phoneKey(s) {
  let d = s.replace(/\D/g, '');
  if (d.length === 12 && d.startsWith('91')) d = d.slice(2);
  if (d.length === 11 && d.startsWith('0')) d = d.slice(1); // STD / trunk prefix 0 (0141-2345678 == +91 141 2345678)
  return d;
}

/**
 * Find phone numbers and e-mail addresses written in pages, with file/line.
 * Needed so the hub can later change "the phone number" in every place at once.
 * @param {string} htmlMasked PHP-masked html (same line numbers as the file)
 */
function extractContacts(rel, htmlMasked, acc) {
  const text = htmlMasked
    .replace(/<script\b[\s\S]*?<\/script>/gi, (s) => s.replace(/[^\n]/g, ''))
    .replace(/<style\b[\s\S]*?<\/style>/gi, (s) => s.replace(/[^\n]/g, ''))
    .replace(/<!--[\s\S]*?-->/g, (s) => s.replace(/[^\n]/g, ''));
  const lines = text.split('\n');
  const add = (map, key, display, line, via) => {
    let it = map.get(key);
    if (!it) {
      it = { value: display, count: 0, locations: [] };
      map.set(key, it);
    }
    it.count++;
    if (it.locations.length < 25) it.locations.push({ file: rel, line, via });
  };
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw || (raw.indexOf('@') === -1 && !/\d{6}/.test(raw))) continue;
    // links first (tel: / mailto:) so we know HOW the value is written
    for (const m of raw.matchAll(/href\s*=\s*["']tel:([^"']+)["']/gi)) {
      const k = phoneKey(decodeURIComponent(m[1]));
      if (k.length >= 7) add(acc.phones, k, decodeURIComponent(m[1]).trim(), i + 1, 'tel-link');
    }
    for (const m of raw.matchAll(/href\s*=\s*["']mailto:([^"'?]+)/gi)) {
      const e = decodeURIComponent(m[1]).trim().toLowerCase();
      if (/@/.test(e) && !BAD_EMAIL_TLD.test(e)) add(acc.emails, e, e, i + 1, 'mailto-link');
    }
    const plain = raw.replace(/<[^>]*>/g, ' ').replace(/&nbsp;/gi, ' ');
    for (const m of plain.matchAll(EMAIL_RE)) {
      const e = m[0].toLowerCase();
      if (!BAD_EMAIL_TLD.test(e)) add(acc.emails, e, e, i + 1, 'text');
    }
    for (const m of plain.matchAll(PHONE_RE)) {
      const k = phoneKey(m[0]);
      if (k.length >= 8 && k.length <= 13 && !/^(\d)\1+$/.test(k)) add(acc.phones, k, m[0].trim(), i + 1, 'text');
    }
  }
}

function newContactAcc() {
  return { phones: new Map(), emails: new Map() };
}

function finishContacts(acc) {
  const toList = (m) => Array.from(m.values()).sort((a, b) => b.count - a.count);
  return { phones: toList(acc.phones), emails: toList(acc.emails) };
}

module.exports = { extractContacts, newContactAcc, finishContacts };
