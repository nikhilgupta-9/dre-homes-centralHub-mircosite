'use strict';
const fs = require('fs');
const zlib = require('zlib');
const readline = require('readline');

const ENQUIRY_COLS = /^(name|full_?name|first_?name|email|e_?mail|phone|mobile|contact|contact_?no|whatsapp|message|msg|comments?|enquiry|inquiry|query|requirement|subject|city|service)$/i;
const ENQUIRY_TABLE = /enquir|inquir|contact|lead|quer(y|ies)|message|submission|request|feedback|booking|appointment|callback|form/i;

/**
 * Read table structure out of a MySQL dump WITHOUT keeping any row data.
 * Streams line by line, so a 500 MB dump costs almost no memory. Handles .sql and .sql.gz.
 */
async function parseDump(absPath) {
  const tables = new Map();
  let input = fs.createReadStream(absPath);
  if (/\.gz$/i.test(absPath)) input = input.pipe(zlib.createGunzip());
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  let cur = null;
  let lines = 0;
  try {
    for await (const line of rl) {
      lines++;
      if (cur) {
        if (/^\)[^;]*;?\s*$/.test(line)) {
          cur = null;
          continue;
        }
        const col = line.match(/^\s*[`"]([^`"]+)[`"]\s+(\w+(?:\([^)]*\))?)/);
        if (col) cur.columns.push({ name: col[1], type: col[2].toLowerCase() });
        else if (/^\s*PRIMARY\s+KEY/i.test(line)) cur.hasPrimaryKey = true;
        continue;
      }
      const ct = line.match(/^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?([\w$]+)[`"]?\s*\(/i);
      if (ct) {
        cur = { name: ct[1], columns: [], inserts: 0, hasPrimaryKey: false };
        tables.set(ct[1], cur);
        // one-line CREATE TABLE (...); — rare, give up on columns but keep the table
        if (/\)\s*(ENGINE|;)/i.test(line)) cur = null;
        continue;
      }
      const ins = line.match(/^\s*INSERT\s+(?:IGNORE\s+)?INTO\s+[`"]?([\w$]+)[`"]?/i);
      if (ins && tables.has(ins[1])) tables.get(ins[1]).inserts++;
    }
  } finally {
    rl.close();
    input.destroy();
  }
  const out = [];
  for (const t of tables.values()) {
    const names = t.columns.map((c) => c.name);
    const colHits = names.filter((n) => ENQUIRY_COLS.test(n)).length;
    const score = colHits + (ENQUIRY_TABLE.test(t.name) ? 2 : 0) + (names.some((n) => /mail/i.test(n)) ? 1 : 0);
    out.push({
      name: t.name,
      columns: t.columns,
      insertStatements: t.inserts,
      enquiryScore: score,
      looksLikeEnquiries: score >= 4 && names.some((n) => /mail|phone|mobile/i.test(n)),
      hasStatusColumn: names.some((n) => /^(status|is_read|read|state)$/i.test(n)),
      hasDateColumn: names.some((n) => /(created|date|time|added|submitted)/i.test(n)),
    });
  }
  return { tables: out, lines };
}

module.exports = { parseDump };
