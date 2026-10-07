'use strict';
const fs = require('fs');
const path = require('path');

/** Folders never worth reading (Mac zips carry __MACOSX junk). */
const SKIP_DIRS = new Set(['node_modules', '.git', '.svn', '.hg', '__MACOSX', '.idea', '.vscode']);
const SKIP_FILE = /^(\.DS_Store|Thumbs\.db|\._.*)$/;

const LIMITS = {
  maxFiles: 100000,
  maxTextBytes: 2 * 1024 * 1024,        // largest html/php/js we parse
  maxZipEntries: 200000,
  maxZipTotalBytes: 2 * 1024 * 1024 * 1024,
  maxZipFileBytes: 400 * 1024 * 1024,
};

/** List every file under root (no symlinks). Paths use forward slashes. */
function walk(root, { skipDirNames = SKIP_DIRS, maxFiles = LIMITS.maxFiles } = {}) {
  const out = [];
  const stack = [''];
  let truncated = false;
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
      const childRel = rel ? rel + '/' + e.name : e.name;
      if (e.isDirectory()) {
        if (skipDirNames.has(e.name)) continue;
        stack.push(childRel);
      } else if (e.isFile()) {
        if (SKIP_FILE.test(e.name)) continue;
        if (out.length >= maxFiles) {
          truncated = true;
          continue;
        }
        let size = 0;
        try {
          size = fs.statSync(path.join(root, childRel)).size;
        } catch (err) {
          continue;
        }
        out.push({ rel: childRel, size, ext: path.extname(e.name).toLowerCase(), base: e.name });
      }
    }
  }
  out.sort((a, b) => (a.rel < b.rel ? -1 : 1));
  out.truncated = truncated;
  return out;
}

/** Read a text file, or null when it is binary / too large / unreadable. */
function readText(abs, maxBytes = LIMITS.maxTextBytes) {
  let buf;
  try {
    const st = fs.statSync(abs);
    if (st.size > maxBytes) return null;
    buf = fs.readFileSync(abs);
  } catch (e) {
    return null;
  }
  if (buf.includes(0)) return null;
  let s = buf.toString('utf8');
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  return s;
}

/** 1-based line number of a character index. */
function lineAt(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function countNewlines(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 10) n++;
  return n;
}

/** Posix-style join/normalize that never leaves the site root. Returns null if it escapes. */
function resolveRel(fromRel, target) {
  let t = target.replace(/\\/g, '/');
  let base;
  if (t.startsWith('/')) {
    base = [];
    t = t.slice(1);
  } else {
    const dir = fromRel.includes('/') ? fromRel.slice(0, fromRel.lastIndexOf('/')) : '';
    base = dir ? dir.split('/') : [];
  }
  for (const part of t.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (!base.length) return null;
      base.pop();
    } else base.push(part);
  }
  return base.join('/');
}

module.exports = { SKIP_DIRS, SKIP_FILE, LIMITS, walk, readText, lineAt, countNewlines, resolveRel };
