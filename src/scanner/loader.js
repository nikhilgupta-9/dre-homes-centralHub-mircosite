'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const AdmZip = require('adm-zip');
const { SKIP_DIRS, LIMITS } = require('./util');

/**
 * Safely unpack a zip. Never trusts entry names: blocks ../ traversal, absolute paths, symlinks,
 * oversized files and zip bombs. Skips Mac junk (__MACOSX, ._files, .DS_Store).
 */
function extractZip(zipPath, destDir, warnings) {
  let zip;
  try {
    zip = new AdmZip(zipPath);
  } catch (e) {
    throw new Error('ZIP file kharab hai ya khul nahi raha: ' + e.message);
  }
  const entries = zip.getEntries();
  if (entries.length > LIMITS.maxZipEntries) throw new Error('ZIP mein bahut zyada files hain (' + entries.length + ')');
  let total = 0;
  let extracted = 0;
  for (const e of entries) {
    if (e.isDirectory) continue;
    const name = e.entryName.replace(/\\/g, '/');
    if (/^__MACOSX\//.test(name) || /(^|\/)\.DS_Store$/.test(name) || /(^|\/)\._[^/]*$/.test(name)) continue;
    if (name.startsWith('/') || /^[A-Za-z]:/.test(name) || name.split('/').includes('..')) {
      warnings.push({ code: 'zip-unsafe-path', file: name });
      continue;
    }
    const mode = typeof e.attr === 'number' ? (e.attr >>> 16) & 0o170000 : 0;
    if (mode === 0o120000) {
      warnings.push({ code: 'zip-symlink-skipped', file: name });
      continue;
    }
    const declared = e.header && e.header.size ? e.header.size : 0;
    if (declared > LIMITS.maxZipFileBytes) {
      warnings.push({ code: 'zip-file-too-large', file: name });
      continue;
    }
    total += declared;
    if (total > LIMITS.maxZipTotalBytes) throw new Error('ZIP kholne par bahut bada ho jata hai (zip bomb jaisa), roka gaya');
    const target = path.resolve(destDir, name);
    if (!target.startsWith(destDir + path.sep)) {
      warnings.push({ code: 'zip-unsafe-path', file: name });
      continue;
    }
    let data;
    try {
      data = e.getData();
    } catch (err) {
      warnings.push({ code: 'zip-entry-unreadable', file: name });
      continue;
    }
    if (data.length > LIMITS.maxZipFileBytes) {
      warnings.push({ code: 'zip-file-too-large', file: name });
      continue;
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, data);
    extracted++;
  }
  return extracted;
}

/** Shallowest folder that holds an index page (zips often wrap the site in an extra folder). */
function findSiteRoot(dir) {
  const queue = [[dir, 0]];
  while (queue.length) {
    const [d, depth] = queue.shift();
    let ents;
    try {
      ents = fs.readdirSync(d, { withFileTypes: true });
    } catch (e) {
      continue;
    }
    if (ents.some((e) => e.isFile() && /^index\.(html?|php)$/i.test(e.name))) return d;
    if (depth < 3) {
      for (const e of ents) {
        if (e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) queue.push([path.join(d, e.name), depth + 1]);
      }
    }
  }
  return dir;
}

/**
 * Turn a user-supplied path (folder or .zip) into a folder we can read.
 * Returns { root, name, source, warnings, cleanup }.
 */
function prepareInput(input) {
  const warnings = [];
  const abs = path.resolve(input);
  let st;
  try {
    st = fs.statSync(abs);
  } catch (e) {
    throw new Error('Path nahi mila: ' + input);
  }
  if (st.isDirectory()) {
    const real = fs.realpathSync(abs);
    const root = findSiteRoot(real);
    return {
      root,
      name: path.basename(real),
      source: 'folder',
      rootRel: path.relative(real, root).split(path.sep).join('/'),
      warnings,
      cleanup() {},
    };
  }
  if (st.isFile() && /\.zip$/i.test(abs)) {
    const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sg-scan-')));
    try {
      const n = extractZip(abs, tmp, warnings);
      if (n === 0) throw new Error('ZIP khaali hai ya usme koi file nahi mili');
    } catch (e) {
      fs.rmSync(tmp, { recursive: true, force: true });
      throw e;
    }
    const root = findSiteRoot(tmp);
    return {
      root,
      name: path.basename(abs).replace(/\.zip$/i, ''),
      source: 'zip',
      rootRel: path.relative(tmp, root).split(path.sep).join('/'),
      warnings,
      cleanup() {
        fs.rmSync(tmp, { recursive: true, force: true });
      },
    };
  }
  throw new Error('Sirf folder ya .zip file chalegi: ' + input);
}

module.exports = { prepareInput, extractZip, findSiteRoot };
