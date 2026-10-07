'use strict';
/**
 * Helper for pytests/test_scanner_parity.py: runs the ORIGINAL Node scanner and dumps what it produces,
 * so the Python port can be compared with it.
 *
 *   node pytests/dump_scan.js build <outDir>            build fixtures + dump reports
 *   node pytests/dump_scan.js html <cases.json> <out>   dump parseHtml() for [[rel, html], ...]
 *   node pytests/dump_scan.js scandirs <root> <out>     scan every sub-folder of root, dump reports + text
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { buildFixtures, makeZip, zipFolder } = require('../test/helpers');
const { scanSite } = require('../src/scanner');
const { scanMany, writeBulkOutputs } = require('../src/scanner/bulk');
const { renderText, renderBulkText } = require('../src/scanner/report');
const { parseHtml } = require('../src/scanner/forms');
const { generateConfig } = require('../src/config');

const norm = (r) => {
  const c = JSON.parse(JSON.stringify(r));
  if (c.scanner) {
    delete c.scanner.scannedAt;
    delete c.scanner.durationMs;
  }
  return c;
};
const put = (f, v) => {
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, typeof v === 'string' ? v : JSON.stringify(v, null, 1));
};

async function build(out) {
  const sites = path.join(out, 'sites');
  const zips = path.join(out, 'zips');
  const exp = path.join(out, 'expected');
  fs.mkdirSync(zips, { recursive: true });
  const dirs = buildFixtures(sites);

  // extra regression site (id-only inputs + long $.ajax options)
  const d = path.join(sites, 'idajax');
  fs.mkdirSync(path.join(d, 'js'), { recursive: true });
  fs.mkdirSync(path.join(d, 'mail'), { recursive: true });
  fs.writeFileSync(path.join(d, 'index.html'), '<!DOCTYPE html><html><head><title>T</title></head><body><form id="contactForm" novalidate><input id="name" type="text"><input id="email" type="email"><textarea id="message"></textarea><button type="submit">Send</button></form><script src="js/contact_me.js"></script></body></html>');
  fs.writeFileSync(path.join(d, 'js', 'contact_me.js'), '$(function(){ $("input,textarea").jqBootstrapValidation({ submitSuccess: function($f, e){ e.preventDefault(); var name=$("input#name").val(); var email=$("input#email").val(); var message=$("textarea#message").val();\n$.ajax({ url: "././mail/contact_me.php", type: "POST", data: { name: name, email: email, message: message }, cache: false, success: function(){ $("#success").html("<div class=\'alert\'>"); $("#success > .alert").append("<strong>Your message has been sent.</strong>"); $("#contactForm").trigger("reset"); }, error: function(){ $("#success").html("<div>error</div>"); } }); } }); });');
  fs.writeFileSync(path.join(d, 'mail', 'contact_me.php'), '<?php\nif(empty($_POST[\'name\'])||empty($_POST[\'email\'])){ echo "No arguments Provided!"; return false; }\n$name = strip_tags($_POST[\'name\']);\nmail("me@x.in","Contact",$name);\nreturn true;\n');
  dirs.idajax = d;

  const names = Object.keys(dirs);
  for (const n of names) {
    const rf = await scanSite(dirs[n]);
    put(path.join(exp, n + '.folder.json'), norm(rf));
    put(path.join(exp, n + '.folder.txt'), renderText(rf));
    zipFolder(dirs[n], path.join(zips, n + '.zip'));
    const rz = await scanSite(path.join(zips, n + '.zip'));
    put(path.join(exp, n + '.zip.json'), norm(rz));
    put(path.join(exp, n + '.zip.txt'), renderText(rz));
    // zip without a wrapper folder
    zipFolder(dirs[n], path.join(zips, n + '.flat.zip'), { wrapper: false });
    const rzf = await scanSite(path.join(zips, n + '.flat.zip'));
    put(path.join(exp, n + '.flat.json'), norm(rzf));
  }

  // hostile / odd inputs
  const odd = path.join(out, 'odd');
  fs.mkdirSync(odd, { recursive: true });
  const id = 'sgevil' + process.pid + Date.now();
  fs.writeFileSync(path.join(odd, 'evil.zip'), makeZip([
    { name: `../${id}1.txt`, data: 'pwn' },
    { name: `../../${id}2.txt`, data: 'pwn' },
    { name: `sub/../../${id}3.txt`, data: 'pwn' },
    { name: `/tmp/${id}4.txt`, data: 'pwn' },
    { name: `C:\\win\\${id}5.txt`, data: 'pwn' },
    { name: 'link', data: '/etc/passwd', mode: 0o120777 },
    { name: 'a\\b\\..\\..\\..\\x.txt', data: 'pwn' },
    { name: 'dir/', data: '' },
    { name: 'caf\u00e9/index.html', data: 'x' },
    { name: 'site/index.html', data: '<html><body><h1>fine</h1><form><input name="email"><textarea name="m"></textarea></form></body></html>' },
  ]));
  fs.writeFileSync(path.join(odd, 'only-junk.zip'), makeZip([{ name: '__MACOSX/x', data: 'a' }, { name: '.DS_Store', data: 'b' }]));
  fs.writeFileSync(path.join(odd, 'x.txt'), 'hi');
  fs.writeFileSync(path.join(odd, 'garbage.zip'), 'not a zip at all');
  fs.writeFileSync(path.join(odd, 'empty.zip'), Buffer.alloc(0));
  const oddRes = {};
  for (const [k, p] of [['evil', 'evil.zip'], ['junk', 'only-junk.zip'], ['txt', 'x.txt'], ['garbage', 'garbage.zip'], ['empty', 'empty.zip'], ['missing', 'nope'], ['nodir', 'nodir']]) {
    try {
      oddRes[k] = { ok: norm(await scanSite(path.join(odd, p))) };
    } catch (e) {
      oddRes[k] = { error: e.message };
    }
  }
  put(path.join(exp, 'odd.json'), oddRes);
  put(path.join(exp, 'odd-evil.txt'), renderText(oddRes.evil.ok));

  // external SQL files (plain, gz, corrupt gz, missing)
  const sqlDir = path.join(out, 'sqlx');
  fs.mkdirSync(sqlDir, { recursive: true });
  const dump = 'CREATE TABLE `leads` (\r\n  `id` int(11) NOT NULL,\r\n  `email` varchar(100),\r\n  `phone` varchar(20),\r\n  `message` text,\r\n  `created_at` datetime,\r\n  PRIMARY KEY (`id`)\r\n) ENGINE=InnoDB;\r\nINSERT INTO `leads` VALUES (1);\r\nCREATE TABLE IF NOT EXISTS orders (\n  `id` int,\n  `total` decimal(10,2)\n);\n';
  fs.writeFileSync(path.join(sqlDir, 'plain.sql'), dump);
  fs.writeFileSync(path.join(sqlDir, 'packed.sql.gz'), zlib.gzipSync(dump));
  const gz = zlib.gzipSync(dump);
  fs.writeFileSync(path.join(sqlDir, 'cut.sql.gz'), gz.subarray(0, gz.length - 12));
  fs.writeFileSync(path.join(sqlDir, 'bad.sql.gz'), 'this is not gzip');
  const sqlFiles = ['plain.sql', 'packed.sql.gz', 'cut.sql.gz', 'bad.sql.gz', 'missing.sql'].map((x) => path.join(sqlDir, x));
  const rs = await scanSite(dirs['acme-dental'], { sqlFiles });
  put(path.join(exp, 'sqlx.json'), norm(rs));
  put(path.join(exp, 'sqlx.txt'), renderText(rs));

  // bulk
  const parent = path.join(out, 'bulk');
  fs.mkdirSync(parent);
  for (const n of ['acme-dental', 'quick-ajax', 'external-forms', 'wp-site', 'empty-site']) fs.cpSync(dirs[n], path.join(parent, n), { recursive: true });
  zipFolder(dirs['self-post'], path.join(parent, 'self-post.zip'));
  fs.writeFileSync(path.join(parent, 'broken.zip'), 'this is not a zip');
  fs.mkdirSync(path.join(parent, '=evil'));
  fs.writeFileSync(path.join(parent, '=evil', 'index.html'), '<html><body><h1>x</h1></body></html>');
  fs.mkdirSync(path.join(parent, 'Zeta Site'));
  fs.writeFileSync(path.join(parent, 'Zeta Site', 'index.html'), '<html><body><h1>zeta</h1></body></html>');
  fs.mkdirSync(path.join(parent, 'alpha_site'));
  fs.writeFileSync(path.join(parent, 'alpha_site', 'index.html'), '<html><body><h1>alpha</h1></body></html>');
  fs.mkdirSync(path.join(parent, 'Acme-Dental2'));
  fs.writeFileSync(path.join(parent, 'Acme-Dental2', 'index.html'), '<html><body><h1>acme two</h1></body></html>');
  fs.mkdirSync(path.join(parent, '.hidden'));
  fs.mkdirSync(path.join(parent, 'node_modules'));
  fs.writeFileSync(path.join(parent, 'notes.txt'), 'ignored');
  const seen = [];
  const bulk = await scanMany(parent, { onProgress: (p) => seen.push(p) });
  const outDir = path.join(out, 'bulk-js-out');
  writeBulkOutputs(bulk, outDir);
  put(path.join(exp, 'bulk.json'), {
    parent: bulk.parent, warnings: bulk.warnings, totals: bulk.totals, rows: bulk.rows, progress: seen,
    results: bulk.results.map((r) => ({ name: r.name, input: r.input, status: r.status, error: r.error, report: r.report ? norm(r.report) : null })),
  });
  put(path.join(exp, 'bulk.txt'), renderBulkText(bulk));
  const single = await scanMany(dirs['acme-dental']);
  put(path.join(exp, 'bulk-single.json'), { warnings: single.warnings, totals: single.totals, rows: single.rows });
  let berr;
  try { await scanMany(path.join(out, 'sqlx', 'nonexistent')); } catch (e) { berr = e.message; }
  let berr2;
  try { fs.mkdirSync(path.join(out, 'emptyparent')); await scanMany(path.join(out, 'emptyparent')); } catch (e) { berr2 = e.message; }
  put(path.join(exp, 'bulk-errors.json'), { missing: berr, empty: berr2 });

  // config generator: structure only (random parts differ)
  const g = generateConfig({ siteId: 'Test Site', password: 'Test#Pass123' });
  put(path.join(exp, 'config-keys.json'), { siteId: g.siteId, keys: Object.keys(g) });
  put(path.join(out, 'names.json'), names);
}

function html(casesFile, outFile) {
  const cases = JSON.parse(fs.readFileSync(casesFile, 'utf8'));
  const res = cases.map(([rel, h]) => JSON.parse(JSON.stringify(parseHtml(rel, h))));
  fs.writeFileSync(outFile, JSON.stringify(res));
}

/** Scan every sub-folder of `root` and dump {name: {report, text} | {error}} (used for mutation fuzzing). */
async function scanDirs(root, outFile) {
  const res = {};
  for (const n of fs.readdirSync(root).sort()) {
    try {
      const r = await scanSite(path.join(root, n));
      res[n] = { report: norm(r), text: renderText(r) };
    } catch (e) {
      res[n] = { error: e.message };
    }
  }
  fs.writeFileSync(outFile, JSON.stringify(res));
}

(async () => {
  const [mode, a, b] = process.argv.slice(2);
  if (mode === 'scandirs') await scanDirs(path.resolve(a), b);
  else if (mode === 'build') await build(path.resolve(a));
  else if (mode === 'html') html(a, b);
  else {
    console.error('usage: dump_scan.js build <outDir> | html <cases.json> <out.json>');
    process.exit(2);
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
