#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const { scanSite } = require('../src/scanner');
const { scanMany, writeBulkOutputs } = require('../src/scanner/bulk');
const { renderText, renderBulkText } = require('../src/scanner/report');
const { writeConfig } = require('../src/config');
const { protectSite } = require('../src/injector');
const { protectMany, writeSiteReports } = require('../src/injector/bulk');
const { renderProtectText, renderLoginText, renderProtectBulk } = require('../src/injector/report');

const HELP = `SpamGuard Studio (Phase 2 scanner + Phase 3 protect)

  sg scan <site.zip | site-folder>   [--json out.json] [--sql dump.sql] [--quiet]
      Ek site scan karo: forms, handlers, database, plan. Hinglish report print hoti hai.

  sg scan <folder-of-sites> --bulk --out <report-folder>
      Bahut saari sites ek saath. Folder mein har sub-folder / .zip ek site maani jaati hai.
      Output: summary.csv, summary.json, report.txt, reports/<site>.json + .txt

  sg protect <site.zip | site-folder> --out <folder> [--dry-run] [--include-review] [--sql dump.sql]
            [--password p] [--notify mail] [--quarantine] [--timezone Asia/Kolkata] [--keep-folder] [--base-path /sub/]
            [--hub-url https://hub.example.com --hub-token TOKEN]   (site khud hub mein judd jati hai)
      Site ko protect karo. Output folder mein: <site>-protected.zip, <site>-backup-original.zip,
      report.txt, report.json, PRIVATE-login.txt. Original zip/folder ko haath nahi lagta.
      --dry-run: kuch likhe bina bas dikhao ki kya badlega.

  sg protect <folder-of-sites> --bulk --out <folder> [same options]
      Bahut saari sites ek saath. Output: summary.csv, report.txt, PRIVATE-credentials.csv + har site ka folder.

  sg config --site-id <name> --out <path/to/spamguard/config.php> [--notify mail] [--password p]
            [--quarantine] [--timezone Asia/Kolkata] [--force]
      SpamGuard ki config.php banata hai (PHP install karne ki zarurat nahi).
`;

function parseArgs(argv) {
  const out = { _: [], multi: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) out[key] = true;
      else {
        out[key] = next;
        (out.multi[key] = out.multi[key] || []).push(next);
        i++;
      }
    } else out._.push(a);
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  if (!cmd || args.help || args.h) {
    process.stdout.write(HELP);
    return 0;
  }
  if (cmd === 'scan') {
    const input = args._[1];
    if (!input) throw new Error('Site ka zip ya folder do. Example: sg scan mysite.zip');
    const opts = { sqlFiles: args.multi.sql || [] };
    if (args.bulk) {
      if (!args.out) throw new Error('--bulk ke saath --out <folder> bhi do');
      const bulk = await scanMany(input, Object.assign(opts, {
        onProgress: (p) => { if (!args.quiet) process.stderr.write(`\r[${p.done}/${p.total}] ${p.name}${' '.repeat(20)}`); },
      }));
      if (!args.quiet) process.stderr.write('\n');
      writeBulkOutputs(bulk, args.out);
      process.stdout.write(renderBulkText(bulk));
      process.stdout.write(`\nPoori report: ${path.resolve(args.out)}\n`);
      return bulk.totals.failed ? 2 : 0;
    }
    const report = await scanSite(input, opts);
    if (args.json && args.json !== true) fs.writeFileSync(args.json, JSON.stringify(report, null, 2));
    if (!args.quiet) process.stdout.write(renderText(report));
    if (args.json && args.json !== true) process.stdout.write(`JSON report: ${path.resolve(args.json)}\n`);
    return 0;
  }
  if (cmd === 'protect') {
    const input = args._[1];
    if (!input) throw new Error('Site ka zip ya folder do. Example: sg protect mysite.zip --out ./result');
    const str = (k) => (args[k] === true ? undefined : args[k]);
    if (!args['dry-run'] && !str('out')) throw new Error('--out <folder> do (jahan protected zip aur report banenge)');
    const opts = {
      outDir: str('out'),
      dryRun: !!args['dry-run'],
      includeReview: !!args['include-review'],
      sqlFiles: args.multi.sql || [],
      password: str('password'),
      notifyEmail: str('notify'),
      timezone: str('timezone'),
      quarantine: !!args.quarantine,
      keepFolder: !!args['keep-folder'],
      basePath: str('base-path'),
      hub: str('hub-url') && str('hub-token') ? { url: str('hub-url'), token: str('hub-token') } : undefined,
    };
    if (args.bulk) {
      const bulk = await protectMany(input, Object.assign(opts, {
        onProgress: (p) => { if (!args.quiet) process.stderr.write(`\r[${p.done}/${p.total}] ${p.name}${' '.repeat(20)}`); },
      }));
      if (!args.quiet) process.stderr.write('\n');
      process.stdout.write(renderProtectBulk(bulk));
      if (!opts.dryRun) process.stdout.write(`\nPoori report: ${path.resolve(opts.outDir)}\n`);
      return bulk.totals.failed ? 2 : 0;
    }
    const r = await protectSite(input, opts);
    if (!opts.dryRun) writeSiteReports(r, path.resolve(opts.outDir));
    if (!args.quiet) process.stdout.write(renderProtectText(r));
    if (r.login && !opts.dryRun) process.stdout.write(`Admin password: ${r.login.password}   (PRIVATE-login.txt mein bhi hai)\n`);
    return 0;
  }
  if (cmd === 'config') {
    if (!args.out || args.out === true) throw new Error('--out <.../spamguard/config.php> do');
    const g = writeConfig(args.out, {
      siteId: args['site-id'] === true ? undefined : args['site-id'],
      password: args.password === true ? undefined : args.password,
      notifyEmail: args.notify === true ? undefined : args.notify,
      timezone: args.timezone === true ? undefined : args.timezone,
      quarantine: !!args.quarantine,
      force: !!args.force,
    });
    process.stdout.write(`config.php ban gayi: ${path.resolve(args.out)}\n`);
    process.stdout.write(g.generatedPassword ? `Admin password : ${g.password}   (sirf ek baar dikh raha hai, save kar lo)\n` : 'Admin password : (jo aapne diya)\n');
    process.stdout.write(`Admin page     : /spamguard/spam-admin.php\nSelftest       : /spamguard/selftest.php?key=${g.selftestKey}   (setup ke baad selftest.php delete kar do)\n`);
    return 0;
  }
  throw new Error('Pata nahi ye command: ' + cmd + '\n\n' + HELP);
}

main().then(
  (code) => process.exit(code || 0),
  (e) => {
    process.stderr.write('Error: ' + e.message + '\n');
    process.exit(1);
  }
);
