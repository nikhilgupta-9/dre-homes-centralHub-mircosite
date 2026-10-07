#!/usr/bin/env node
'use strict';
const { execFile } = require('child_process');
const { createStudio } = require('../src/web/server');

const major = Number(process.versions.node.split('.')[0]);
if (major < 18) {
  console.error('Node purana hai (' + process.versions.node + '). nodejs.org se naya Node (LTS) install karo.');
  process.exit(1);
}
const studio = createStudio();
studio.listen(Number(process.env.PORT) || 4780).then(({ url }) => {
  console.log('\n  SpamGuard Studio chal raha hai:  ' + url);
  console.log('  Browser me khul jayega. Band karne ke liye is window me Ctrl+C dabao.\n');
  if (!process.env.SG_NO_OPEN) {
    if (process.platform === 'darwin') execFile('open', [url], () => {});
    else if (process.platform === 'win32') execFile('cmd', ['/c', 'start', '', url], () => {});
    else execFile('xdg-open', [url], () => {});
  }
}).catch((e) => {
  console.error('Start nahi ho paya: ' + e.message);
  process.exit(1);
});
const bye = () => { studio.close(); process.exit(0); };
process.on('SIGINT', bye);
process.on('SIGTERM', bye);
