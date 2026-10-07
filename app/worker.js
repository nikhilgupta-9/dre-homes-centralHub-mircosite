'use strict';
// Runs the heavy work (scan, zip, protect) off the main thread so the window never freezes.
const { parentPort } = require('worker_threads');
const svc = require('../src/app/service');

parentPort.on('message', async (m) => {
  const { id, op, args } = m;
  const progress = (p) => parentPort.postMessage({ id, type: 'progress', data: p });
  try {
    let data;
    if (op === 'classify') data = svc.classifyDrop(args[0]);
    else if (op === 'scan') data = await svc.scan(args[0], args[1]);
    else if (op === 'protect') data = await svc.protect(args[0], args[1]);
    else if (op === 'scanBulk') data = await svc.scanBulk(args[0], progress);
    else if (op === 'protectBulk') data = await svc.protectBulk(args[0], args[1], progress);
    else throw new Error('unknown op ' + op);
    parentPort.postMessage({ id, type: 'done', data });
  } catch (e) {
    parentPort.postMessage({ id, type: 'error', message: e && e.message ? e.message : String(e) });
  }
});
