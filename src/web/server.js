'use strict';
/**
 * SpamGuard Studio, browser edition.
 * A tiny local web server: it only listens on 127.0.0.1, so only THIS computer can open it.
 * The page is the same one the desktop app used; files are "uploaded" to this same computer (a temp folder), not to the internet.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { Worker } = require('worker_threads');
const { normalizeUrl } = require('../hub');

const RENDERER = path.join(__dirname, '..', '..', 'app', 'renderer');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
const MAX_JSON = 1024 * 1024;

function createStudio(opts = {}) {
  const home = opts.home || path.join(os.homedir(), '.spamguard-studio');
  const docs = opts.docs || path.join(os.homedir(), 'Documents');
  const token = crypto.randomBytes(24).toString('hex');
  const uploadRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-up-'));
  const allowed = new Set();
  const clients = new Set();
  const pending = new Map();
  let worker = null;
  let seq = 0;
  let port = 0;
  let server = null;

  const settingsFile = () => path.join(home, 'settings.json');
  const DEFAULTS = () => ({ outDir: path.join(docs, 'SpamGuard Results'), notifyEmail: '', quarantine: false, includeReview: false, timezone: 'Asia/Kolkata', hubUrl: '', hubToken: '' });
  const loadSettings = () => {
    try {
      return Object.assign(DEFAULTS(), JSON.parse(fs.readFileSync(settingsFile(), 'utf8')));
    } catch (e) {
      return DEFAULTS();
    }
  };
  const publicSettings = (s) => ({ outDir: s.outDir, notifyEmail: s.notifyEmail, quarantine: s.quarantine, includeReview: s.includeReview, timezone: s.timezone, hubUrl: s.hubUrl, hubTokenSet: !!s.hubToken });

  function saveSettings(s) {
    const d = DEFAULTS();
    const cur = loadSettings();
    const clean = {
      outDir: typeof s.outDir === 'string' && path.isAbsolute(s.outDir.trim()) ? s.outDir.trim() : d.outDir,
      notifyEmail: typeof s.notifyEmail === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.notifyEmail.trim()) ? s.notifyEmail.trim() : '',
      quarantine: !!s.quarantine,
      includeReview: !!s.includeReview,
      timezone: typeof s.timezone === 'string' && /^[A-Za-z_]+\/[A-Za-z_\-+0-9]+$/.test(s.timezone) ? s.timezone : d.timezone,
      hubUrl: '',
      hubToken: '',
    };
    const url = typeof s.hubUrl === 'string' ? s.hubUrl.trim() : '';
    if (url) {
      clean.hubUrl = normalizeUrl(url);
      const typed = typeof s.hubToken === 'string' ? s.hubToken.trim() : '';
      if (typed && !/^[A-Za-z0-9_-]{20,80}$/.test(typed)) throw new Error('Hub token galat lag raha hai. Hub ke Settings se poora copy karo.');
      clean.hubToken = typed || cur.hubToken;
    }
    fs.mkdirSync(home, { recursive: true });
    fs.writeFileSync(settingsFile(), JSON.stringify(clean, null, 2), { mode: 0o600 });
    return publicSettings(clean);
  }

  const freshRunDir = (base) => {
    const stamp = new Date().toISOString().slice(0, 19).replace('T', '_').replace(/:/g, '-');
    let dir = path.join(base, stamp);
    for (let i = 2; fs.existsSync(dir); i++) dir = path.join(base, stamp + '-' + i);
    return dir;
  };

  // ---- heavy work runs in a worker thread so the page never freezes
  const broadcast = (obj) => {
    const line = 'data: ' + JSON.stringify(obj) + '\n\n';
    for (const c of clients) c.write(line);
  };
  function startWorker() {
    worker = new Worker(path.join(__dirname, '..', '..', 'app', 'worker.js'));
    worker.on('message', (m) => {
      const p = pending.get(m.id);
      if (!p) return;
      if (m.type === 'progress') broadcast(Object.assign({ job: m.id }, m.data));
      else {
        pending.delete(m.id);
        if (m.type === 'done') p.resolve(m.data);
        else p.reject(new Error(m.message));
      }
    });
    const dead = (e) => {
      for (const p of pending.values()) p.reject(e instanceof Error ? e : new Error('Kaam beech mein ruk gaya. Dobara try karo.'));
      pending.clear();
      worker = null;
    };
    worker.on('error', dead);
    worker.on('exit', dead);
  }
  function run(op, ...args) {
    if (!worker) startWorker();
    const id = ++seq;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, op, args });
    });
  }

  const inUploads = (p) => {
    const abs = path.resolve(String(p || ''));
    return abs.startsWith(uploadRoot + path.sep) ? abs : null;
  };
  // the page may only name paths it uploaded (or .sql files it uploaded); never arbitrary paths on the computer
  const uploadedOnly = (arr) => {
    if (!Array.isArray(arr)) return [];
    return arr.map(inUploads).filter(Boolean);
  };
  const cleanDrop = (drop) => {
    if (!drop || typeof drop !== 'object') throw new Error('bad request');
    const out = Object.assign({}, drop);
    if (out.sqlFiles) out.sqlFiles = uploadedOnly(out.sqlFiles);
    if (out.kind === 'site') {
      if (!inUploads(out.input)) throw new Error('bad request');
    } else if (out.kind === 'bulk') {
      if (out.parent && !inUploads(out.parent)) throw new Error('bad request');
      if (out.items) {
        for (const it of out.items) if (!inUploads(it.input)) throw new Error('bad request');
      }
      if (!out.parent && !out.items) throw new Error('bad request');
    } else throw new Error('bad request');
    return out;
  };

  const rememberOutputs = (ui) => {
    if (ui && ui.outputs && ui.outputs.dir) allowed.add(ui.outputs.dir);
  };

  const api = {
    async version() {
      return require('../../package.json').version;
    },
    async 'settings/get'() {
      return publicSettings(loadSettings());
    },
    async 'settings/set'(b) {
      return saveSettings(b || {});
    },
    async classify(b) {
      return run('classify', uploadedOnly(b && b.paths));
    },
    async scan(b) {
      const drop = cleanDrop(b);
      if (drop.kind === 'site') return run('scan', drop.input, { sqlFiles: drop.sqlFiles || [] }).then((r) => ({ ui: r.ui, text: r.text }));
      return run('scanBulk', drop);
    },
    async protect(b) {
      const drop = cleanDrop(b);
      const s = loadSettings();
      const o = { outDir: freshRunDir(s.outDir), notifyEmail: s.notifyEmail, quarantine: s.quarantine, includeReview: s.includeReview, timezone: s.timezone, sqlFiles: drop.sqlFiles || [], hub: s.hubUrl && s.hubToken ? { url: s.hubUrl, token: s.hubToken } : undefined };
      fs.mkdirSync(o.outDir, { recursive: true });
      allowed.add(o.outDir);
      if (drop.kind === 'site') {
        const r = await run('protect', drop.input, o);
        rememberOutputs(r.ui);
        return r;
      }
      const bulk = await run('protectBulk', drop, o);
      return Object.assign({ outDir: o.outDir }, bulk);
    },
    async reveal(b) {
      const abs = path.resolve(String((b && b.path) || ''));
      if (![...allowed].some((a) => abs === a || abs.startsWith(a + path.sep))) return false;
      if (opts.noOpen) return true;
      if (process.platform === 'darwin') execFile('open', ['-R', abs], () => {});
      else if (process.platform === 'win32') execFile('explorer', ['/select,', abs], () => {});
      else execFile('xdg-open', [fs.existsSync(abs) && fs.statSync(abs).isDirectory() ? abs : path.dirname(abs)], () => {});
      return true;
    },
    async readReport(b) {
      const abs = path.resolve(String((b && b.path) || ''));
      if (![...allowed].some((a) => abs.startsWith(a + path.sep)) || !/report\.txt$/.test(abs)) throw new Error('not allowed');
      return fs.readFileSync(abs, 'utf8');
    },
  };

  const safeRel = (rel) => {
    const parts = String(rel || '').split(/[\\/]+/).filter(Boolean);
    if (!parts.length || parts.some((p) => p === '..' || p === '.' || p.includes('\0'))) return null;
    return parts;
  };

  function upload(req, res, url) {
    const batch = String(url.searchParams.get('batch') || '');
    if (!/^[a-f0-9]{16}$/.test(batch)) return send(res, 400, { error: 'bad batch' });
    const parts = safeRel(url.searchParams.get('rel'));
    if (!parts) return send(res, 400, { error: 'bad path' });
    const dir = path.join(uploadRoot, batch);
    const file = path.join(dir, ...parts);
    if (!file.startsWith(dir + path.sep)) return send(res, 400, { error: 'bad path' });
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const out = fs.createWriteStream(file);
    req.pipe(out);
    out.on('finish', () => send(res, 200, { root: dir }));
    out.on('error', () => send(res, 500, { error: 'write failed' }));
    req.on('aborted', () => out.destroy());
  }

  function send(res, code, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(body);
  }

  const hostOk = (req) => {
    const h = String(req.headers.host || '').toLowerCase();
    return h === '127.0.0.1:' + port || h === 'localhost:' + port;
  };

  function handler(req, res) {
    // DNS-rebinding guard: only our own address is accepted as Host
    if (!hostOk(req)) {
      res.writeHead(403);
      return res.end('forbidden');
    }
    const url = new URL(req.url, 'http://127.0.0.1');
    const headers = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' };
    if (req.method === 'GET' && !url.pathname.startsWith('/api/')) {
      const name = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      if (!['index.html', 'app.js', 'bridge.js', 'style.css'].includes(name)) {
        res.writeHead(404);
        return res.end('not found');
      }
      let body = fs.readFileSync(name === 'bridge.js' ? path.join(__dirname, 'bridge.js') : path.join(RENDERER, name), 'utf8');
      if (name === 'index.html') body = body.replace('</head>', `<meta name="sg-token" content="${token}">\n</head>`);
      res.writeHead(200, Object.assign({ 'Content-Type': MIME[path.extname(name)], 'Cache-Control': 'no-store' }, headers));
      return res.end(body);
    }
    // everything under /api needs the secret token (a random web page cannot read it, so it cannot drive this app)
    const given = req.headers['x-sg-token'] || url.searchParams.get('t');
    const ok = typeof given === 'string' && given.length === token.length && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(token));
    if (!ok) return send(res, 403, { error: 'forbidden' });
    if (req.method === 'GET' && url.pathname === '/api/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' });
      res.write(': hi\n\n');
      clients.add(res);
      req.on('close', () => clients.delete(res));
      return;
    }
    if (req.method !== 'POST') return send(res, 405, { error: 'method' });
    if (url.pathname === '/api/upload') return upload(req, res, url);
    const name = url.pathname.slice('/api/'.length);
    if (!Object.prototype.hasOwnProperty.call(api, name)) return send(res, 404, { error: 'unknown' });
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_JSON) req.destroy();
      else chunks.push(c);
    });
    req.on('end', async () => {
      try {
        const b = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        send(res, 200, { ok: true, data: await api[name](b) });
      } catch (e) {
        send(res, 200, { ok: false, error: e && e.message ? e.message : String(e) });
      }
    });
  }

  function listen(want) {
    return new Promise((resolve, reject) => {
      let p = want;
      const tryPort = () => {
        server = http.createServer(handler);
        server.once('error', (e) => {
          if (e.code === 'EADDRINUSE' && want !== 0 && p < want + 20) {
            p++;
            return tryPort();
          }
          reject(e);
        });
        server.listen(p, '127.0.0.1', () => {
          port = server.address().port;
          resolve({ port, url: `http://127.0.0.1:${port}/` });
        });
      };
      tryPort();
    });
  }

  function close() {
    for (const c of clients) c.end();
    if (worker) worker.terminate();
    if (server) server.close();
    fs.rmSync(uploadRoot, { recursive: true, force: true });
  }

  return { listen, close, token: () => token, uploadRoot };
}

module.exports = { createStudio };
