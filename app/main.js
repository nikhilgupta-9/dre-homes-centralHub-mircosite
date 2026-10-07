'use strict';
const { app, BrowserWindow, ipcMain, dialog, shell, session, safeStorage } = require('electron');
const { normalizeUrl } = require('../src/hub');
const { Worker } = require('worker_threads');
const fs = require('fs');
const path = require('path');
const os = require('os');

if (process.env.SG_USER_DATA) app.setPath('userData', process.env.SG_USER_DATA);

let win = null;
let worker = null;
let seq = 0;
const pending = new Map();
const allowed = new Set(); // paths the window may ask us to open / read (only our own outputs)

const defaultOut = () => path.join(app.getPath('documents'), 'SpamGuard Results');
const settingsFile = () => path.join(app.getPath('userData'), 'settings.json');
const DEFAULTS = () => ({ outDir: defaultOut(), notifyEmail: '', quarantine: false, includeReview: false, timezone: 'Asia/Kolkata', hubUrl: '', hubTokenEnc: '', hubTokenPlain: '' });

function loadSettings() {
  try {
    return Object.assign(DEFAULTS(), JSON.parse(fs.readFileSync(settingsFile(), 'utf8')));
  } catch (e) {
    return DEFAULTS();
  }
}
// The hub token only lets this app CREATE sites (it can never read leads). Still, keep it out of plain text when the OS offers a keychain.
function storeToken(t) {
  if (!t) return { hubTokenEnc: '', hubTokenPlain: '' };
  if (safeStorage && safeStorage.isEncryptionAvailable()) return { hubTokenEnc: safeStorage.encryptString(t).toString('base64'), hubTokenPlain: '' };
  return { hubTokenEnc: '', hubTokenPlain: t };
}
function readToken(s) {
  try {
    if (s.hubTokenEnc) return safeStorage.decryptString(Buffer.from(s.hubTokenEnc, 'base64'));
  } catch (e) {
    return '';
  }
  return s.hubTokenPlain || '';
}
const publicSettings = (s) => ({ outDir: s.outDir, notifyEmail: s.notifyEmail, quarantine: s.quarantine, includeReview: s.includeReview, timezone: s.timezone, hubUrl: s.hubUrl, hubTokenSet: !!readToken(s) });

function saveSettings(s) {
  const d = DEFAULTS();
  const cur = loadSettings();
  const clean = {
    outDir: typeof s.outDir === 'string' && path.isAbsolute(s.outDir) ? s.outDir : d.outDir,
    notifyEmail: typeof s.notifyEmail === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.notifyEmail.trim()) ? s.notifyEmail.trim() : '',
    quarantine: !!s.quarantine,
    includeReview: !!s.includeReview,
    timezone: typeof s.timezone === 'string' && /^[A-Za-z_]+\/[A-Za-z_\-+0-9]+$/.test(s.timezone) ? s.timezone : d.timezone,
    hubUrl: '',
    hubTokenEnc: '',
    hubTokenPlain: '',
  };
  const url = typeof s.hubUrl === 'string' ? s.hubUrl.trim() : '';
  if (url) {
    clean.hubUrl = normalizeUrl(url); // throws a readable error for http://, junk, credentials in the URL
    const typed = typeof s.hubToken === 'string' ? s.hubToken.trim() : '';
    if (typed && !/^[A-Za-z0-9_-]{20,80}$/.test(typed)) throw new Error('Hub token galat lag raha hai. Hub ke Settings se poora copy karo.');
    Object.assign(clean, typed ? storeToken(typed) : { hubTokenEnc: cur.hubTokenEnc, hubTokenPlain: cur.hubTokenPlain });
  }
  fs.mkdirSync(path.dirname(settingsFile()), { recursive: true });
  fs.writeFileSync(settingsFile(), JSON.stringify(clean, null, 2), { mode: 0o600 });
  return publicSettings(clean);
}

/** One new folder per run: 2026-10-07_13-25-10, with -2, -3 ... if it somehow exists already. */
function freshRunDir(base) {
  const stamp = new Date().toISOString().slice(0, 19).replace('T', '_').replace(/:/g, '-');
  let dir = path.join(base, stamp);
  for (let i = 2; fs.existsSync(dir); i++) dir = path.join(base, stamp + '-' + i);
  return dir;
}

function startWorker() {
  worker = new Worker(path.join(__dirname, 'worker.js'));
  worker.on('message', (m) => {
    const p = pending.get(m.id);
    if (!p) return;
    if (m.type === 'progress') {
      if (win && !win.isDestroyed()) win.webContents.send('sg:progress', Object.assign({ job: m.id }, m.data));
    } else {
      pending.delete(m.id);
      if (m.type === 'done') p.resolve(m.data);
      else p.reject(new Error(m.message));
    }
  });
  worker.on('error', (e) => {
    for (const p of pending.values()) p.reject(e);
    pending.clear();
    worker = null;
  });
  worker.on('exit', () => {
    for (const p of pending.values()) p.reject(new Error('Kaam beech mein ruk gaya. Dobara try karo.'));
    pending.clear();
    worker = null;
  });
}
function run(op, ...args) {
  if (!worker) startWorker();
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, op, args });
  });
}

const rememberOutputs = (ui) => {
  if (!ui) return;
  if (ui.outputs && ui.outputs.dir) allowed.add(ui.outputs.dir);
};

function setup() {
  ipcMain.handle('sg:version', () => app.getVersion());
  ipcMain.handle('sg:settings:get', () => publicSettings(loadSettings()));
  ipcMain.handle('sg:settings:set', (_e, s) => saveSettings(s || {}));
  ipcMain.handle('sg:outdir', async () => {
    const r = await dialog.showOpenDialog(win, { title: 'Result kahan save karein?', properties: ['openDirectory', 'createDirectory'] });
    return r.canceled ? null : r.filePaths[0];
  });
  ipcMain.handle('sg:pick', async (_e, kind) => {
    const opts = kind === 'folder'
      ? { title: 'Site ka folder chuno', properties: ['openDirectory'] }
      : kind === 'sql'
        ? { title: 'Database (.sql) chuno', properties: ['openFile'], filters: [{ name: 'SQL', extensions: ['sql'] }] }
        : { title: 'Site ka zip chuno', properties: ['openFile', 'multiSelections'], filters: [{ name: 'ZIP', extensions: ['zip'] }] };
    const r = await dialog.showOpenDialog(win, opts);
    return r.canceled ? [] : r.filePaths;
  });
  ipcMain.handle('sg:classify', (_e, paths) => run('classify', Array.isArray(paths) ? paths.filter((p) => typeof p === 'string') : []));
  ipcMain.handle('sg:scan', async (_e, drop) => {
    if (!drop || typeof drop !== 'object') throw new Error('bad request');
    if (drop.kind === 'site') return run('scan', drop.input, { sqlFiles: drop.sqlFiles || [] }).then((r) => ({ ui: r.ui, text: r.text }));
    if (drop.kind === 'bulk') return run('scanBulk', drop);
    throw new Error('bad request');
  });
  ipcMain.handle('sg:protect', async (_e, drop) => {
    if (!drop || typeof drop !== 'object') throw new Error('bad request');
    const s = loadSettings();
    const opts = { outDir: freshRunDir(s.outDir), notifyEmail: s.notifyEmail, quarantine: s.quarantine, includeReview: s.includeReview, timezone: s.timezone, sqlFiles: drop.sqlFiles || [], hub: s.hubUrl && readToken(s) ? { url: s.hubUrl, token: readToken(s) } : undefined };
    fs.mkdirSync(opts.outDir, { recursive: true });
    allowed.add(opts.outDir);
    if (drop.kind === 'site') {
      const r = await run('protect', drop.input, opts);
      rememberOutputs(r.ui);
      return r;
    }
    if (drop.kind === 'bulk') {
      const bulk = await run('protectBulk', drop, opts);
      return Object.assign({ outDir: opts.outDir }, bulk);
    }
    throw new Error('bad request');
  });
  ipcMain.handle('sg:reveal', (_e, p) => {
    const abs = path.resolve(String(p || ''));
    if (![...allowed].some((a) => abs === a || abs.startsWith(a + path.sep))) return false;
    shell.showItemInFolder(abs);
    return true;
  });
  ipcMain.handle('sg:readReport', (_e, p) => {
    const abs = path.resolve(String(p || ''));
    if (![...allowed].some((a) => abs.startsWith(a + path.sep)) || !/report\.txt$/.test(abs)) throw new Error('not allowed');
    return fs.readFileSync(abs, 'utf8');
  });
}

function createWindow() {
  win = new BrowserWindow({
    width: 980,
    height: 760,
    minWidth: 760,
    minHeight: 560,
    title: 'SpamGuard Studio',
    backgroundColor: '#f6f5f2',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true, nodeIntegration: false, webSecurity: true },
  });
  win.webContents.on('will-navigate', (e) => e.preventDefault()); // a file dropped outside the drop zone must never navigate the window
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.on('closed', () => (win = null));
}

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  setup();
  createWindow();
  app.on('activate', () => {
    if (!BrowserWindow.getAllWindows().length) createWindow();
  });
});
app.on('window-all-closed', () => {
  if (worker) worker.terminate();
  app.quit();
});
