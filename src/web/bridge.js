'use strict';
/* Browser version of the old Electron preload: same window.sg API, but it talks to the local server.
   Files are copied to a temp folder on THIS computer (nothing leaves the machine). */
(function () {
  const token = document.querySelector('meta[name="sg-token"]').content;
  const listeners = new Set();
  const emit = (p) => listeners.forEach((fn) => fn(p));

  async function call(name, body) {
    const r = await fetch('/api/' + name, { method: 'POST', headers: { 'X-SG-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || 'Error');
    return j.data;
  }
  try {
    const es = new EventSource('/api/events?t=' + encodeURIComponent(token));
    es.onmessage = (m) => { try { emit(JSON.parse(m.data)); } catch (e) { /* ignore */ } };
  } catch (e) { /* progress bar just will not move */ }

  const SKIP = /(^|\/)(\.git|node_modules|\.DS_Store)(\/|$)/;
  const batchId = () => Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, '0')).join('');

  // items: [{file, rel}] -> uploads them all, returns the paths (on the server) of the top-level things
  async function uploadAll(items) {
    items = items.filter((i) => !SKIP.test(i.rel));
    if (!items.length) return [];
    const batch = batchId();
    let root = '';
    let done = 0;
    let next = 0;
    const worker = async () => {
      while (next < items.length) {
        const it = items[next++];
        const r = await fetch('/api/upload?batch=' + batch + '&rel=' + encodeURIComponent(it.rel), { method: 'POST', headers: { 'X-SG-Token': token, 'Content-Type': 'application/octet-stream' }, body: it.file });
        const j = await r.json();
        if (!r.ok) throw new Error(j.error || 'Upload fail');
        root = j.root;
        done++;
        emit({ done, total: items.length, name: it.rel });
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
    const tops = [...new Set(items.map((i) => i.rel.split('/')[0]))];
    return tops.map((t) => root + '/' + t);
  }

  const readEntries = (reader) => new Promise((res, rej) => reader.readEntries(res, rej));
  async function walk(entry, prefix, out) {
    if (entry.isFile) {
      const file = await new Promise((res, rej) => entry.file(res, rej));
      out.push({ file, rel: prefix + entry.name });
    } else if (entry.isDirectory) {
      if (SKIP.test(prefix + entry.name + '/')) return;
      const reader = entry.createReader();
      for (;;) {
        const batch = await readEntries(reader);
        if (!batch.length) break;
        for (const e of batch) await walk(e, prefix + entry.name + '/', out);
      }
    }
  }

  const pickFiles = (accept, dir, multiple) => new Promise((resolve) => {
    const inp = document.createElement('input');
    inp.type = 'file';
    if (accept) inp.accept = accept;
    if (dir) inp.webkitdirectory = true;
    if (multiple) inp.multiple = true;
    inp.style.display = 'none';
    document.body.append(inp);
    inp.addEventListener('change', () => { const f = Array.from(inp.files || []); inp.remove(); resolve(f); });
    inp.addEventListener('cancel', () => { inp.remove(); resolve([]); });
    inp.click();
  });

  window.sg = {
    // must be called synchronously inside the drop event (the browser forgets the entries afterwards)
    pathsFromDrop: (dt) => {
      const entries = Array.from(dt.items || []).map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null)).filter(Boolean);
      return (async () => {
        const items = [];
        for (const e of entries) await walk(e, '', items);
        return uploadAll(items);
      })();
    },
    pick: async (kind) => {
      if (kind === 'folder') {
        const files = await pickFiles('', true, false);
        return uploadAll(files.map((f) => ({ file: f, rel: f.webkitRelativePath || f.name })));
      }
      const files = await pickFiles(kind === 'sql' ? '.sql' : '.zip', false, kind !== 'sql');
      return uploadAll(files.map((f) => ({ file: f, rel: f.name })));
    },
    classify: (paths) => call('classify', { paths }),
    scan: (drop) => call('scan', drop),
    protect: (drop) => call('protect', drop),
    getSettings: () => call('settings/get'),
    setSettings: (s) => call('settings/set', s),
    chooseOutDir: async () => null,
    reveal: (p) => call('reveal', { path: p }),
    readReport: (p) => call('readReport', { path: p }),
    onProgress: (fn) => { listeners.add(fn); return () => listeners.delete(fn); },
    version: () => call('version'),
  };
})();
