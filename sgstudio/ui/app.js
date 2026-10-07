'use strict';
/* Renderer: plain DOM, no libraries. Site data (names, files, labels) comes from untrusted sites,
   so text is ALWAYS set with textContent, never innerHTML. */
(function () {
  const $ = (id) => document.getElementById(id);
  const sg = window.sg;
  const VIEWS = ['home', 'busy', 'scan', 'done', 'bulkscan', 'bulkdone'];
  let settings = null;
  let drop = null;
  let last = null; // last protect result (for folder / report buttons)
  let busyCount = 0;

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v === null || v === undefined) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return el;
  }
  const show = (name) => {
    for (const v of VIEWS) $('view-' + v).hidden = v !== name;
    window.scrollTo(0, 0);
  };
  const banner = (msg) => {
    $('banner').textContent = msg || '';
    $('banner').hidden = !msg;
  };
  const tile = (n, label, cls) => h('div', { class: 'tile ' + (cls || '') }, h('b', { text: n }), h('span', { text: label }));
  const pill = (text, cls) => h('span', { class: 'pill ' + (cls || ''), text });
  const fail = (e) => {
    banner(String((e && e.message) || e).replace(/^Error invoking remote method '[^']+': (Error: )?/, ''));
    show('home');
  };

  function busy(title, sub) {
    $('busy-title').textContent = title;
    $('busy-sub').textContent = sub || '';
    $('busy-bar').hidden = true;
    $('busy-detail').textContent = '';
    show('busy');
  }
  sg.onProgress((p) => {
    if (!p || typeof p.total !== 'number') return;
    $('busy-bar').hidden = false;
    $('busy-bar').firstElementChild.style.width = Math.round((p.done / p.total) * 100) + '%';
    $('busy-detail').textContent = `${p.done} / ${p.total}   ${p.name || ''}`;
  });

  // ------------------------------------------------------------------ settings
  async function loadSettings() {
    settings = await sg.getSettings();
    $('s-out').value = settings.outDir;
    $('s-mail').value = settings.notifyEmail;
    $('s-quar').checked = settings.quarantine;
    $('s-review').checked = settings.includeReview;
    $('s-hub').value = settings.hubUrl || '';
    $('s-tok').value = '';
    $('s-tok').placeholder = settings.hubTokenSet ? 'Save hai. Badalna ho to naya daalo' : 'Hub ke Settings se copy karo';
  }
  $('btn-settings').addEventListener('click', () => {
    const open = $('settings').hidden;
    $('settings').hidden = !open;
    $('btn-settings').setAttribute('aria-expanded', String(open));
  });
  $('s-save').addEventListener('click', async () => {
    try {
      settings = await sg.setSettings({ outDir: $('s-out').value, notifyEmail: $('s-mail').value, quarantine: $('s-quar').checked, includeReview: $('s-review').checked, timezone: settings.timezone, hubUrl: $('s-hub').value, hubToken: $('s-tok').value });
    } catch (e) {
      return banner(String((e && e.message) || e).replace(/^Error invoking remote method '[^']+': (Error: )?/, ''));
    }
    banner('');
    $('s-mail').value = settings.notifyEmail;
    $('s-hub').value = settings.hubUrl || '';
    $('s-tok').value = '';
    $('s-tok').placeholder = settings.hubTokenSet ? 'Save hai. Badalna ho to naya daalo' : 'Hub ke Settings se copy karo';
    $('settings').hidden = true;
    $('btn-settings').setAttribute('aria-expanded', 'false');
    if (!$('view-scan').hidden) paintScanButton();
  });

  // ------------------------------------------------------------------ input: drop / pick
  async function handlePaths(paths) {
    banner('');
    try {
      if (paths && typeof paths.then === 'function') {
        busy('Files load ho rahi hain...', 'Sirf aapke computer par, kahin bheji nahi ja rahi');
        paths = await paths;
        if (!paths.length) return show('home');
      }
      if (!paths || !paths.length) return;
      const c = await sg.classify(paths);
      if (c.kind === 'invalid') return banner(c.reason);
      drop = c;
      if (c.kind === 'site') {
        busy('Site scan ho rahi hai...', c.name);
        const r = await sg.scan(c);
        paintScan(r.ui);
      } else {
        busy(`${c.count} sites scan ho rahi hain...`, 'Isme thoda time lag sakta hai');
        const r = await sg.scan(c);
        paintBulkScan(r);
      }
    } catch (e) {
      fail(e);
    }
  }
  const dz = $('drop');
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('over'); }));
  dz.addEventListener('drop', (e) => handlePaths(sg.pathsFromDrop(e.dataTransfer)));
  // a file dropped anywhere else must not open in the window
  document.addEventListener('dragover', (e) => e.preventDefault());
  document.addEventListener('drop', (e) => { e.preventDefault(); if (!dz.contains(e.target)) handlePaths(sg.pathsFromDrop(e.dataTransfer)); });
  dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('pick-zip').click(); } });
  $('pick-zip').addEventListener('click', async () => handlePaths(sg.pick('zip')));
  $('pick-folder').addEventListener('click', async () => handlePaths(sg.pick('folder')));

  // ------------------------------------------------------------------ single site: scan result
  const STATUS = { auto: ['Apne aap', 'ok'], review: ['Review', 'warn'], manual: ['Haath se', 'bad'], skip: ['Enquiry nahi', ''], done: ['Pehle se', 'ok'] };
  let scanUi = null;
  function paintScan(ui) {
    scanUi = ui;
    $('scan-name').textContent = ui.name;
    $('scan-meta').textContent = `${ui.platform || 'plain PHP'}  ·  ${ui.summary.pages} pages  ·  Database: ${ui.database.used ? 'mila' : 'nahi'}`;
    const s = ui.summary;
    $('scan-tiles').replaceChildren(tile(s.enquiryForms, 'Enquiry forms'), tile(s.auto, 'Apne aap protect', 'ok'), tile(s.review, 'Review', s.review ? 'warn' : ''), tile(s.manual, 'Haath se', s.manual ? 'bad' : ''), s.done ? tile(s.done, 'Pehle se protected', 'ok') : null);
    const forms = ui.forms.filter((f) => f.status !== 'skip');
    $('scan-forms').replaceChildren(
      ...(forms.length
        ? forms.map((f) => {
            const [t, c] = STATUS[f.status];
            return h('div', { class: 'item' },
              h('div', { class: 'item-top' }, h('b', { text: f.label }), pill(t, c)),
              h('div', { class: 'where', text: `${f.file}:${f.line || '?'}` + (f.handler ? `  →  ${f.handler}${f.submitMode === 'ajax' ? ' (AJAX)' : ''}` : '') }),
              f.notes.length ? h('ul', { class: 'notes' }, f.notes.map((n) => h('li', { text: n }))) : null);
          })
        : [h('div', { class: 'item' }, h('b', { text: 'Is site mein enquiry form nahi mila.' }), h('div', { class: 'where', text: 'Shayad galat folder diya hai, ya site mein form hai hi nahi.' }))]));
    $('scan-sqlname').textContent = drop.sqlFiles && drop.sqlFiles.length ? drop.sqlFiles.map((p) => p.split(/[\\/]/).pop()).join(', ') : '';
    paintScanButton();
    show('scan');
  }
  function paintScanButton() {
    const n = scanUi.summary.auto + (settings.includeReview ? scanUi.summary.review : 0);
    const b = $('scan-go');
    b.disabled = n === 0;
    b.textContent = n ? `Protect karo (${n} form)` : 'Kuch protect nahi ho sakta';
  }
  $('scan-back').addEventListener('click', reset);
  $('scan-sql').addEventListener('click', async () => {
    const p = await sg.pick('sql');
    if (!p.length) return;
    drop = Object.assign({}, drop, { sqlFiles: (drop.sqlFiles || []).concat(p) });
    busy('Dobara scan ho raha hai...', drop.name);
    try { paintScan((await sg.scan(drop)).ui); } catch (e) { fail(e); }
  });
  $('scan-go').addEventListener('click', async () => {
    busy('Protect ho raha hai...', drop.name);
    try {
      const r = await sg.protect(drop);
      last = r;
      paintDone(r);
    } catch (e) {
      fail(e);
    }
  });

  // ------------------------------------------------------------------ single site: result
  const TONE = { protected: 'ok', 'already-protected': 'ok', partial: 'warn', 'manual-only': 'neutral', 'nothing-to-do': 'neutral', 'no-forms': 'neutral', failed: 'bad' };
  const OUT_CLS = { protected: 'ok', 'already-protected': 'ok', 'needs-review': 'warn', manual: 'bad', failed: 'bad' };
  function paintDone(r) {
    const ui = r.ui;
    $('done-banner').className = 'status ' + (TONE[ui.status] || 'neutral');
    $('done-banner').replaceChildren(ui.statusText, h('small', { text: ui.name }));
    const s = ui.summary;
    $('done-tiles').replaceChildren(tile(s.protected, 'Protected', s.protected ? 'ok' : ''), tile(s.alreadyProtected, 'Pehle se'), tile(s.needsReview, 'Review baaki', s.needsReview ? 'warn' : ''), tile(s.manual, 'Haath se baaki', s.manual ? 'bad' : ''), tile(s.failed, 'Fail', s.failed ? 'bad' : ''));
    $('done-forms').replaceChildren(...ui.forms.map((f) => h('div', { class: 'item' },
      h('div', { class: 'item-top' }, h('b', { text: f.label }), pill(f.outcomeText, OUT_CLS[f.outcome] || '')),
      h('div', { class: 'where', text: `${f.file}:${f.line || '?'}` + (f.handler ? `  →  ${f.handler}` : '') }),
      f.notes.length ? h('ul', { class: 'notes' }, f.notes.map((n) => h('li', { text: n }))) : null)));
    const hubLine = $('done-hub');
    hubLine.textContent = !ui.hub ? '' : ui.hub.status === 'connected' ? `Hub se juda (site #${ui.hub.siteId}). Pehli enquiry ya page-view ke baad "Live" dikhegi.` : ui.hub.status === 'failed' ? 'Hub se connect nahi hua: ' + ui.hub.error + ' Site protect ho gayi hai, par hub mein nahi judi.' : '';
    hubLine.hidden = !hubLine.textContent;
    $('done-login').hidden = !ui.login;
    if (ui.login) $('done-pass').textContent = ui.login.password;
    const steps = $('done-steps');
    steps.hidden = !ui.steps.length;
    steps.querySelector('ol').replaceChildren(...ui.steps.map((t) => h('li', { text: t })));
    $('done-folder').hidden = !(ui.outputs && ui.outputs.protectedZip);
    $('done-report').hidden = !(ui.outputs && ui.outputs.dir);
    show('done');
  }
  $('done-copy').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('done-pass').textContent); $('done-copy').textContent = 'Copy ho gaya'; setTimeout(() => ($('done-copy').textContent = 'Copy'), 1800); } catch (e) { $('done-copy').textContent = 'Select karke Cmd+C'; }
  });
  $('done-folder').addEventListener('click', () => sg.reveal(last.ui.outputs.protectedZip));
  $('done-report').addEventListener('click', async () => {
    try {
      $('report-text').textContent = await sg.readReport(last.ui.outputs.dir + '/report.txt');
      $('report-dialog').showModal();
    } catch (e) { banner('Report khul nahi payi.'); }
  });
  $('report-close').addEventListener('click', () => $('report-dialog').close());
  $('done-again').addEventListener('click', reset);

  // ------------------------------------------------------------------ bulk
  const table = (cols, rows) => h('table', null,
    h('thead', null, h('tr', null, cols.map((c) => h('th', { text: c.label })))),
    h('tbody', null, rows.map((r) => h('tr', null, cols.map((c) => {
      const v = c.render ? c.render(r) : r[c.key];
      return h('td', { class: c.cls || false }, v && v.nodeType ? v : String(v === undefined || v === null ? '' : v));
    })))));
  function paintBulkScan(r) {
    const t = r.totals;
    $('bs-title').textContent = `${t.sites} sites mili`;
    $('bs-tiles').replaceChildren(tile(t.sites, 'Sites'), tile(t.forms, 'Enquiry forms'), tile(t.auto, 'Apne aap protect', 'ok'), tile(t.review, 'Review', t.review ? 'warn' : ''), tile(t.manual, 'Haath se', t.manual ? 'bad' : ''), tile(t.failed, 'Khuli nahi', t.failed ? 'bad' : ''));
    $('bs-table').replaceChildren(table([
      { label: 'Site', key: 'name', cls: 'name' },
      { label: 'Forms', key: 'enquiryForms' }, { label: 'Auto', key: 'auto' }, { label: 'Review', key: 'review' }, { label: 'Haath se', key: 'manual' },
      { label: 'Pehle se', key: 'done' }, { label: 'Database', key: 'db' },
      { label: 'Status', render: (x) => (x.status === 'failed' ? pill('Khuli nahi', 'bad') : pill('Scan ho gayi', 'ok')) },
    ], r.rows));
    const n = t.auto + (settings.includeReview ? t.review : 0);
    $('bs-go').disabled = n === 0;
    $('bs-go').textContent = n ? `Sab protect karo (${n} form)` : 'Kuch protect nahi ho sakta';
    show('bulkscan');
  }
  $('bs-back').addEventListener('click', reset);
  $('bs-go').addEventListener('click', async () => {
    busy(`${drop.count} sites protect ho rahi hain...`, 'Window band mat karna');
    try {
      const r = await sg.protect(drop);
      last = r;
      paintBulkDone(r);
    } catch (e) { fail(e); }
  });
  const BULK_TXT = { protected: ['Protected', 'ok'], partial: ['Kuch baaki', 'warn'], 'manual-only': ['Haath se', 'bad'], 'nothing-to-do': ['Kuch nahi badla', ''], 'no-forms': ['Form nahi', ''], 'already-protected': ['Pehle se', 'ok'], failed: ['Fail', 'bad'] };
  function paintBulkDone(r) {
    const t = r.totals;
    const bad = t.failed > 0;
    $('bd-banner').className = 'status ' + (bad || t.partial || t.formsOpen ? 'warn' : t.protected ? 'ok' : 'neutral');
    $('bd-banner').replaceChildren(`${t.protected} site protect hui, ${t.formsProtected} forms`, h('small', { text: `${t.partial} adhoori, ${t.untouched} mein kuch nahi badla, ${t.failed} fail` + (t.formsOpen ? `  ·  ${t.formsOpen} form haath se karne baaki` : '') }));
    $('bd-tiles').replaceChildren(tile(t.protected, 'Protected', 'ok'), tile(t.partial, 'Adhoori', t.partial ? 'warn' : ''), tile(t.untouched, 'Kuch nahi badla'), tile(t.already, 'Pehle se'), tile(t.failed, 'Fail', t.failed ? 'bad' : ''));
    $('bd-table').replaceChildren(table([
      { label: 'Site', key: 'name', cls: 'name' },
      { label: 'Status', render: (x) => { const [a, c] = BULK_TXT[x.status] || [x.status, '']; return pill(a, c); } },
      { label: 'Protected forms', key: 'protectedForms' }, { label: 'Baaki', key: 'openForms' },
      { label: 'Note', key: 'error', cls: 'name' },
    ], r.rows));
    show('bulkdone');
  }
  $('bd-folder').addEventListener('click', () => sg.reveal(last.outDir));
  $('bd-again').addEventListener('click', reset);

  function reset() {
    drop = null; last = null; scanUi = null;
    banner('');
    show('home');
  }

  loadSettings().then(() => show('home'));
})();
