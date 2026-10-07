'use strict';
const { lineAt } = require('./util');

/** JS libraries are never form handlers: skip them (cheap, and avoids false matches). */
const LIB_FILE = /(^|[\/.\-_])(jquery|bootstrap|popper|slick|owl|swiper|wow|aos|lightbox|fancybox|isotope|magnific|waypoints|counterup|modernizr|validate|validator|moment|lodash|underscore|angular|react|vue|chart|gsap|three|select2|datatables|tinymce|ckeditor|particles|typed|parallax|jquery-ui|easing|imagesloaded|masonry|sweetalert|toastr|recaptcha|analytics|gtag|fontawesome|polyfill|vendor|vendors|plugins?)(\.|-|_|\/)/i;

function isLibraryJs(rel) {
  return /\.min\.js$/i.test(rel) || LIB_FILE.test(rel);
}

const QUOTE = '[\'"`]';

/** All AJAX-ish calls in a script: [{index, url|null, usesFormAction, kind}] */
function findAjaxCalls(js) {
  const out = [];
  const push = (index, url, kind, extra) => out.push(Object.assign({ index, url: url || null, usesFormAction: false, kind }, extra || {}));
  let m;
  const ajax = new RegExp('\\$\\.ajax\\s*\\(\\s*\\{', 'g');
  while ((m = ajax.exec(js))) {
    // options object can be long (data + success handlers): read a window, stop at the next ajax call
    let body = js.slice(m.index + m[0].length, m.index + m[0].length + 2500);
    const nxt = body.search(/\$\.ajax\s*\(/);
    if (nxt > -1) body = body.slice(0, nxt);
    const u = body.match(new RegExp('url\\s*:\\s*(' + QUOTE + ')([^\'"`]+)\\1'));
    const usesAction = /url\s*:\s*[^,}]*(?:attr\s*\(\s*['"]action['"]\s*\)|\.action\b|prop\s*\(\s*['"]action['"])/.test(body);
    const type = body.match(/(?:type|method)\s*:\s*['"](\w+)['"]/i);
    push(m.index, u ? u[2] : null, 'jquery-ajax', { usesFormAction: usesAction && !u, method: type ? type[1].toUpperCase() : null, dataType: (body.match(/dataType\s*:\s*['"](\w+)['"]/) || [])[1] || null });
  }
  const post = new RegExp('\\$\\.(post|get)\\s*\\(\\s*(' + QUOTE + ')([^\'"`]+)\\2', 'g');
  while ((m = post.exec(js))) if (m[1] === 'post') push(m.index, m[3], 'jquery-post', { method: 'POST' });
  const postAction = /\$\.post\s*\(\s*[^,'"`)]*(?:attr\s*\(\s*['"]action['"]\s*\)|\.action\b)/g;
  while ((m = postAction.exec(js))) push(m.index, null, 'jquery-post', { usesFormAction: true, method: 'POST' });
  const fetchRe = new RegExp('\\bfetch\\s*\\(\\s*(' + QUOTE + ')([^\'"`]+)\\1([\\s\\S]{0,300})', 'g');
  while ((m = fetchRe.exec(js))) {
    if (/method\s*:\s*['"]post['"]/i.test(m[3])) push(m.index, m[2], 'fetch', { method: 'POST' });
  }
  const fetchAction = /\bfetch\s*\(\s*[\w$.]*(?:\.action\b|attr\s*\(\s*['"]action['"]\s*\))/g;
  while ((m = fetchAction.exec(js))) push(m.index, null, 'fetch', { usesFormAction: true, method: 'POST' });
  const xhr = new RegExp('\\.open\\s*\\(\\s*[\'"]post[\'"]\\s*,\\s*(' + QUOTE + ')([^\'"`]+)\\1', 'gi');
  while ((m = xhr.exec(js))) push(m.index, m[2], 'xhr', { method: 'POST' });
  const xhrAction = /\.open\s*\(\s*['"]post['"]\s*,\s*[\w$.]*(?:\.action\b|attr\s*\(\s*['"]action['"]\s*\))/gi;
  while ((m = xhrAction.exec(js))) push(m.index, null, 'xhr', { usesFormAction: true, method: 'POST' });
  const axios = new RegExp('\\baxios\\.post\\s*\\(\\s*(' + QUOTE + ')([^\'"`]+)\\1', 'g');
  while ((m = axios.exec(js))) push(m.index, m[2], 'axios', { method: 'POST' });
  out.sort((a, b) => a.index - b.index);
  return out;
}

/** What does the page's JS expect back? (feeds the "fake success" answer for spam) */
function expectedResponse(js, from) {
  const win = js.slice(from, from + 1600);
  const hints = [];
  for (const m of win.matchAll(/\b(?:data|response|res|result|resp|msg|json|d)\.(\w+)\s*(===?|!==?)\s*(['"]?)([\w\- ]+)\3/g)) {
    hints.push({ key: m[1], op: m[2].replace('===', '==').replace('!==', '!='), value: m[4].trim() });
  }
  for (const m of win.matchAll(/\b(?:data|response|res|result|resp|msg|text|t|d)(?:\.trim\s*\(\s*\))?\s*(===?)\s*(['"])([^'"]{1,30})\2/g)) {
    hints.push({ key: null, op: '==', value: m[3] });
  }
  for (const m of win.matchAll(/\bif\s*\(\s*(!?)\s*(?:data|response|res|result|resp)\.(success|ok|status|error)\s*\)/g)) {
    hints.push({ key: m[2], op: m[1] ? 'falsy' : 'truthy', value: null });
  }
  let type = 'unknown';
  if (/dataType\s*:\s*['"]json['"]|\.json\s*\(\s*\)|JSON\.parse|\$\.getJSON/.test(win) || hints.some((h) => h.key)) type = 'json';
  else if (/\.text\s*\(\s*\)|responseText/.test(win) || hints.some((h) => !h.key)) type = 'text';
  return { type, hints };
}

/** Escape for use inside a RegExp. */
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Places inside `js` where this form is selected by id / class / name. */
function selectorMentions(js, attrs) {
  const spots = [];
  const add = (re) => {
    let m;
    while ((m = re.exec(js))) spots.push(m.index);
  };
  if (attrs.id) {
    const id = esc(attrs.id);
    add(new RegExp('[\'"`]#' + id + '[\'"`\\s.:\\[]', 'g'));
    add(new RegExp('getElementById\\s*\\(\\s*[\'"]' + id + '[\'"]', 'g'));
    add(new RegExp('forms\\s*\\[\\s*[\'"]' + id + '[\'"]', 'g'));
  }
  if (attrs.name) add(new RegExp('form\\[name\\s*=\\s*[\'"]?' + esc(attrs.name) + '[\'"]?\\]|document\\.forms\\.' + esc(attrs.name) + '\\b', 'g'));
  for (const cls of (attrs.class || '').split(/\s+/).filter(Boolean)) {
    add(new RegExp('[\'"`][^\'"`]*\\.' + esc(cls) + '(?![\\w-])[^\'"`]*[\'"`]', 'g'));
    add(new RegExp('getElementsByClassName\\s*\\(\\s*[\'"]' + esc(cls) + '[\'"]', 'g'));
  }
  return spots;
}

/** Does this script attach a submit handler to every <form> / form[method=post]? */
function bindsAllForms(js) {
  return /\$\(\s*['"]form(?:\[[^\]]*\])?['"]\s*\)\s*\.(?:on\s*\(\s*['"]submit['"]|submit\s*\()/.test(js) ||
    /querySelector(?:All)?\s*\(\s*['"]form(?:\[[^\]]*\])?['"]\s*\)(?:\.forEach\([^)]*)?[\s\S]{0,80}addEventListener\s*\(\s*['"]submit['"]/.test(js) ||
    /document\.forms\s*\[\s*0\s*\]/.test(js);
}

/**
 * Link a form to the AJAX call that submits it.
 * @param scripts [{file, line, text, kind:'inline'|'file'}] candidate scripts
 * @returns {null|{url, usesFormAction, confidence, file, line, kind, expects}}
 */
function linkAjax(form, scripts, generalScripts) {
  const tryScripts = (list, generic) => {
    for (const s of list) {
      const calls = s._calls || (s._calls = findAjaxCalls(s.text));
      if (!calls.length) continue;
      let anchors = generic ? (bindsAllForms(s.text) ? [0] : []) : selectorMentions(s.text, form.attrs);
      if (!anchors.length) continue;
      let best = null;
      for (const anchor of anchors) {
        const after = calls.filter((c) => c.index >= anchor && c.index - anchor < 3500);
        const cand = after[0] || (calls.length === 1 ? calls[0] : null);
        if (cand) {
          const near = Math.abs(cand.index - anchor);
          if (!best || near < best.near) best = { cand, near };
        }
      }
      if (!best) continue;
      const c = best.cand;
      return {
        url: c.url,
        usesFormAction: c.usesFormAction,
        confidence: generic ? 'medium' : best.near <= 1500 ? 'high' : 'medium',
        file: s.file,
        line: s.line ? s.line + (s.kind === 'inline' ? lineAt(s.text, c.index) - 1 : 0) : lineAt(s.text, c.index),
        kind: c.kind,
        method: c.method || 'POST',
        expects: expectedResponse(s.text, c.index),
      };
    }
    return null;
  };
  // Last resort: the script reads this form's fields by id (e.g. $("input#email")) and makes exactly one POST call.
  const byFields = () => {
    const ids = (form.fieldIds || []).filter((i) => i.length > 1);
    if (ids.length < 2) return null;
    for (const s of scripts) {
      const calls = s._calls || (s._calls = findAjaxCalls(s.text));
      const posts = calls.filter((c) => (c.method || 'POST') === 'POST');
      if (posts.length !== 1) continue;
      const hit = ids.filter((i) => new RegExp('#' + esc(i) + '(?![\\w-])').test(s.text) || new RegExp('getElementById\\s*\\(\\s*[\'"]' + esc(i) + '[\'"]').test(s.text));
      if (hit.length < 2) continue;
      const c = posts[0];
      return {
        url: c.url,
        usesFormAction: c.usesFormAction,
        confidence: 'medium',
        file: s.file,
        line: s.line ? s.line + (s.kind === 'inline' ? lineAt(s.text, c.index) - 1 : 0) : lineAt(s.text, c.index),
        kind: c.kind,
        method: 'POST',
        expects: expectedResponse(s.text, c.index),
      };
    }
    return null;
  };
  return tryScripts(scripts, false) || tryScripts(generalScripts, true) || byFields();
}

module.exports = { isLibraryJs, findAjaxCalls, expectedResponse, linkAjax, selectorMentions };
