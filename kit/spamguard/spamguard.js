/*! SpamGuard client v1.0
 * One <script> tag per page is all a micro-site needs:
 *   <script src="/spamguard/spamguard.js" defer></script>
 * It finds enquiry forms and adds: hidden honeypot, signed time-token, interaction counter,
 * ad-source fields (utm_* / gclid) and (optionally) Cloudflare Turnstile.
 * Optional settings, set BEFORE the script tag:
 *   window.SpamGuardConfig = { turnstileSiteKey: '0x4AAA...', selector: 'form.enquiry', tokenUrl: '/spamguard/token.php' };
 * Opt a form out with data-sg="off".
 */
(function () {
  'use strict';
  if (window.__sgLoaded) { return; }
  window.__sgLoaded = true;

  var cfg = window.SpamGuardConfig || {};
  var script = document.currentScript;
  var base = (script && script.src) ? script.src.replace(/[?#].*$/, '').replace(/[^\/]*$/, '') : '/spamguard/';
  var tokenUrl = cfg.tokenUrl || (base + 'token.php');
  var token = '';
  var tokenInputs = [];

  function param(name) {
    var m = new RegExp('[?&]' + name + '=([^&#]*)').exec(location.search);
    if (!m) { return ''; }
    try { return decodeURIComponent(m[1].replace(/\+/g, ' ')).slice(0, 200); } catch (e) { return ''; }
  }

  // Remember where the visitor came from (ad click) for 30 days, so the lead can be matched to its ad.
  function attribution() {
    var keys = ['utm_source', 'utm_medium', 'utm_campaign', 'gclid'];
    var saved = {};
    try {
      saved = JSON.parse(localStorage.getItem('sg_attr') || '{}') || {};
      if (saved.exp && saved.exp < Date.now()) { saved = {}; }
    } catch (e) { saved = {}; }
    var found = false;
    for (var i = 0; i < keys.length; i++) {
      var v = param(keys[i]);
      if (v) { saved[keys[i]] = v; found = true; }
    }
    if (found) {
      saved.exp = Date.now() + 30 * 864e5;
      try { localStorage.setItem('sg_attr', JSON.stringify(saved)); } catch (e) { /* private mode */ }
    }
    return saved;
  }

  function hidden(name, value) {
    var i = document.createElement('input');
    i.type = 'hidden'; i.name = name; i.value = value || '';
    return i;
  }

  function isEnquiryForm(f) {
    if (f.getAttribute('data-sg') === 'off') { return false; }
    if (f.querySelector('input[type=password]')) { return false; }   // login forms are not enquiries
    if (cfg.selector) { return f.matches ? f.matches(cfg.selector) : true; }
    return !!f.querySelector('textarea, input[type=email], input[type=tel], input[name*=mail i], input[name*=phone i], input[name*=mobile i]');
  }

  function protect(f, attr) {
    if (f.__sg) { return; }
    f.__sg = true;

    // honeypot (off-screen, never focusable)
    var wrap = document.createElement('div');
    wrap.setAttribute('aria-hidden', 'true');
    wrap.style.cssText = 'position:absolute!important;left:-10000px!important;top:auto!important;width:1px;height:1px;overflow:hidden';
    var hp = document.createElement('input');
    hp.type = 'text'; hp.name = 'sg_website'; hp.tabIndex = -1; hp.value = '';
    hp.setAttribute('autocomplete', 'off');
    wrap.appendChild(hp);
    f.appendChild(wrap);

    var t = hidden('sg_t', token);
    var inter = hidden('sg_i', '0');
    f.appendChild(t); f.appendChild(inter);
    tokenInputs.push(t);

    f.appendChild(hidden('sg_page', location.pathname.slice(0, 300)));
    var map = { utm_source: 'sg_utm_source', utm_medium: 'sg_utm_medium', utm_campaign: 'sg_utm_campaign', gclid: 'sg_gclid' };
    for (var k in map) {
      if (Object.prototype.hasOwnProperty.call(map, k) && attr[k]) { f.appendChild(hidden(map[k], attr[k])); }
    }

    // count real keyboard / pointer / touch activity inside the form
    var n = 0;
    var bump = function () { n++; inter.value = String(n); };
    var evs = ['keydown', 'pointerdown', 'touchstart', 'input', 'change'];
    for (var e = 0; e < evs.length; e++) { f.addEventListener(evs[e], bump, true); }

    if (cfg.turnstileSiteKey) { addTurnstile(f); }
  }

  function addTurnstile(f) {
    var div = document.createElement('div');
    div.className = 'sg-turnstile';
    var btn = f.querySelector('[type=submit], button:not([type])');
    if (btn && btn.parentNode) { btn.parentNode.insertBefore(div, btn); } else { f.appendChild(div); }
    var render = function () {
      try { window.turnstile.render(div, { sitekey: cfg.turnstileSiteKey, theme: 'auto' }); } catch (e) { /* fail-open */ }
    };
    if (window.turnstile) { render(); return; }
    if (!window.__sgTsLoading) {
      window.__sgTsLoading = [];
      var s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      s.async = true; s.defer = true;
      s.onload = function () { var q = window.__sgTsLoading; window.__sgTsLoading = null; for (var i = 0; i < q.length; i++) { q[i](); } };
      document.head.appendChild(s);
    }
    if (window.__sgTsLoading) { window.__sgTsLoading.push(render); }
  }

  function fetchToken(cb) {
    var done = function (t) { cb(t || ''); };
    try {
      if (window.fetch) {
        fetch(tokenUrl, { cache: 'no-store', credentials: 'same-origin' })
          .then(function (r) { return r.json(); })
          .then(function (j) { done(j && j.t); })
          .catch(function () { done(''); });
        return;
      }
    } catch (e) { /* fall through to XHR */ }
    try {
      var x = new XMLHttpRequest();
      x.open('GET', tokenUrl, true);
      x.onload = function () { try { done(JSON.parse(x.responseText).t); } catch (e) { done(''); } };
      x.onerror = function () { done(''); };
      x.send();
    } catch (e) { done(''); }
  }

  function scan(root, attr) {
    var forms = (root.querySelectorAll ? root.querySelectorAll('form') : []);
    for (var i = 0; i < forms.length; i++) {
      if (isEnquiryForm(forms[i])) { protect(forms[i], attr); }
    }
  }

  function init() {
    var attr = attribution();
    scan(document, attr);
    fetchToken(function (t) {
      token = t;
      for (var i = 0; i < tokenInputs.length; i++) { tokenInputs[i].value = t; }
    });
    if (window.MutationObserver) {
      var timer = null;
      // forms added later by a script/popup get protected too (debounced, cheap)
      new MutationObserver(function () {
        if (timer) { return; }
        timer = setTimeout(function () {
          timer = null;
          try {
            if (!document || !document.querySelectorAll) { return; }
            scan(document, attr);
            if (token) { for (var i = 0; i < tokenInputs.length; i++) { if (!tokenInputs[i].value) { tokenInputs[i].value = token; } } }
          } catch (e) { /* never break the page */ }
        }, 60);
      }).observe(document.documentElement, { childList: true, subtree: true });
    }
  }

  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); } else { init(); }
})();
