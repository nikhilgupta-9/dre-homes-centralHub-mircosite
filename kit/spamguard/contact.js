/* SpamGuard contact sync: shows the site's central contact details and swaps old numbers/emails for the new ones.
 * Add before </body>:  <script src="/spamguard/contact.js" defer></script>
 *   <span data-sg-contact="phone"></span>        -> text
 *   <a data-sg-contact-link="phone">Call</a>     -> tel:/mailto:/wa.me/URL link (+ text when empty)
 * Never breaks the page: every step is wrapped. */
(function () {
  'use strict';
  var script = document.currentScript || (function () { var s = document.getElementsByTagName('script'); return s[s.length - 1]; })();
  var base = (script && script.src ? script.src : location.href).replace(/[^\/]*(\?.*)?$/, '');
  var digits = function (s) { return String(s || '').replace(/\D/g, ''); };
  function samePhone(a, b) {
    a = digits(a); b = digits(b);
    if (a.length < 6 || b.length < 6) return false;
    return a.length >= 10 && b.length >= 10 ? a.slice(-10) === b.slice(-10) : a === b;
  }
  function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function phoneRe(old) {
    var d = digits(old);
    if (d.length < 6) return null;
    var core = d.split('').join('[\\s().\\-]{0,3}');
    var prefix = d.length === 10 ? '(?:\\+?\\d{1,3}[\\s.\\-]{0,3})?' : '';
    return new RegExp('(^|[^\\d+])(' + prefix + '\\(?' + core + ')(?!\\d)', 'g');
  }
  function pairs(c) {
    var out = [], leg = c.legacy || {}, f = c.f || {};
    Object.keys(leg).forEach(function (field) {
      var nv = f[field]; if (!nv || !Array.isArray(leg[field])) return;
      var kind = field === 'phone' || field === 'phone2' || field === 'whatsapp' ? 'phone' : field === 'email' ? 'email' : 'text';
      leg[field].forEach(function (old) {
        old = String(old).trim();
        if (old && old !== nv && (kind !== 'phone' || digits(old) !== digits(nv))) out.push({ kind: kind, old: old, nv: nv });
      });
    });
    return out;
  }
  function replaceText(t, ps) {
    ps.forEach(function (p) {
      if (p.kind === 'phone') { var re = phoneRe(p.old); if (re) t = t.replace(re, function (m, a) { return a + p.nv; }); }
      else if (p.kind === 'email') t = t.replace(new RegExp(esc(p.old), 'gi'), function () { return p.nv; });
      else { var w = p.old.split(/\s+/).filter(Boolean).map(esc); if (w.length) t = t.replace(new RegExp(w.join('\\s+'), 'gi'), function () { return p.nv; }); }
    });
    return t;
  }
  function fixHref(a, ps) {
    var h = a.getAttribute('href'); if (!h) return;
    for (var i = 0; i < ps.length; i++) {
      var p = ps[i], m;
      if (p.kind === 'phone') {
        if ((m = /^(tel:)(.*)$/i.exec(h)) && samePhone(decodeURIComponent(m[2]), p.old)) { a.setAttribute('href', m[1] + (p.nv.indexOf('+') > -1 ? '+' : '') + digits(p.nv)); return; }
        if ((m = /^(https?:\/\/(?:wa\.me\/|api\.whatsapp\.com\/send\?phone=|wa\.me\/send\?phone=))([\d+\s%\-]+)(.*)$/i.exec(h)) && samePhone(decodeURIComponent(m[2]), p.old)) { a.setAttribute('href', m[1] + digits(p.nv) + m[3]); return; }
      } else if (p.kind === 'email' && (m = /^(mailto:)([^?]*)(.*)$/i.exec(h)) && decodeURIComponent(m[2]).toLowerCase() === p.old.toLowerCase()) { a.setAttribute('href', m[1] + p.nv + m[3]); return; }
    }
  }
  function linkFor(key, v) {
    if (key === 'phone' || key === 'phone2') return 'tel:' + (v.indexOf('+') > -1 ? '+' : '') + digits(v);
    if (key === 'whatsapp') return 'https://wa.me/' + digits(v);
    if (key === 'email') return 'mailto:' + v;
    return /^https?:\/\//i.test(v) ? v : null;
  }
  function apply(c) {
    var f = c.f || {}, custom = c.custom || {};
    var val = function (k) { return f[k] != null ? f[k] : custom[k]; };
    document.querySelectorAll('[data-sg-contact]').forEach(function (el) { var v = val(el.getAttribute('data-sg-contact')); if (v) el.textContent = v; });
    document.querySelectorAll('[data-sg-contact-link]').forEach(function (el) {
      var k = el.getAttribute('data-sg-contact-link'), v = val(k); if (!v) return;
      var l = linkFor(k, v); if (l) el.setAttribute('href', l);
      if (!el.textContent.trim()) el.textContent = v;
    });
    var ps = pairs(c); if (!ps.length) return;
    var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode: function (n) { var p = n.parentNode && n.parentNode.nodeName; return /^(SCRIPT|STYLE|TEXTAREA|NOSCRIPT)$/.test(p) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT; }
    });
    var nodes = [], n; while ((n = walker.nextNode())) nodes.push(n);
    nodes.forEach(function (t) { var nv = replaceText(t.nodeValue, ps); if (nv !== t.nodeValue) t.nodeValue = nv; });
    document.querySelectorAll('a[href]').forEach(function (a) { fixHref(a, ps); });
  }
  function run() {
    try {
      fetch(base + 'contact.php', { credentials: 'omit' }).then(function (r) { return r.ok ? r.json() : null; }).then(function (c) { if (c && c.v) { try { apply(c); } catch (e) {} } }).catch(function () {});
    } catch (e) {}
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run); else run();
})();
