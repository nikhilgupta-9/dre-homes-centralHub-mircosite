'use strict';
const cheerio = require('cheerio');

const CAPTCHA_HINTS = [
  [/google\.com\/recaptcha|g-recaptcha/i, 'recaptcha'],
  [/hcaptcha\.com|h-captcha/i, 'hcaptcha'],
  [/challenges\.cloudflare\.com\/turnstile|cf-turnstile/i, 'turnstile'],
];

/** Third-party form services: the data never touches our PHP, so server-side protection is impossible. */
const EXTERNAL_SERVICES = [
  [/formspree\.io/i, 'Formspree'],
  [/docs\.google\.com\/forms|forms\.gle/i, 'Google Forms'],
  [/formsubmit\.co/i, 'FormSubmit'],
  [/getform\.io/i, 'Getform'],
  [/web3forms\.com/i, 'Web3Forms'],
  [/list-manage\.com|mailchimp/i, 'Mailchimp'],
  [/hsforms\.com|hubspot/i, 'HubSpot'],
  [/hooks\.zapier\.com/i, 'Zapier'],
  [/formcarry\.com/i, 'Formcarry'],
  [/usebasin\.com/i, 'Basin'],
  [/sendinblue|brevo/i, 'Brevo'],
  [/typeform\.com/i, 'Typeform'],
  [/wufoo\.com/i, 'Wufoo'],
  [/jotform\.com/i, 'JotForm'],
  [/convertkit\.com/i, 'ConvertKit'],
  [/zoho\.(com|in)/i, 'Zoho'],
  [/pabbly\.com|make\.com|integromat/i, 'automation webhook'],
];

function detectCaptcha(s) {
  const out = [];
  for (const [re, name] of CAPTCHA_HINTS) if (re.test(s)) out.push(name);
  return out;
}

function externalService(url) {
  for (const [re, name] of EXTERNAL_SERVICES) if (re.test(url)) return name;
  return null;
}

const clean = (s) => String(s || '').replace(/\{\{PHP\}\}/g, '').replace(/\s+/g, ' ').trim();

/** Decide what a form is for. Only enquiry-like forms get protected. */
function classifyForm(f) {
  const types = f.fields.map((x) => x.type);
  const names = f.fields.map((x) => (x.name || '').toLowerCase());
  if (types.includes('password')) return 'login';
  const vis = f.visibleFields;
  const hasEmail = types.includes('email') || names.some((n) => /mail/.test(n));
  const hasPhone = types.includes('tel') || names.some((n) => /phone|mobile|\btel\b|whatsapp|contact_?(no|num)/.test(n));
  const hasText = f.fields.some((x) => x.tag === 'textarea');
  const act = (f.attrs.action || '').toLowerCase();
  if (
    types.includes('search') ||
    /search/.test(act) ||
    (vis.length <= 2 && names.some((n) => /^(q|s|search|query|keyword|keywords)$/.test(n)) && (f.attrs.method || 'get') === 'get')
  ) {
    return 'search';
  }
  if (hasEmail || hasPhone || hasText) {
    if (vis.length === 1 && hasEmail && !hasText) return 'newsletter';
    if (vis.length === 1 && hasPhone && !hasText) return 'callback';
    return 'enquiry';
  }
  return 'other';
}

/**
 * Parse one (PHP-masked) HTML view.
 * @returns {{forms:object[], scripts:{inline:object[], src:string[]}, snapshot:object}}
 */
function parseHtml(rel, html) {
  const $ = cheerio.load(html, { sourceCodeLocationInfo: true });
  const pageCaptcha = detectCaptcha(html);
  const hasSgScript = /spamguard\.js/i.test(html);
  const forms = [];

  $('form').each((i, el) => {
    const $f = $(el);
    const loc = el.sourceCodeLocation || {};
    const attrs = {
      id: $f.attr('id') || '',
      name: $f.attr('name') || '',
      class: $f.attr('class') || '',
      action: $f.attr('action'),
      method: ($f.attr('method') || 'get').toLowerCase(),
      enctype: ($f.attr('enctype') || '').toLowerCase(),
      onsubmit: $f.attr('onsubmit') || '',
    };
    const fields = [];
    $f.find('input, textarea, select, button').each((j, fe) => {
      const t = fe.tagName.toLowerCase();
      const type = t === 'input' ? ($(fe).attr('type') || 'text').toLowerCase() : t === 'button' ? ($(fe).attr('type') || 'submit').toLowerCase() : t;
      fields.push({
        tag: t,
        type,
        name: $(fe).attr('name') || '',
        id: $(fe).attr('id') || '',
        required: $(fe).attr('required') !== undefined,
        placeholder: clean($(fe).attr('placeholder')),
      });
    });
    const visibleFields = fields.filter(
      (x) => x.name && x.tag !== 'button' && !['hidden', 'submit', 'button', 'image', 'reset'].includes(x.type)
    );
    const submit = $f.find('button[type=submit], button:not([type]), input[type=submit]').first();
    const submitText = clean(submit.is('input') ? submit.attr('value') : submit.text()).slice(0, 40);
    const inner = $.html($f);
    const form = {
      file: rel,
      line: loc.startLine || null,
      endLine: loc.endLine || null,
      attrs,
      fields,
      visibleFields: visibleFields.map((x) => x.name),
      submitText,
      captcha: Array.from(new Set(detectCaptcha(inner).concat(forms.length === 0 && pageCaptcha.length ? pageCaptcha : []))),
      hasCsrf: fields.some((x) => x.type === 'hidden' && /csrf|_token|nonce|authenticity/i.test(x.name)),
      hasHoneypot: fields.some((x) => /honey|trap|hp_?field|bot_?field/i.test(x.name)),
      hasSgFields: fields.some((x) => /^sg_/.test(x.name)),
      hasFileUpload: fields.some((x) => x.type === 'file') || attrs.enctype === 'multipart/form-data',
      dynamicAction: typeof attrs.action === 'string' && attrs.action.includes('{{PHP}}'),
    };
    form.kind = classifyForm(form);
    forms.push(form);
  });

  // scripts (inline text and src) — used to find AJAX submissions
  const inline = [];
  const src = [];
  $('script').each((i, el) => {
    const s = $(el).attr('src');
    if (s) src.push(s);
    else {
      const text = $(el).text();
      if (text && text.trim()) inline.push({ line: (el.sourceCodeLocation && el.sourceCodeLocation.startLine) || null, text });
    }
  });

  // light SEO / mobile snapshot (feeds the hub's SEO tool later)
  const meta = (n) => {
    const m = $('meta').filter((k, e) => (e.attribs.name || '').toLowerCase() === n || (e.attribs.property || '').toLowerCase() === n);
    return m.length ? clean(m.first().attr('content')) : '';
  };
  const titleRaw = $('title').first().text();
  const h1s = $('h1');
  const imgs = $('img');
  const bodyText = clean($('body').text() || '');
  const snapshot = {
    title: titleRaw.includes('{{PHP}}') ? '' : clean(titleRaw),
    titleDynamic: titleRaw.includes('{{PHP}}'),
    hasTitleTag: $('title').length > 0,
    metaDescription: meta('description'),
    h1Count: h1s.length,
    h1: h1s.length ? clean(h1s.first().text()) : '',
    canonical: clean($('link[rel=canonical]').attr('href')),
    robotsMeta: meta('robots'),
    lang: clean($('html').attr('lang')),
    viewport: meta('viewport'),
    ogTitle: meta('og:title'),
    images: { total: imgs.length, missingAlt: imgs.filter((k, e) => e.attribs.alt === undefined).length },
    hasJsonLd: $('script[type="application/ld+json"]').length > 0,
    wordCount: bodyText ? bodyText.split(' ').length : 0,
    hasHtmlShell: $('html').length > 0 && /<html\b/i.test(html),
    hasSpamGuardScript: hasSgScript,
  };
  return { forms, scripts: { inline, src }, snapshot };
}

module.exports = { parseHtml, classifyForm, externalService, detectCaptcha };
