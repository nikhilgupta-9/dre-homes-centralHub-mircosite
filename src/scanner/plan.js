'use strict';

const R = (code, level, extra) => Object.assign({ code, level }, extra || {});

/**
 * Decide what can be done for one form.
 *   auto   : safe to protect without a human
 *   review : probably fine, a person should look first
 *   manual : cannot be protected automatically (reason says why)
 *   skip   : not an enquiry form (login, search ...)
 *   done   : SpamGuard already installed on this form
 * `actions` is the machine-readable to-do list for the injector (Phase 3).
 */
function planForm(form, ctx) {
  const reasons = [];
  const actions = [];
  const done = (status) => ({ status, reasons, actions });

  if (!form.protectable) {
    reasons.push(R('not-enquiry', 'info', { kind: form.kind }));
    return done('skip');
  }
  if (ctx.platform.cms) {
    reasons.push(R('cms', 'warn', { cms: ctx.platform.name }));
    return done('manual');
  }
  if (form.generatedByPhp) {
    reasons.push(R('php-generated', 'warn'));
    return done('manual');
  }
  const a = form.action;
  if (a.type === 'external') {
    reasons.push(R('external-service', 'warn', { service: a.service || 'other website' }));
    return done('manual');
  }
  if (a.type === 'mailto') {
    reasons.push(R('mailto-form', 'warn'));
    return done('manual');
  }
  if (a.type === 'dynamic') {
    reasons.push(R('dynamic-action', 'warn'));
    return done('manual');
  }
  if (a.type === 'js' && !form.ajax) {
    reasons.push(R('js-action', 'warn'));
    return done('manual');
  }
  const h = form.handler;
  if (!h || !h.exists) {
    reasons.push(R('handler-missing', 'warn', { path: (h && h.path) || a.raw || '' }));
    return done('manual');
  }
  if (!h.isPhp) {
    reasons.push(R('handler-not-php', 'warn', { path: h.file }));
    return done('manual');
  }

  let status = 'auto';
  const downgrade = (to) => {
    if (status === 'auto' || (status === 'review' && to === 'manual')) status = to;
  };

  if (!h.capabilities.readsPost) {
    reasons.push(R('handler-no-post', 'warn', { file: h.file }));
    downgrade('review');
  }
  if (form.submitMode === 'ajax') {
    if (form.ajax && form.ajax.confidence !== 'high') {
      reasons.push(R('ajax-link-uncertain', 'warn'));
      downgrade('review');
    }
    if (!h.response.successJson && !h.response.successText) {
      reasons.push(R('ajax-response-unknown', 'warn'));
      downgrade('review');
    } else {
      reasons.push(R('ajax-response-found', 'info', { json: !!h.response.successJson }));
    }
  }
  if (ctx.handlerMixedKinds.get(h.file)) {
    reasons.push(R('shared-handler-multiple-forms', 'warn', { file: h.file }));
    downgrade('review');
  }
  if (form.existing.captcha.length || h.capabilities.verifiesCaptcha.length) {
    reasons.push(R('existing-captcha', 'info', { types: Array.from(new Set(form.existing.captcha.concat(h.capabilities.verifiesCaptcha))) }));
  }
  if (form.hasFileUpload) reasons.push(R('file-upload', 'info'));
  if (form.pagesUsing && form.pagesUsing.length) reasons.push(R('form-in-include', 'info', { pages: form.pagesUsing.length }));
  if (a.type === 'self' && form.submitMode !== 'ajax') reasons.push(R('self-post', 'info'));

  // what is still missing?
  const guard = h.capabilities.guardCalled;
  const client = form.existing.clientScript;
  if (!client) actions.push({ type: 'add-script-tag', file: form.file, afterLine: form.endLine });
  if (!guard) actions.push({ type: 'add-guard-call', file: h.file, hints: h.injection });
  const resp = {};
  if (h.response.successJson) resp.json = h.response.successJson;
  else if (h.response.successText) resp.text = h.response.successText;
  if (h.response.redirect && form.submitMode !== 'ajax') resp.redirect = h.response.redirect;
  if (Object.keys(resp).length) actions.push(Object.assign({ type: 'set-success-response', confidence: h.response.confidence }, resp));

  if (guard && client) {
    reasons.push(R('already-protected', 'info'));
    return done('done');
  }
  if (guard && !client) reasons.push(R('client-script-missing', 'info'));
  if (!guard && client) reasons.push(R('guard-missing', 'info'));
  return done(status);
}

module.exports = { planForm };
