"""Decide what can be done for one form (port of plan.js).

  auto   : safe to protect without a human
  review : probably fine, a person should look first
  manual : cannot be protected automatically (reason says why)
  skip   : not an enquiry form (login, search ...)
  done   : SpamGuard already installed on this form
`actions` is the machine-readable to-do list for the injector.
"""
from .util import uniq


def _r(code, level, **extra):
    d = {'code': code, 'level': level}
    d.update(extra)
    return d


def plan_form(form, ctx):
    reasons = []
    actions = []

    def done(status):
        return {'status': status, 'reasons': reasons, 'actions': actions}

    if not form['protectable']:
        reasons.append(_r('not-enquiry', 'info', kind=form['kind']))
        return done('skip')
    if ctx['platform']['cms']:
        reasons.append(_r('cms', 'warn', cms=ctx['platform']['name']))
        return done('manual')
    if form['generatedByPhp']:
        reasons.append(_r('php-generated', 'warn'))
        return done('manual')
    a = form['action']
    if a['type'] == 'external':
        reasons.append(_r('external-service', 'warn', service=a['service'] or 'other website'))
        return done('manual')
    if a['type'] == 'mailto':
        reasons.append(_r('mailto-form', 'warn'))
        return done('manual')
    if a['type'] == 'dynamic':
        reasons.append(_r('dynamic-action', 'warn'))
        return done('manual')
    if a['type'] == 'js' and not form['ajax']:
        reasons.append(_r('js-action', 'warn'))
        return done('manual')
    h = form['handler']
    if not h or not h['exists']:
        reasons.append(_r('handler-missing', 'warn', path=(h and h['path']) or a['raw'] or ''))
        return done('manual')
    if not h['isPhp']:
        reasons.append(_r('handler-not-php', 'warn', path=h['file']))
        return done('manual')

    state = {'status': 'auto'}

    def downgrade(to):
        if state['status'] == 'auto' or (state['status'] == 'review' and to == 'manual'):
            state['status'] = to

    caps = h['capabilities']
    if not caps['readsPost']:
        reasons.append(_r('handler-no-post', 'warn', file=h['file']))
        downgrade('review')
    if form['submitMode'] == 'ajax':
        if form['ajax'] and form['ajax']['confidence'] != 'high':
            reasons.append(_r('ajax-link-uncertain', 'warn'))
            downgrade('review')
        if not h['response']['successJson'] and not h['response']['successText']:
            reasons.append(_r('ajax-response-unknown', 'warn'))
            downgrade('review')
        else:
            reasons.append(_r('ajax-response-found', 'info', json=bool(h['response']['successJson'])))
    if ctx['handlerMixedKinds'].get(h['file']):
        reasons.append(_r('shared-handler-multiple-forms', 'warn', file=h['file']))
        downgrade('review')
    if form['existing']['captcha'] or caps['verifiesCaptcha']:
        reasons.append(_r('existing-captcha', 'info', types=uniq(list(form['existing']['captcha']) + list(caps['verifiesCaptcha']))))
    if form.get('hasFileUpload'):
        reasons.append(_r('file-upload', 'info'))
    if form.get('pagesUsing'):
        reasons.append(_r('form-in-include', 'info', pages=len(form['pagesUsing'])))
    if a['type'] == 'self' and form['submitMode'] != 'ajax':
        reasons.append(_r('self-post', 'info'))

    # what is still missing?
    guard = caps['guardCalled']
    client = form['existing']['clientScript']
    if not client:
        actions.append({'type': 'add-script-tag', 'file': form['file'], 'afterLine': form['endLine']})
    if not guard:
        actions.append({'type': 'add-guard-call', 'file': h['file'], 'hints': h['injection']})
    resp = {}
    if h['response']['successJson']:
        resp['json'] = h['response']['successJson']
    elif h['response']['successText']:
        resp['text'] = h['response']['successText']
    if h['response']['redirect'] and form['submitMode'] != 'ajax':
        resp['redirect'] = h['response']['redirect']
    if resp:
        act = {'type': 'set-success-response', 'confidence': h['response']['confidence']}
        act.update(resp)
        actions.append(act)

    if guard and client:
        reasons.append(_r('already-protected', 'info'))
        return done('done')
    if guard and not client:
        reasons.append(_r('client-script-missing', 'info'))
    if not guard and client:
        reasons.append(_r('guard-missing', 'info'))
    return done(state['status'])
