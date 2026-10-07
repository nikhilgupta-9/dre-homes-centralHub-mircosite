"""Talks to the central hub from the desktop app / CLI (port of src/hub.js).

Only creates sites; it can never read leads.  stdlib only (urllib), Python 3.9 compatible.
"""
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

_JS_WS = '\t\n\x0b\x0c\r \xa0﻿                　'

MSG_BAD_URL = 'Hub ka address galat hai. Example: https://hub.example.com'
MSG_NEED_HTTPS = 'Hub ka address https:// se shuru hona chahiye (SSL zaroori hai).'
MSG_NO_CREDS = 'Hub ke address mein username/password mat daalo.'
MSG_BAD_TOKEN = 'Hub ka token galat hai (hub ke Settings mein se copy karo).'

_DEFAULT_PORT = {'http': 80, 'https': 443}


def _js_trim(s):
    return str(s).strip(_JS_WS)


def normalize_url(u):
    """Return scheme://host[:port]/path without trailing slash or /index.php|install.php|login.php."""
    raw = _js_trim(u)
    # WHATWG URL parsing drops tabs/newlines anywhere in the input
    raw = re.sub(r'[\t\n\r]', '', raw)
    try:
        parts = urllib.parse.urlsplit(raw)
        scheme = parts.scheme.lower()
        if not scheme:
            raise ValueError('no scheme')
        host = parts.hostname
        port = parts.port  # may raise ValueError
        username = parts.username
        password = parts.password
        netloc = parts.netloc
    except ValueError:
        raise ValueError(MSG_BAD_URL)
    if scheme in ('http', 'https'):
        if not host:
            raise ValueError(MSG_BAD_URL)
    else:
        raise ValueError(MSG_NEED_HTTPS)
    hostname = host.lower()
    if ':' in hostname:  # IPv6 literal: URL.hostname keeps the brackets
        hostname = '[' + hostname + ']'
    local = hostname in ('127.0.0.1', 'localhost', '[::1]')
    if scheme != 'https' and not (scheme == 'http' and local):
        raise ValueError(MSG_NEED_HTTPS)
    if username or password:
        raise ValueError(MSG_NO_CREDS)
    origin = scheme + '://' + hostname
    if port is not None and port != _DEFAULT_PORT[scheme]:
        origin += ':' + str(port)
    path = parts.path or '/'
    # resolve "." and ".." segments like URL.pathname does
    segs = []
    for seg in path.split('/')[1:]:
        if seg == '..':
            if segs:
                segs.pop()
        elif seg != '.':
            segs.append(seg)
    path = '/' + '/'.join(segs)
    full = re.sub(r'/+$', '', origin + path)
    return re.sub(r'/(index|install|login)\.php$', '', full)


_RE_DOMAIN = re.compile(r'^(?:www\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\Z', re.I)


def looks_like_domain(s):
    return bool(_RE_DOMAIN.match(str(s)))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError('redirect not allowed')


_RE_TOKEN = re.compile(r'^[A-Za-z0-9_-]{20,80}\Z')


def provision_site(hub, name, timeout=15):
    """Register a site at the hub.

    hub = {'url': ..., 'token': ...}.  Returns {'site_id', 'site_key', 'secret', 'hub_url'}; raises Exception(message).
    """
    url = hub.get('url') if isinstance(hub, dict) else getattr(hub, 'url', None)
    token = hub.get('token') if isinstance(hub, dict) else getattr(hub, 'token', None)
    base = normalize_url(url)
    tok = _js_trim(token or '')
    if not _RE_TOKEN.match(_js_trim(token or '')):
        raise ValueError(MSG_BAD_TOKEN)
    name = str(name)
    body = {'name': name[:190], 'ref': 'studio:' + name[:150]}
    if looks_like_domain(name):
        body['domain'] = name
    data = json.dumps(body, separators=(',', ':')).encode('utf-8')
    handlers = [_NoRedirect()]
    host = urllib.parse.urlsplit(base).hostname or ''
    if host in ('127.0.0.1', 'localhost', '::1'):
        handlers.append(urllib.request.ProxyHandler({}))  # never send local traffic through a proxy
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(base + '/api/provision.php', data=data, method='POST', headers={
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + tok,
    })
    status = None
    raw = b''
    try:
        with opener.open(req, timeout=timeout) as res:
            status = res.status
            raw = res.read()
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            raw = e.read()
        except Exception:
            raw = b''
    except Exception as e:
        timed_out = isinstance(e, (socket.timeout, TimeoutError)) or isinstance(getattr(e, 'reason', None), (socket.timeout, TimeoutError))
        raise Exception('Hub se connect nahi hua (' + ('der lag gayi' if timed_out else 'internet/address check karo') + ').')
    if status == 401:
        raise Exception('Hub ne token nahi manaa. Hub ke Settings se naya token lekar yahan daalo.')
    if status == 429:
        raise Exception('Hub keh raha hai thoda ruko (bahut requests). Thodi der baad try karo.')
    j = None
    try:
        j = json.loads(raw.decode('utf-8'))
    except Exception:
        j = None
    ok = status is not None and 200 <= status < 300
    if not ok or not isinstance(j, dict) or not j.get('ok') or not j.get('site_key') or not j.get('secret'):
        raise Exception('Hub se galat jawab aaya (status ' + str(status) + ').')
    return {'site_id': j.get('site_id'), 'site_key': j['site_key'], 'secret': j['secret'], 'hub_url': base}
