"""SpamGuard Studio, browser edition: a tiny local web server (stdlib only).
It listens on 127.0.0.1 only, so only THIS computer can open it. Files are copied to a temp folder on this
same computer, never sent anywhere."""
import hmac
import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import service
from .hub import normalize_url

UI = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ui')
MIME = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8'}
MAX_JSON = 1024 * 1024
VERSION = '0.5.0'


class Studio(object):
    def __init__(self, home=None, docs=None, no_open=False):
        self.home = home or os.path.join(os.path.expanduser('~'), '.spamguard-studio')
        self.docs = docs or os.path.join(os.path.expanduser('~'), 'Documents')
        self.no_open = no_open
        self.token = secrets.token_hex(24)
        self.upload_root = os.path.realpath(tempfile.mkdtemp(prefix='sg-up-'))
        self.allowed = set()
        self.clients = []
        self.lock = threading.Lock()
        self.port = 0
        self.httpd = None

    # ---------------------------------------------------------------- settings
    def _sfile(self):
        return os.path.join(self.home, 'settings.json')

    def defaults(self):
        return {'outDir': os.path.join(self.docs, 'SpamGuard Results'), 'notifyEmail': '', 'quarantine': False, 'includeReview': False, 'timezone': 'Asia/Kolkata', 'hubUrl': '', 'hubToken': ''}

    def load_settings(self):
        s = self.defaults()
        try:
            with open(self._sfile(), encoding='utf-8') as f:
                s.update(json.load(f))
        except (OSError, ValueError):
            pass
        return s

    @staticmethod
    def public_settings(s):
        return {'outDir': s['outDir'], 'notifyEmail': s['notifyEmail'], 'quarantine': s['quarantine'], 'includeReview': s['includeReview'], 'timezone': s['timezone'], 'hubUrl': s['hubUrl'], 'hubTokenSet': bool(s['hubToken'])}

    def save_settings(self, s):
        d = self.defaults()
        cur = self.load_settings()
        out_dir = s.get('outDir')
        mail = s.get('notifyEmail')
        tz = s.get('timezone')
        clean = {
            'outDir': out_dir.strip() if isinstance(out_dir, str) and os.path.isabs(out_dir.strip()) else d['outDir'],
            'notifyEmail': mail.strip() if isinstance(mail, str) and re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', mail.strip()) else '',
            'quarantine': bool(s.get('quarantine')),
            'includeReview': bool(s.get('includeReview')),
            'timezone': tz if isinstance(tz, str) and re.match(r'^[A-Za-z_]+/[A-Za-z_\-+0-9]+$', tz) else d['timezone'],
            'hubUrl': '', 'hubToken': '',
        }
        url = s.get('hubUrl')
        url = url.strip() if isinstance(url, str) else ''
        if url:
            clean['hubUrl'] = normalize_url(url)
            typed = s.get('hubToken')
            typed = typed.strip() if isinstance(typed, str) else ''
            if typed and not re.match(r'^[A-Za-z0-9_-]{20,80}$', typed):
                raise ValueError('Hub token galat lag raha hai. Hub ke Settings se poora copy karo.')
            clean['hubToken'] = typed or cur['hubToken']
        os.makedirs(self.home, exist_ok=True)
        fd = os.open(self._sfile(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(clean, f, indent=2)
        return self.public_settings(clean)

    def fresh_run_dir(self, base):
        stamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
        d = os.path.join(base, stamp)
        i = 2
        while os.path.exists(d):
            d = os.path.join(base, '%s-%d' % (stamp, i))
            i += 1
        return d

    # ---------------------------------------------------------------- safety helpers
    def in_uploads(self, p):
        try:
            a = os.path.realpath(str(p or ''))
        except (OSError, ValueError):
            return None
        return a if a.startswith(self.upload_root + os.sep) else None

    def uploaded_only(self, arr):
        return [x for x in (self.in_uploads(p) for p in arr) if x] if isinstance(arr, list) else []

    def clean_drop(self, drop):
        if not isinstance(drop, dict):
            raise ValueError('bad request')
        out = dict(drop)
        if out.get('sqlFiles'):
            out['sqlFiles'] = self.uploaded_only(out['sqlFiles'])
        kind = out.get('kind')
        if kind == 'site':
            if not self.in_uploads(out.get('input')):
                raise ValueError('bad request')
        elif kind == 'bulk':
            if out.get('parent') and not self.in_uploads(out['parent']):
                raise ValueError('bad request')
            for it in out.get('items') or []:
                if not self.in_uploads(it.get('input')):
                    raise ValueError('bad request')
            if not out.get('parent') and not out.get('items'):
                raise ValueError('bad request')
        else:
            raise ValueError('bad request')
        return out

    def broadcast(self, obj):
        line = ('data: ' + json.dumps(obj) + '\n\n').encode('utf-8')
        with self.lock:
            for q in self.clients:
                q.put(line)

    # ---------------------------------------------------------------- API
    def api(self, name, b):
        if name == 'version':
            return VERSION
        if name == 'settings/get':
            return self.public_settings(self.load_settings())
        if name == 'settings/set':
            return self.save_settings(b or {})
        if name == 'classify':
            return service.classify_drop(self.uploaded_only((b or {}).get('paths')))
        if name == 'scan':
            drop = self.clean_drop(b)
            if drop['kind'] == 'site':
                return service.scan(drop['input'], drop.get('sqlFiles') or [])
            return service.scan_bulk(drop, lambda p: self.broadcast(p))
        if name == 'protect':
            drop = self.clean_drop(b)
            s = self.load_settings()
            o = {'outDir': self.fresh_run_dir(s['outDir']), 'notifyEmail': s['notifyEmail'], 'quarantine': s['quarantine'], 'includeReview': s['includeReview'], 'timezone': s['timezone'], 'sqlFiles': drop.get('sqlFiles') or [],
                 'hub': {'url': s['hubUrl'], 'token': s['hubToken']} if s['hubUrl'] and s['hubToken'] else None}
            os.makedirs(o['outDir'], exist_ok=True)
            self.allowed.add(o['outDir'])
            if drop['kind'] == 'site':
                r = service.protect(drop['input'], o)
                outs = r['ui'].get('outputs') or {}
                if outs.get('dir'):
                    self.allowed.add(outs['dir'])
                return r
            bulk = service.protect_bulk(drop, o, lambda p: self.broadcast(p))
            res = {'outDir': o['outDir']}
            res.update(bulk)
            return res
        if name == 'reveal':
            a = os.path.abspath(str((b or {}).get('path') or ''))
            if not any(a == x or a.startswith(x + os.sep) for x in self.allowed):
                return False
            if self.no_open:
                return True
            try:
                if sys.platform == 'darwin':
                    subprocess.Popen(['open', '-R', a])
                elif sys.platform.startswith('win'):
                    subprocess.Popen(['explorer', '/select,', a])
                else:
                    subprocess.Popen(['xdg-open', a if os.path.isdir(a) else os.path.dirname(a)])
            except OSError:
                pass
            return True
        if name == 'readReport':
            a = os.path.abspath(str((b or {}).get('path') or ''))
            if not any(a.startswith(x + os.sep) for x in self.allowed) or not a.endswith('report.txt'):
                raise ValueError('not allowed')
            with open(a, encoding='utf-8') as f:
                return f.read()
        raise KeyError(name)

    def upload(self, h, q):
        batch = (q.get('batch') or [''])[0]
        rel = (q.get('rel') or [''])[0]
        if not re.match(r'^[a-f0-9]{16}$', batch):
            return h.send_json(400, {'error': 'bad batch'})
        parts = [p for p in re.split(r'[\\/]+', rel) if p]
        if not parts or any(p in ('.', '..') or '\0' in p for p in parts):
            return h.send_json(400, {'error': 'bad path'})
        d = os.path.join(self.upload_root, batch)
        f = os.path.join(d, *parts)
        if not os.path.realpath(f).startswith(os.path.realpath(d) + os.sep):
            return h.send_json(400, {'error': 'bad path'})
        os.makedirs(os.path.dirname(f), exist_ok=True)
        left = int(h.headers.get('Content-Length') or 0)
        with open(f, 'wb') as out:
            while left > 0:
                chunk = h.rfile.read(min(left, 1 << 20))
                if not chunk:
                    break
                out.write(chunk)
                left -= len(chunk)
        h.send_json(200, {'root': os.path.realpath(d)})

    # ---------------------------------------------------------------- server
    def listen(self, want=4780):
        studio = self

        class H(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *a):
                pass

            def send_json(self, code, obj):
                body = json.dumps(obj).encode('utf-8')
                self.send_response(code)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def plain(self, code, text):
                body = text.encode('utf-8')
                self.send_response(code)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def host_ok(self):
                h = (self.headers.get('Host') or '').lower()
                return h in ('127.0.0.1:%d' % studio.port, 'localhost:%d' % studio.port)

            def token_ok(self, u):
                given = self.headers.get('X-SG-Token') or (parse_qs(u.query).get('t') or [''])[0]
                return hmac.compare_digest(given.encode(), studio.token.encode())

            def do_GET(self):
                self.route('GET')

            def do_POST(self):
                self.route('POST')

            def route(self, method):
                try:
                    self._route(method)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def _route(self, method):
                if not self.host_ok():
                    return self.plain(403, 'forbidden')
                u = urlparse(self.path)
                if method == 'GET' and not u.path.startswith('/api/'):
                    name = 'index.html' if u.path == '/' else u.path[1:]
                    if name not in ('index.html', 'app.js', 'bridge.js', 'style.css'):
                        return self.plain(404, 'not found')
                    with open(os.path.join(UI, name), encoding='utf-8') as f:
                        body = f.read()
                    if name == 'index.html':
                        body = body.replace('</head>', '<meta name="sg-token" content="%s">\n</head>' % studio.token)
                    data = body.encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', MIME[os.path.splitext(name)[1]])
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.send_header('X-Frame-Options', 'DENY')
                    self.send_header('Referrer-Policy', 'no-referrer')
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                if not self.token_ok(u):
                    return self.send_json(403, {'error': 'forbidden'})
                if method == 'GET' and u.path == '/api/events':
                    return self.events()
                if method != 'POST':
                    return self.send_json(405, {'error': 'method'})
                if u.path == '/api/upload':
                    return studio.upload(self, parse_qs(u.query))
                name = u.path[len('/api/'):]
                n = int(self.headers.get('Content-Length') or 0)
                if n > MAX_JSON:
                    return self.send_json(413, {'error': 'too big'})
                raw = self.rfile.read(n) if n else b''
                try:
                    body = json.loads(raw.decode('utf-8')) if raw else {}
                    data = studio.api(name, body)
                    self.send_json(200, {'ok': True, 'data': data})
                except KeyError:
                    self.send_json(404, {'error': 'unknown'})
                except Exception as e:  # shown to the user as a readable message
                    self.send_json(200, {'ok': False, 'error': str(e) or e.__class__.__name__})

            def events(self):
                q = queue.Queue()
                with studio.lock:
                    studio.clients.append(q)
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.close_connection = True
                try:
                    self.wfile.write(b': hi\n\n')
                    self.wfile.flush()
                    while True:
                        try:
                            line = q.get(timeout=15)
                        except queue.Empty:
                            line = b': ping\n\n'
                        self.wfile.write(line)
                        self.wfile.flush()
                except (OSError, ValueError):
                    pass
                finally:
                    with studio.lock:
                        if q in studio.clients:
                            studio.clients.remove(q)

        class S(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = False

        port = want
        while True:
            try:
                self.httpd = S(('127.0.0.1', port), H)
                break
            except OSError:
                if want == 0 or port >= want + 20:
                    raise
                port += 1
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return 'http://127.0.0.1:%d/' % self.port

    def close(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        shutil.rmtree(self.upload_root, ignore_errors=True)
