"""Bounded local proxy and Intruder for the manual HTTP workbench."""

import hashlib
import http.client
import ipaddress
import json
import re
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import web_workbench_api as wb
from rg_evidence.scope import parse_target


MAX_PAYLOADS = 12
MAX_POSITIONS = 4
MARKERS = tuple('{{%d}}' % index for index in range(1, MAX_POSITIONS + 1))
PENDING = {}
RUNS = {}
APPROVALS = {}
INTERCEPT = False
PROXY_PORT = None
SERIAL = threading.Lock()


def reset():
    global INTERCEPT
    with wb.LOCK:
        INTERCEPT = False
        for item in PENDING.values():
            item['decision'] = 'drop'
            item['event'].set()
        PENDING.clear()
        APPROVALS.clear()
        RUNS.clear()


def state():
    with wb.LOCK:
        return {'proxy_port': PROXY_PORT, 'intercept': INTERCEPT,
                'pending': [{'id': key, 'method': value['request']['method'],
                             'url': value['request']['url'],
                             'request': value['request'],
                             'request_preview': wb._request_lines(value['request']),
                             'created_at': value['created_at']}
                            for key, value in PENDING.items()],
                'runs': [{key: value[key] for key in ('id', 'status', 'mode', 'total', 'results')}
                         for value in RUNS.values()]}


def set_intercept(data):
    global INTERCEPT
    if not isinstance(data, dict) or set(data) != {'enabled'} or not isinstance(data['enabled'], bool):
        raise ValueError('enabled must be true or false')
    with wb.LOCK:
        INTERCEPT = data['enabled']
        if not INTERCEPT:
            for item in PENDING.values():
                item['decision'] = 'drop'
                item['event'].set()
    return state()


def decide(data):
    if not isinstance(data, dict) or set(data) - {'id', 'action', 'request'}:
        raise ValueError('Invalid intercept decision')
    if data.get('action') not in ('forward', 'drop'):
        raise ValueError('Choose forward or drop')
    with wb.LOCK:
        item = PENDING.get(data.get('id'))
        project = dict(wb.PROJECT) if wb.PROJECT else None
    if not item or not project:
        raise ValueError('Pending request no longer exists')
    request = item['request']
    if data['action'] == 'forward' and 'request' in data:
        request = wb._normalized_request(data['request'], project)
    with wb.LOCK:
        if PENDING.get(data['id']) is not item or item['event'].is_set():
            raise ValueError('Pending request already decided')
        item['request'] = request
        item['decision'] = data['action']
        item['event'].set()
    return {'id': data['id'], 'action': data['action']}


def _template(data):
    if not isinstance(data, dict) or set(data) - {'mode', 'request', 'payloads'}:
        raise ValueError('Intruder requires mode, request, and payloads')
    mode = data.get('mode')
    if mode not in ('sniper', 'battering_ram'):
        raise ValueError('Choose Sniper or Battering ram')
    payloads = data.get('payloads')
    if not isinstance(payloads, list) or not (1 <= len(payloads) <= MAX_PAYLOADS):
        raise ValueError('Use 1 to 12 payloads')
    if any(not isinstance(p, str) or not p or len(p.encode('utf-8')) > 256 or '\n' in p or '\r' in p for p in payloads):
        raise ValueError('Payloads must be nonempty single lines of at most 256 bytes')
    raw = data.get('request')
    if not isinstance(raw, dict):
        raise ValueError('Request template required')
    if not isinstance(raw.get('headers', {}), dict):
        raise ValueError('Template headers must be an object')
    with wb.LOCK:
        project = dict(wb.PROJECT) if wb.PROJECT else None
    if not project:
        raise ValueError('Set the authorized project scope first')
    # Validate a fully substituted request before accepting the template.
    values = [str(raw.get('url', '')), str(raw.get('body', ''))] + [str(value) for value in raw.get('headers', {}).values()]
    if any(marker not in MARKERS for value in values for marker in re.findall(r'\{\{\d+\}\}', value)):
        raise ValueError('Only position markers {{1}} through {{4}} are supported')
    positions = [marker for marker in MARKERS if any(marker in value for value in values)]
    if not positions:
        raise ValueError('Add a position marker such as {{1}} to URL, header value, or body')
    sample = _replace(raw, positions, positions[0], payloads[0], mode)
    wb._normalized_request(sample, project)
    total = len(payloads) * (len(positions) if mode == 'sniper' else 1)
    return project, raw, mode, payloads, positions, total


def _replace(raw, positions, active, payload, mode):
    def subst(value):
        output = value
        for marker in positions:
            output = output.replace(marker, payload if mode == 'battering_ram' or marker == active else '')
        return output
    return {'method': raw.get('method', 'GET'), 'url': subst(raw.get('url', '')),
            'headers': {key: subst(value) for key, value in raw.get('headers', {}).items()},
            'body': subst(raw.get('body', ''))}


def intruder_preview(data):
    project, raw, mode, payloads, positions, total = _template(data)
    if total > 24:
        raise ValueError('At most 24 requests per run')
    digest = hashlib.sha256(json.dumps({'data': data, 'project': project['created_at']}, sort_keys=True).encode()).hexdigest()
    token = wb.secrets.token_urlsafe(24)
    with wb.LOCK:
        APPROVALS.clear()
        APPROVALS[token] = (digest, time.monotonic() + 300)
    first = wb._normalized_request(_replace(raw, positions, positions[0], payloads[0], mode), project)
    return {'approval_token': token, 'mode': mode, 'positions': positions, 'payload_count': len(payloads),
            'request_count': total, 'first_request': wb._request_lines(first),
            'note': 'Sequential requests, at most one per second; no automatic vulnerability verdict.'}


def intruder_start(data):
    if not isinstance(data, dict) or 'approval_token' not in data:
        raise ValueError('Preview approval is required')
    token = data['approval_token']
    payload = {key: value for key, value in data.items() if key != 'approval_token'}
    project, raw, mode, payloads, positions, total = _template(payload)
    digest = hashlib.sha256(json.dumps({'data': payload, 'project': project['created_at']}, sort_keys=True).encode()).hexdigest()
    with wb.LOCK:
        approved = APPROVALS.pop(token, None)
        if not approved or approved[1] < time.monotonic() or approved[0] != digest:
            raise ValueError('Intruder request changed or approval expired; preview again')
        if any(run['status'] == 'running' for run in RUNS.values()):
            raise ValueError('An Intruder run is already active')
        identifier = wb.secrets.token_urlsafe(12)
        run = {'id': identifier, 'status': 'running', 'mode': mode, 'total': total, 'results': [],
               'project_created_at': project['created_at'], 'cancel': False}
        RUNS[identifier] = run
    threading.Thread(target=_run_intruder, args=(run, project, raw, mode, payloads, positions), daemon=True).start()
    return {'id': identifier, 'status': 'running', 'total': total}


def _run_intruder(run, project, raw, mode, payloads, positions):
    try:
        combinations = [(marker, payload) for marker in (positions if mode == 'sniper' else positions[:1]) for payload in payloads]
        for index, (marker, payload) in enumerate(combinations):
            with wb.LOCK:
                if run['cancel'] or not wb.PROJECT or wb.PROJECT['created_at'] != project['created_at']:
                    run['status'] = 'cancelled'
                    return
            if index:
                time.sleep(1)
            try:
                request = wb._normalized_request(_replace(raw, positions, marker, payload, mode), project)
                with SERIAL:
                    result = wb._perform(request, 'intruder')
                row = {'position': marker if mode == 'sniper' else 'all', 'payload': payload,
                       'status': result['status'], 'elapsed_ms': result['elapsed_ms'],
                       'body_sha256': result['body_sha256'], 'body_bytes': result['body_bytes'],
                       'body_truncated': result['body_truncated'],
                       'url': result['url']}
            except Exception as exc:
                row = {'position': marker if mode == 'sniper' else 'all', 'payload': payload, 'error': str(exc)}
            with wb.LOCK:
                run['results'].append(row)
        with wb.LOCK:
            run['status'] = 'complete'
    except Exception as exc:
        with wb.LOCK:
            run['status'] = 'error'
            run['results'].append({'error': str(exc)})


def intruder_cancel(data):
    if not isinstance(data, dict) or set(data) != {'id'}:
        raise ValueError('Run id required')
    with wb.LOCK:
        run = RUNS.get(data['id'])
        if not run:
            raise ValueError('Unknown run')
        run['cancel'] = True
    return {'id': data['id'], 'status': 'cancelling'}


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    timeout = 30

    def log_message(self, *_):
        pass

    def _error(self, code, message):
        data = message.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def _proxy_request(self):
        try:
            if not ipaddress.ip_address(self.client_address[0]).is_loopback:
                raise ValueError('Loopback clients only')
            if self.headers.get('Transfer-Encoding'):
                raise ValueError('Chunked request bodies are unsupported')
            length = int(self.headers.get('Content-Length', '0'))
            if length < 0 or length > wb.MAX_BODY:
                raise ValueError('Request body exceeds 64 KiB')
            raw_body = self.rfile.read(length).decode('utf-8') if length else ''
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in wb.FORBIDDEN_HEADERS and key.lower() not in ('accept-encoding',)}
            with wb.LOCK:
                project = dict(wb.PROJECT) if wb.PROJECT else None
                intercept = INTERCEPT
            if not project:
                raise ValueError('Set project scope in the dashboard first')
            if not self.path.startswith(('http://', 'https://')):
                raise ValueError('Use this listener as a configured forward proxy')
            request = wb._normalized_request({'method': self.command, 'url': self.path,
                                              'headers': headers, 'body': raw_body}, project)
            if intercept:
                identifier = wb.secrets.token_urlsafe(9)
                item = {'request': request, 'event': threading.Event(), 'decision': None, 'created_at': wb._utc()}
                with wb.LOCK:
                    PENDING[identifier] = item
                item['event'].wait(30)
                with wb.LOCK:
                    PENDING.pop(identifier, None)
                if item['decision'] != 'forward':
                    self._error(403, 'Request dropped or intercept timed out')
                    return
                request = item['request']
            result, raw, raw_headers = wb._exchange(request, 'proxy')
            if result['body_truncated']:
                self._error(502, 'Proxy response exceeds the 64 KiB safety limit')
                return
            self.send_response_only(result['status'], result['reason'])
            for key, value in raw_headers:
                if key.lower() not in ('content-length', 'transfer-encoding', 'connection'):
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Connection', 'close')
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(raw)
            self.close_connection = True
        except (ValueError, OSError, http.client.HTTPException, UnicodeError) as exc:
            self._error(400, str(exc))

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _proxy_request

    def do_CONNECT(self):
        try:
            with wb.LOCK:
                project = dict(wb.PROJECT) if wb.PROJECT else None
            if not project or project['path_prefix'] != '/':
                raise ValueError('HTTPS tunnel requires an origin-root scope')
            target = parse_target('https://' + self.path + '/')
            if not wb._in_scope(target, project):
                raise ValueError('CONNECT target is outside project scope')
            upstream = socket.create_connection((wb._resolve(target[1], target[2]), target[2]), timeout=10)
            with upstream:
                self.connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                with wb.LOCK:
                    wb.HISTORY.insert(0, {'method': 'CONNECT', 'url': target[4], 'status': 200,
                                          'elapsed_ms': 0,
                                          'observations': ['TLS tunnel metadata only; contents not inspected.'],
                                          'checked_at': wb._utc(), 'source': 'proxy'})
                    del wb.HISTORY[wb.MAX_HISTORY:]
                self.connection.settimeout(30)
                upstream.settimeout(30)
                start = time.monotonic()
                while time.monotonic() - start < 120:
                    readable, _, _ = select.select([self.connection, upstream], [], [], 30)
                    if not readable:
                        break
                    for source in readable:
                        chunk = source.recv(65536)
                        if not chunk:
                            return
                        (upstream if source is self.connection else self.connection).sendall(chunk)
        except (ValueError, OSError) as exc:
            self._error(403, str(exc))
        finally:
            self.close_connection = True


def start_proxy(port=0):
    global PROXY_PORT
    server = ThreadingHTTPServer(('127.0.0.1', port), ProxyHandler)
    server.daemon_threads = True
    PROXY_PORT = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return PROXY_PORT


ROUTES = {'/api/workbench/advanced/intercept': set_intercept,
          '/api/workbench/advanced/decision': decide,
          '/api/workbench/advanced/intruder/preview': intruder_preview,
          '/api/workbench/advanced/intruder/start': intruder_start,
          '/api/workbench/advanced/intruder/cancel': intruder_cancel}


def handle(handler, path, method):
    if path == '/api/workbench/advanced/state' and method == 'GET':
        handler._send_json(200, state())
    elif path in ROUTES and method == 'POST':
        if 'application/json' not in handler.headers.get('Content-Type', '').lower():
            handler._send_json(415, {'error': 'JSON required'})
        else:
            data = handler._read_json_body()
            if data is not None:
                handler._send_json(200, ROUTES[path](data))
    else:
        handler._send_json(404, {'error': 'Unknown workbench route'})
