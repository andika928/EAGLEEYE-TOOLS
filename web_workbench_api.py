"""Manual, scope-bound HTTP workbench for the local security dashboard.

Every outbound request requires an exact server-issued preview token. The
workbench does not crawl, fuzz, follow redirects, or claim vulnerabilities.
"""

from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from rg_evidence.scope import parse_target


LOCK = threading.Lock()
PROJECT = None
PREVIEWS = {}
HISTORY = []
MAX_BODY = 64 * 1024
MAX_RESPONSE = 64 * 1024
MAX_HEADERS = 30
MAX_HISTORY = 50
PREVIEW_SECONDS = 300
ALLOWED_METHODS = {'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'}
FORBIDDEN_HEADERS = {'host', 'content-length', 'transfer-encoding', 'connection',
                     'proxy-authorization', 'proxy-connection', 'upgrade', 'te', 'trailer'}
SECRET_HEADERS = {'authorization', 'cookie', 'proxy-authorization', 'set-cookie'}


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _origin(target):
    return target[:3]


def _path_only(target):
    return target[3].split('?', 1)[0]


def _in_scope(target, project):
    if _origin(target) != tuple(project['origin']):
        return False
    prefix = project['path_prefix']
    path = _path_only(target)
    return prefix == '/' or path == prefix or path.startswith(prefix.rstrip('/') + '/')


def configure(data):
    if not isinstance(data, dict) or set(data) - {'scope_url', 'authorized'}:
        raise ValueError('Only scope_url and authorized are accepted')
    if data.get('authorized') is not True:
        raise ValueError('Explicit testing authorization is required')
    raw = data.get('scope_url')
    if not isinstance(raw, str) or len(raw) > 2048 or '://' not in raw:
        raise ValueError('Enter a full HTTP(S) scope URL')
    target = parse_target(raw)
    project = {'scope_url': target[4].split('?', 1)[0], 'initial_url': target[4],
               'origin': list(_origin(target)),
               'path_prefix': _path_only(target), 'created_at': _utc()}
    with LOCK:
        global PROJECT
        PROJECT = project
        PREVIEWS.clear()
        HISTORY.clear()
    try:
        import workbench_advanced
        workbench_advanced.reset()
    except ImportError:
        pass
    return dict(project)


def _normalized_request(data, project):
    if not isinstance(data, dict) or set(data) - {'method', 'url', 'headers', 'body'}:
        raise ValueError('Request accepts method, url, headers, and body only')
    method = str(data.get('method', 'GET')).upper()
    if method not in ALLOWED_METHODS:
        raise ValueError('Unsupported HTTP method')
    raw_url = data.get('url')
    if not isinstance(raw_url, str) or len(raw_url) > 4096 or '://' not in raw_url:
        raise ValueError('Enter a full HTTP(S) request URL')
    target = parse_target(raw_url)
    if not _in_scope(target, project):
        raise ValueError('Request is outside the configured origin or path scope')
    raw_headers = data.get('headers', {})
    if not isinstance(raw_headers, dict) or len(raw_headers) > MAX_HEADERS:
        raise ValueError('Headers must be an object with at most 30 entries')
    headers = {}
    for key, value in raw_headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError('Header names and values must be text')
        if not re.fullmatch(r'[A-Za-z0-9-]+', key):
            raise ValueError('Invalid header name')
        if key.lower() in FORBIDDEN_HEADERS or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Forbidden or unsafe request header')
        if any(existing.lower() == key.lower() for existing in headers):
            raise ValueError('Duplicate request header')
        if len(key) + len(value) > 8192:
            raise ValueError('Header too large')
        headers[key] = value
    body = data.get('body', '')
    if not isinstance(body, str) or len(body.encode('utf-8')) > MAX_BODY:
        raise ValueError('Request body must be text and at most 64 KiB')
    if method in {'GET', 'HEAD'} and body:
        raise ValueError('GET and HEAD requests cannot include a body here')
    return {'method': method, 'url': target[4], 'headers': headers, 'body': body}


def _digest(request, project):
    encoded = json.dumps({'request': request, 'project': project['created_at']},
                         sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def _redact_header(name, value):
    if name.lower() == 'set-cookie':
        parts = value.split(';')
        cookie_name = parts[0].split('=', 1)[0].strip()
        allowed_attrs = {'path', 'domain', 'expires', 'max-age', 'samesite',
                         'secure', 'httponly', 'partitioned', 'priority'}
        attrs = '; '.join(part.strip() for part in parts[1:]
                          if part.strip().split('=', 1)[0].lower() in allowed_attrs)
        return cookie_name + '=[redacted]' + ('; ' + attrs if attrs else '')
    return '[redacted]' if name.lower() in SECRET_HEADERS else value


def _request_lines(request):
    target = parse_target(request['url'])
    default_port = 443 if target[0] == 'https' else 80
    authority = '[' + target[1] + ']' if ':' in target[1] else target[1]
    lines = [request['method'] + ' ' + target[3] + ' HTTP/1.1',
             'Host: ' + authority + (':' + str(target[2]) if target[2] != default_port else '')]
    lines += [key + ': ' + _redact_header(key, value) for key, value in request['headers'].items()]
    return '\n'.join(lines) + ('\n\n[body: %d UTF-8 bytes]' % len(request['body'].encode('utf-8')) if request['body'] else '')


def preview(data):
    with LOCK:
        project = dict(PROJECT) if PROJECT else None
    if not project:
        raise ValueError('Set the authorized project scope first')
    request = _normalized_request(data, project)
    token = secrets.token_urlsafe(24)
    with LOCK:
        PREVIEWS.clear()  # Only the latest proposed action can be approved.
        PREVIEWS[token] = (_digest(request, project), time.monotonic() + PREVIEW_SECONDS)
    return {'approval_token': token, 'expires_in_seconds': PREVIEW_SECONDS,
            'scope_url': project['scope_url'], 'request_preview': _request_lines(request),
            'method': request['method'], 'url': request['url'],
            'body_bytes': len(request['body'].encode('utf-8')),
            'note': 'One request only. No redirects, crawling, fuzzing, or automatic retries.'}


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, address, **kwargs):
        super().__init__(host, port, **kwargs)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, **kwargs):
        super().__init__(host, port, **kwargs)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def _resolve(host, port):
    addresses = {item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    if not addresses:
        raise ValueError('Target did not resolve')
    parsed = [ipaddress.ip_address(address) for address in addresses]
    # A host resolving to both public and internal addresses is ambiguous.
    if not all(address.is_global or address.is_loopback for address in parsed):
        raise ValueError('Private, link-local, or reserved network targets are blocked')
    if any(address.is_loopback for address in parsed) and not all(address.is_loopback for address in parsed):
        raise ValueError('Mixed loopback and public DNS answers are blocked')
    return sorted(addresses)[0]


def _observations(scheme, status, headers):
    lower = {key.lower(): value for key, value in headers if key.lower() != 'set-cookie'}
    notes = []
    if scheme == 'https' and 'strict-transport-security' not in lower:
        notes.append('HSTS was absent on this response. Informational observation.')
    if 'x-content-type-options' not in lower:
        notes.append('X-Content-Type-Options was absent on this response. Informational observation.')
    if 'text/html' in lower.get('content-type', '').lower() and 'content-security-policy' not in lower:
        notes.append('Content-Security-Policy was absent on this HTML response. Informational observation.')
    if 300 <= status < 400 and 'location' in lower:
        notes.append('Redirect destination was recorded but not requested.')
    for key, value in headers:
        if key.lower() == 'set-cookie':
            name = value.split('=', 1)[0].strip() or 'unnamed cookie'
            attrs = {part.strip().split('=', 1)[0].lower() for part in value.split(';')[1:]}
            missing = [flag for flag in ('secure', 'httponly', 'samesite') if flag not in attrs]
            if missing:
                notes.append('Cookie %s lacks %s in this response. Review its purpose and browser exposure.' % (name, ', '.join(missing)))
    return notes


def send(data):
    if not isinstance(data, dict) or set(data) - {'approval_token', 'method', 'url', 'headers', 'body'}:
        raise ValueError('Send requires the previewed request and approval_token')
    token = data.get('approval_token')
    if not isinstance(token, str):
        raise ValueError('Preview approval is required')
    with LOCK:
        project = dict(PROJECT) if PROJECT else None
    if not project:
        raise ValueError('Set the authorized project scope first')
    request = _normalized_request({key: value for key, value in data.items() if key != 'approval_token'}, project)
    with LOCK:
        approved = PREVIEWS.pop(token, None)
    if not approved or approved[1] < time.monotonic() or approved[0] != _digest(request, project):
        raise ValueError('Request changed or preview approval expired; preview it again')
    return _perform(request, 'repeater')


def _perform(request, source):
    result, _, _ = _exchange(request, source)
    return result


def _exchange(request, source):
    scheme, host, port, path, url = parse_target(request['url'])
    address = _resolve(host, port)
    headers = dict(request['headers'])
    headers.setdefault('User-Agent', 'ReconGuard-ManualWorkbench/1.0')
    headers.setdefault('Accept-Encoding', 'identity')
    body = request['body'].encode('utf-8') if request['body'] else None
    connection = (_PinnedHTTPS(host, port, address, timeout=10, context=ssl.create_default_context())
                  if scheme == 'https' else _PinnedHTTP(host, port, address, timeout=10))
    start = time.monotonic()
    try:
        connection.request(request['method'], path, body=body, headers=headers)
        response = connection.getresponse()
        body_bytes = response.read(MAX_RESPONSE + 1)
        response_headers = response.getheaders()
        elapsed = round((time.monotonic() - start) * 1000)
        result = {'method': request['method'], 'url': url, 'status': response.status,
                  'reason': response.reason, 'elapsed_ms': elapsed,
                  'headers': [[key, _redact_header(key, value)] for key, value in response_headers],
                  'body_preview': body_bytes[:MAX_RESPONSE].decode('utf-8', errors='replace'),
                  'body_truncated': len(body_bytes) > MAX_RESPONSE,
                  'body_bytes': len(body_bytes[:MAX_RESPONSE]),
                  'body_sha256': hashlib.sha256(body_bytes[:MAX_RESPONSE]).hexdigest(),
                  'observations': _observations(scheme, response.status, response_headers),
                  'confirmed_vulnerabilities': 0, 'checked_at': _utc(), 'source': source}
    finally:
        connection.close()
    with LOCK:
        HISTORY.insert(0, {key: result[key] for key in ('method', 'url', 'status', 'elapsed_ms',
                         'observations', 'checked_at', 'source')})
        del HISTORY[MAX_HISTORY:]
    return result, body_bytes[:MAX_RESPONSE], response_headers


def state():
    with LOCK:
        return {'project': dict(PROJECT) if PROJECT else None, 'history': list(HISTORY),
                'capabilities': ['manual request preview', 'one-use approval', 'HTTP history',
                                 'passive response observations', 'JSON export', 'local proxy',
                                 'intercept', 'bounded intruder', 'read-only browser preview']}


def handle(handler, base, method):
    path = urlsplit(handler.path).path
    if not path.startswith('/api/workbench/'):
        return False
    try:
        host_header = handler.headers.get('Host', '')
        host = urlsplit('http://' + host_header).hostname
        try:
            local = host == 'localhost' or ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
        origin = handler.headers.get('Origin')
        if (not local or not ipaddress.ip_address(handler.client_address[0]).is_loopback
                or (origin and urlsplit(origin).netloc != host_header)):
            handler._send_json(403, {'error': 'Local same-origin requests required'})
            return True
        if method == 'GET' and path == '/api/workbench/state':
            handler._send_json(200, state())
        elif path.startswith('/api/workbench/advanced/'):
            from workbench_advanced import handle as handle_advanced
            handle_advanced(handler, path, method)
        elif method == 'POST' and path in ('/api/workbench/project', '/api/workbench/preview', '/api/workbench/send'):
            if 'application/json' not in handler.headers.get('Content-Type', '').lower():
                handler._send_json(415, {'error': 'JSON required'})
                return True
            data = handler._read_json_body()
            if data is not None:
                action = {'/api/workbench/project': configure,
                          '/api/workbench/preview': preview,
                          '/api/workbench/send': send}[path]
                handler._send_json(200, action(data))
        else:
            handler._send_json(404, {'error': 'Unknown workbench route'})
    except (ValueError, OSError, TypeError, http.client.HTTPException) as exc:
        handler._send_json(400, {'error': str(exc)})
    return True
