"""Separate, bounded SQLmap detection jobs. Scanner claims are not impact proof."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import http.client
import ssl
from html.parser import HTMLParser
from urllib.parse import parse_qsl, unquote, urlsplit, urljoin, urlencode, urlunsplit
from rg_evidence.scope import parse_target, hostname, probe

LOCK = threading.Lock()
JOBS = {}
MAX_SECONDS = 180
MAX_LOG = 2 * 1024 * 1024
MAX_ENDPOINTS = 5
FLAGS = ['--batch', '--non-interactive', '--level=1', '--risk=1', '--technique=BE', '--threads=1',
         '--delay=1', '--timeout=8', '--retries=0', '--ignore-redirects',
         '--drop-set-cookie', '--ignore-proxy', '--disable-coloring', '--fresh-queries',
         '--flush-session', '--answers=follow=N,extend=N', '--abort-code=401,403,429,503']


def executable(base):
    configured = os.environ.get('RECONGUARD_SQLMAP')
    path = configured or shutil.which('sqlmap') or str(Path(base) / 'bin/sqlmap/sqlmap.py')
    p = Path(path)
    if not p.is_file() or p.suffix.lower() in ('.bat', '.cmd'):
        return None
    return [sys.executable, str(p.resolve())] if p.suffix.lower() == '.py' else [str(p.resolve())]


def validate(data):
    if not isinstance(data, dict) or set(data) - {'target', 'parameter', 'scope_host', 'authorized'}:
        raise ValueError('Only target, parameter, scope_host and authorized are accepted')
    if data.get('authorized') is not True:
        raise ValueError('Explicit testing authorization is required')
    raw = str(data.get('target', '')).strip()
    if len(raw) > 2048 or '*' in unquote(raw):
        raise ValueError('URL too long or contains a custom injection marker')
    target = parse_target(raw)
    if data.get('scope_host') and target[1] != hostname(str(data['scope_host']).strip()):
        raise ValueError('The URL hostname must exactly match the authorized hostname')
    pairs = parse_qsl(urlsplit(target[4]).query, keep_blank_values=True)
    names = [key for key, _ in pairs]
    if len(names) != len(set(names)):
        raise ValueError('Repeated query parameter names are ambiguous; use a URL with unique names')
    if len(names) > 10:
        raise ValueError('This bounded check supports at most 10 query parameters per URL')
    if any(not re.fullmatch(r'[A-Za-z0-9_]{1,64}', key) for key in names):
        raise ValueError('Unsupported query parameter name; supported names contain letters, numbers or underscores')
    # Older callers may explicitly select one parameter; the URL-only UI tests all.
    selected = data.get('parameter')
    if selected is not None:
        if selected not in names:
            raise ValueError('Selected parameter must occur in the target URL')
        names = [selected]
    return target, ','.join(names)


def command(prefix, target, param, folder):
    return prefix + ['--url=' + target, '-p', param] + FLAGS + ['--output-dir=' + str(folder)]


def classify(log, returncode, state='completed', parameter=None):
    """Only parse SQLmap's final delimited injection-point summary, never heuristics."""
    observations = []
    for block in re.findall(r'^---\s*\n(.*?)^---\s*$', log, re.M | re.S):
        for match in re.finditer(r'^Parameter: (.+?) \((GET|POST)\)\s*\n(.*?)(?=^Parameter:|\Z)', block, re.M | re.S):
            name, place, body = match.groups()
            if place != 'GET' or (parameter is not None and name not in parameter.split(',')):
                continue
            for item in re.finditer(r'^\s*Type: (.+)\n\s*Title: (.+)\n\s*Payload: (.+)', body, re.M):
                kind, title, payload = item.groups()
                row = {'parameter': name, 'place': place, 'type': kind.strip(),
                       'title': title.strip(), 'payload': payload.strip(),
                       'confidence': 'scanner_reported', 'confirmed': False}
                if row not in observations:
                    observations.append(row)
    complete = state == 'completed' and returncode == 0 and 'ending @' in log
    warning = bool(re.search(r'\[(?:WARNING|CRITICAL|ERROR)\]|false positive|not stable|WAF/IPS', log, re.I))
    verdict = 'INCONCLUSIVE'
    if complete and observations and not warning:
        verdict = 'SCANNER_REPORTED'
    elif complete and not warning and 'all tested parameters do not appear to be injectable' in log:
        verdict = 'NO_DETECTION'
    return {'verdict': verdict, 'observations': observations, 'confirmed_vulnerabilities': 0,
            'review_required': True, 'warnings_present': warning,
            'reason': 'SQLmap output requires independent reproduction and impact review. No detection is not proof of security.'}


def baseline_ok(samples):
    if len(samples) != 2 or any(s.get('state') != 'responded' or not 200 <= s.get('status', 0) < 300 or s.get('body_truncated') for s in samples):
        return False
    fields = ('status', 'body_sample_sha256', 'sampled_bytes', 'headers')
    return all(samples[0].get(f) == samples[1].get(f) for f in fields)


class PageTargets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.forms, self.form = [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'a' and a.get('href'):
            self.links.append(a['href'])
        if tag == 'form':
            self.form = {'action': a.get('action', ''), 'method': a.get('method', 'get').lower(), 'fields': []}
        if self.form is not None and tag == 'input' and a.get('name') and 'disabled' not in a and a.get('type', '').lower() not in ('password', 'file', 'submit', 'button', 'reset'):
            self.form['fields'].append((a['name'], a.get('value', '1')))

    def handle_endtag(self, tag):
        if tag == 'form' and self.form is not None:
            self.forms.append(self.form)
            self.form = None


def discover(target):
    """One HTML page, up to three same-origin redirects, no recursive crawl."""
    original = target[:3]
    current = target
    notes = []
    for _ in range(4):
        connection = (http.client.HTTPSConnection(current[1], current[2], timeout=8, context=ssl.create_default_context())
                      if current[0] == 'https' else http.client.HTTPConnection(current[1], current[2], timeout=8))
        try:
            connection.request('GET', current[3], headers={'User-Agent':'ReconGuard-SQLmap/1.0', 'Accept-Encoding':'identity'})
            response = connection.getresponse()
            body = response.read(262145)
            if 300 <= response.status < 400:
                location = response.getheader('Location')
                nxt = parse_target(urljoin(current[4], location or ''))
                if not location or nxt[:3] != original:
                    return [], ['Redirect left the authorized origin or had no destination; discovery stopped.']
                current = nxt
                continue
            if not 200 <= response.status < 300:
                return [], ['Discovery returned HTTP %s; no endpoints selected.' % response.status]
            if len(body) > 262144:
                return [], ['Discovery page exceeds 256 KiB; no endpoints selected.']
            if 'html' not in (response.getheader('Content-Type') or '').lower():
                return [], ['Discovery response is not HTML; no form/link endpoints selected.']
            parser = PageTargets()
            parser.feed(body.decode('utf-8', errors='replace'))
            break
        finally:
            connection.close()
    else:
        return [], ['Redirect limit reached.']
    urls = [current[4]] + [urljoin(current[4], link) for link in parser.links]
    for form in parser.forms:
        if form['method'] != 'get':
            notes.append('POST form skipped; this URL-only tool tests GET inputs.')
            continue
        u = urlsplit(urljoin(current[4], form['action']))
        urls.append(urlunsplit((u.scheme, u.netloc, u.path, urlencode(form['fields']), '')))
    selected, seen = [], set()
    for url in urls:
        try:
            candidate, names = validate({'target':url.split('#', 1)[0], 'authorized':True})
            if candidate[:3] != original or not names:
                continue
            signature = (candidate[:3], urlsplit(candidate[4]).path, names)
            if signature in seen:
                continue
            seen.add(signature)
            selected.append((candidate, names))
            if len(selected) == MAX_ENDPOINTS:
                notes.append('Discovery capped at five endpoints.')
                break
        except (ValueError, UnicodeError):
            continue
    return selected, notes


def save(base, job):
    folder = Path(base) / 'sqlmap_runs' / job['id']
    folder.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(job, indent=2)
    (folder / 'report.json').write_text(encoded, encoding='utf-8')
    temp = Path(base) / 'sqlmap_last.tmp'
    temp.write_text(encoded, encoding='utf-8')
    temp.replace(Path(base) / 'sqlmap_last.json')


def worker(base, job, target, param, prefix):
    try:
        if not param:
            job.update(state='discovering', reason='Discovering query links and GET forms on the supplied page.')
            endpoints, notes = discover(target)
            job['discovery_notes'] = notes
            job['discovered_endpoints'] = [t[4] for t, _ in endpoints]
            if not endpoints:
                job.update(state='inconclusive', verdict='INCONCLUSIVE', reason='No testable query links or GET forms found on this page. JavaScript-only and POST forms need a dedicated request-based assessment. No SQLmap test was possible.')
                return
            # One selected endpoint per bounded run; report every discovered alternative.
            target, param = endpoints[0]
            job.update(scan_target=target[4], parameter=param, parameters=param.split(','),
                       reason='Testing the first discovered endpoint. Other discovered endpoints are listed for separate runs.')
        samples = [probe(target, 8), probe(target, 8)]
        job['baseline'] = samples
        if any(s.get('state') != 'responded' or not 200 <= s.get('status', 0) < 300 for s in samples):
            job.update(state='inconclusive', verdict='INCONCLUSIVE', reason='Baseline unreachable, blocked or redirected. Inspect the recorded status/error; SQLmap was not started.')
            return
        job['baseline_stable'] = baseline_ok(samples)
        folder = Path(base) / 'sqlmap_runs' / job['id']
        folder.mkdir(parents=True, exist_ok=True)
        log_path = folder / 'sqlmap.log'
        args = command(prefix, target[4], param, folder)
        job['command_argv'] = args
        job['state'] = 'running'
        with log_path.open('wb') as log:
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log, shell=False,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            started = time.monotonic()
            state = 'completed'
            try:
                while proc.poll() is None:
                    job['elapsed_seconds'] = round(time.monotonic() - started)
                    with log_path.open('rb') as live:
                        job['log'] = live.read(MAX_LOG).decode('utf-8', errors='replace')
                    if time.monotonic() - started > MAX_SECONDS or log_path.stat().st_size > MAX_LOG:
                        state = 'limited'
                        proc.kill()
                        break
                    time.sleep(0.2)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
        raw = log_path.read_bytes()[:MAX_LOG]
        text = raw.decode('utf-8', errors='replace')
        job.update(classify(text, proc.returncode, state, param))
        if not job['baseline_stable']:
            job.update(verdict='INCONCLUSIVE', reason='SQLmap ran, but baseline content was dynamic or truncated. Scanner observations require controlled reproduction.')
        job.update(state=state, exit_code=proc.returncode, log=text,
                   evidence_sha256=hashlib.sha256(raw).hexdigest(), log_truncated=log_path.stat().st_size > MAX_LOG)
    except Exception as exc:
        job.update(state='failed', verdict='INCONCLUSIVE', reason=str(exc))
    finally:
        job['finished_at'] = datetime.now(timezone.utc).isoformat()
        try:
            save(base, job)
        except OSError as exc:
            job['save_error'] = str(exc)
        LOCK.release()


def start(data, base):
    target, param = validate(data)
    prefix = executable(base)
    if not prefix:
        raise ValueError('SQLmap is unavailable. Configure RECONGUARD_SQLMAP or install bin/sqlmap/sqlmap.py')
    if not LOCK.acquire(blocking=False):
        raise ValueError('A SQLmap job is already running')
    job = {'id': uuid.uuid4().hex, 'target': target[4], 'parameter': param,
           'parameters': param.split(',') if param else [], 'scope_host': target[1],
           'started_at': datetime.now(timezone.utc).isoformat(), 'state': 'baseline',
           'verdict': 'PENDING', 'confirmed_vulnerabilities': 0, 'observations': []}
    JOBS.clear()
    JOBS[job['id']] = job
    try:
        threading.Thread(target=worker, args=(base, job, target, param, prefix), daemon=True).start()
    except Exception:
        LOCK.release()
        raise
    return dict(job)


def handle(handler, base, method):
    path = urlsplit(handler.path).path
    if not path.startswith('/api/sqlmap/'):
        return False
    try:
        host = urlsplit('http://' + handler.headers.get('Host', '')).hostname
        origin = handler.headers.get('Origin')
        if host not in ('localhost', '127.0.0.1', '::1') or not ipaddress.ip_address(handler.client_address[0]).is_loopback or (origin and urlsplit(origin).netloc != handler.headers.get('Host')):
            handler._send_json(403, {'error': 'Local same-origin requests required'})
            return True
        if method == 'GET' and path == '/api/sqlmap/status':
            handler._send_json(200, {'available': bool(executable(base)), 'running': LOCK.locked()})
        elif method == 'GET' and path == '/api/sqlmap/results':
            file = Path(base) / 'sqlmap_last.json'
            result = dict(next(iter(JOBS.values()))) if JOBS else (json.loads(file.read_text(encoding='utf-8')) if file.exists() else {'state': 'not_run', 'observations': []})
            handler._send_json(200, result)
        elif method == 'POST' and path == '/api/sqlmap/scan':
            if 'application/json' not in handler.headers.get('Content-Type', '').lower():
                handler._send_json(415, {'error': 'JSON required'})
                return True
            data = handler._read_json_body()
            if data is not None:
                handler._send_json(202, start(data, base))
        else:
            handler._send_json(404, {'error': 'Unknown SQLmap route'})
    except (ValueError, OSError, TypeError) as exc:
        handler._send_json(400, {'error': str(exc)})
    return True
