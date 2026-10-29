"""Single-URL, bounded Dalfox v3 jobs for the local dashboard."""
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
from urllib.parse import urlsplit

from rg_evidence.scope import parse_target, Scope
from rg_evidence.tool_imports import dalfox_document, dalfox_records
from rg_evidence.engine_poc import triage, read_limited

LOCK = threading.Lock()
JOBS = {}
MAX_SECONDS = 120
MAX_LOG = 2 * 1024 * 1024


def executable():
    configured = os.environ.get('RECONGUARD_DALFOX')
    bundled = Path(__file__).resolve().parent / 'bin' / 'dalfox-v3.2.4' / 'dalfox.exe'
    path = configured or shutil.which('dalfox') or (str(bundled) if bundled.is_file() else None)
    if not path or not Path(path).is_file() or Path(path).suffix.lower() in ('.bat', '.cmd'):
        return None
    return [str(Path(path).resolve())]


def validate(data):
    if not isinstance(data, dict) or set(data) - {'target', 'authorized'}:
        raise ValueError('Only target and authorized are accepted')
    if data.get('authorized') is not True:
        raise ValueError('Explicit testing authorization is required')
    raw = str(data.get('target', '')).strip()
    if len(raw) > 2048 or '*' in raw:
        raise ValueError('URL too long or contains a wildcard')
    target = parse_target(raw)
    return target


def command(prefix, target, output):
    scheme, host, port = target[:3]
    authority = '[' + host + ']' if ':' in host else host
    default_port = 443 if scheme == 'https' else 80
    origin = scheme + '://' + authority
    port_pattern = r'(?::' + str(default_port) + r')?' if port == default_port else ':' + str(port)
    same_origin = '^' + re.escape(origin) + port_pattern + r'(?:/|$)'
    # Keep discovery/mining enabled: it is what makes a URL without query
    # parameters useful. Dalfox remains confined to the supplied origin.
    return prefix + ['scan', target[4], '--workers', '1', '--max-concurrent-targets', '1', '--max-targets-per-host', '5',
                     '--rate-limit', '1', '--delay', '200', '--timeout', '8', '--retries', '0',
                     '--scan-timeout', '60', '--max-payloads-per-param', '10',
                     '--waf-bypass', 'off', '--insecure=false', '--include-url', same_origin,
                     '--format', 'json', '--include-all', '--output', str(output)]


def save(base, job):
    encoded = json.dumps(job, indent=2)
    (Path(base) / 'dalfox_runs' / job['id'] / 'report.json').write_text(encoded, encoding='utf-8')
    temp = Path(base) / 'dalfox_last.tmp'
    temp.write_text(encoded, encoding='utf-8')
    temp.replace(Path(base) / 'dalfox_last.json')


def worker(base, job, target, prefix):
    folder = Path(base) / 'dalfox_runs' / job['id']
    try:
        folder.mkdir(parents=True, exist_ok=True)
        output, log_path = folder / 'dalfox.json', folder / 'dalfox.log'
        help_result = subprocess.run(prefix + ['scan', '--help'], capture_output=True, text=True,
                                     timeout=10, shell=False)
        if (help_result.returncode != 0 or '--rate-limit' not in help_result.stdout
                or '--include-all' not in help_result.stdout or '--max-targets-per-host' not in help_result.stdout
                or '--include-url' not in help_result.stdout):
            job.update(state='failed', verdict='INCONCLUSIVE', reason='Dalfox v3 CLI required. Install/configure Dalfox v3 to enable native scanning.')
            return
        args = command(prefix, target, output)
        job['command_argv'] = args
        job.update(state='running', reason='Dalfox is checking this authorized URL and bounded same-origin discoveries.')
        with log_path.open('wb') as log:
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log, shell=False,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            started = time.monotonic()
            while proc.poll() is None:
                job['elapsed_seconds'] = round(time.monotonic() - started)
                if log_path.exists():
                    job['log'] = log_path.read_bytes()[:MAX_LOG].decode('utf-8', errors='replace')
                if time.monotonic() - started > MAX_SECONDS or (log_path.exists() and log_path.stat().st_size > MAX_LOG):
                    proc.kill()
                    job.update(state='limited', verdict='INCONCLUSIVE', reason='Dalfox reached the 120-second or 2 MiB output limit; partial results are not treated as a complete assessment.')
                    break
                time.sleep(0.25)
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        code = proc.returncode
        job['exit_code'] = code
        job['log'] = log_path.read_bytes()[:MAX_LOG].decode('utf-8', errors='replace') if log_path.exists() else ''
        if job.get('state') == 'limited':
            return
        if code not in (0, 1) or not output.is_file():
            job.update(state='inconclusive', verdict='INCONCLUSIVE', reason='Dalfox did not produce a complete JSON report (exit %s). Review the source log; no clean result can be inferred.' % code)
            return
        raw = read_limited(output)
        findings, metadata = dalfox_document(raw)
        rows = dalfox_records(raw)
        report = triage(rows, Scope([target[1]]))
        job.update(state='completed', results=report['results'], blocked=report['blocked'],
                   scan_metadata=metadata, source_sha256=hashlib.sha256(raw).hexdigest(),
                   confirmed_vulnerabilities=0, review_required=True)
        has_v = any(row.get('dalfox_tier') == 'V' for row in report['results'])
        incomplete = bool(metadata.get('incomplete'))
        if incomplete:
            job.update(verdict='INCONCLUSIVE', reason='Dalfox marked the run incomplete. Treat every observation as a lead; no negative conclusion is supported.')
        elif has_v:
            job.update(verdict='SCANNER_REPORTED', reason='Dalfox emitted a V-tier result. This is a scanner claim, not independent browser confirmation; verify the exact payload in a real browser with controls.')
        elif report['results']:
            job.update(verdict='REVIEW_REQUIRED', reason='Dalfox reported reflection or analysis observations without a V-tier execution claim. These are not confirmed XSS.')
        else:
            job.update(verdict='NO_DETECTION', reason='Dalfox completed without findings on its discovered and tested inputs. This does not prove the URL or application is free of XSS.')
        job['evidence_sha256'] = hashlib.sha256(job['log'].encode('utf-8')).hexdigest()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        job.update(state='failed', verdict='INCONCLUSIVE', reason=str(exc))
    finally:
        job['finished_at'] = datetime.now(timezone.utc).isoformat()
        try:
            save(base, job)
        except OSError as exc:
            job['save_error'] = str(exc)
        LOCK.release()


def start(data, base):
    target = validate(data)
    prefix = executable()
    if not prefix:
        raise ValueError('Dalfox v3 is unavailable. Install Dalfox v3 or set RECONGUARD_DALFOX to its executable.')
    if not LOCK.acquire(blocking=False):
        raise ValueError('A Dalfox job is already running')
    job = {'id': uuid.uuid4().hex, 'target': target[4], 'scope_host': target[1],
           'started_at': datetime.now(timezone.utc).isoformat(), 'state': 'queued',
           'verdict': 'PENDING', 'results': [], 'confirmed_vulnerabilities': 0}
    JOBS.clear()
    JOBS[job['id']] = job
    try:
        threading.Thread(target=worker, args=(base, job, target, prefix), daemon=True).start()
    except Exception:
        LOCK.release()
        raise
    return dict(job)


def handle(handler, base, method):
    path = urlsplit(handler.path).path
    if not path.startswith('/api/dalfox/'):
        return False
    try:
        host_header = handler.headers.get('Host', '')
        host = urlsplit('http://' + host_header).hostname
        try:
            local = host == 'localhost' or ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
        origin = handler.headers.get('Origin')
        if not local or not ipaddress.ip_address(handler.client_address[0]).is_loopback or (origin and urlsplit(origin).netloc != host_header):
            handler._send_json(403, {'error': 'Local same-origin requests required'})
            return True
        if method == 'GET' and path == '/api/dalfox/status':
            handler._send_json(200, {'available': bool(executable()), 'running': LOCK.locked()})
        elif method == 'GET' and path == '/api/dalfox/results':
            file = Path(base) / 'dalfox_last.json'
            job = dict(next(iter(JOBS.values()))) if JOBS else (json.loads(file.read_text(encoding='utf-8')) if file.exists() else {'state': 'not_run', 'results': []})
            handler._send_json(200, job)
        elif method == 'POST' and path == '/api/dalfox/scan':
            if 'application/json' not in handler.headers.get('Content-Type', '').lower():
                handler._send_json(415, {'error': 'JSON required'})
                return True
            data = handler._read_json_body()
            if data is not None:
                handler._send_json(202, start(data, base))
        else:
            handler._send_json(404, {'error': 'Unknown Dalfox route'})
    except (ValueError, OSError, TypeError) as exc:
        handler._send_json(400, {'error': str(exc)})
    return True
