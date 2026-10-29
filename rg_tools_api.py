"""Dashboard adapters for opt-in Dalfox v3/Nikto runs and offline report intake."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit
from rg_evidence.scope import Scope, parse_target
from rg_evidence.tool_imports import dalfox_document, dalfox_records, nikto_records
from rg_evidence.engine_poc import triage, read_limited

RUN_LOCK = threading.Lock()
READERS = {'dalfox': dalfox_records, 'nikto': nikto_records}


def executable(tool):
    configured = os.environ.get('RECONGUARD_' + tool.upper())
    path = configured or shutil.which(tool) or (shutil.which('nikto.pl') if tool == 'nikto' else None)
    if not path or not Path(path).is_file():
        return None
    path = str(Path(path).resolve())
    if Path(path).suffix.lower() in ('.bat', '.cmd'):
        return None  # Never route target strings through a command shell.
    if path.lower().endswith('.pl'):
        perl = shutil.which('perl')
        return [perl, path] if perl else None
    return [path]


def status():
    return {name: {'available': bool(executable(name)), 'mode': 'native opt-in / JSON import'} for name in READERS}


def policy(data):
    include = data.get('in_scope')
    if not isinstance(include, list) or not all(isinstance(x, str) for x in include):
        raise ValueError('Explicit in_scope hostname rules are required')
    scope = Scope(include)
    patterns = data.get('out_of_scope', [])
    if not isinstance(patterns, list) or len(patterns) > 30:
        raise ValueError('Invalid exclusions')
    # Keep the dashboard legacy regex exclusions; invalid patterns fail closed.
    regexes = [re.compile(x, re.I) for x in patterns if isinstance(x, str) and len(x) <= 200]
    if len(regexes) != len(patterns):
        raise ValueError('Invalid exclusion pattern')
    return scope, regexes


def blocked(url, regexes):
    return any(pattern.search(url) for pattern in regexes)


def intake(data):
    scope, regexes = policy(data)
    uploads = data.get('reports', {})
    if not isinstance(uploads, dict) or not uploads or set(uploads) - set(READERS):
        raise ValueError('Supply Dalfox and/or Nikto JSON reports')
    rows, sources, rejected = [], [], []
    for tool, text in uploads.items():
        if not isinstance(text, str) or len(text.encode('utf-8')) > 1024 * 1024:
            raise ValueError('Each uploaded report must be text, maximum 1 MiB')
        raw = text.encode('utf-8')
        for row in READERS[tool](raw):
            if blocked(row['location'], regexes):
                rejected.append({'engine': row['engine'], 'location': row['location'], 'reason': 'excluded by dashboard regex'})
            else:
                rows.append(row)
        sources.append({'engine': tool, 'sha256': hashlib.sha256(raw).hexdigest(),
                        'scan_metadata': dalfox_document(raw)[1] if tool == 'dalfox' else {}})
    report = triage(rows, scope)
    report['blocked'].extend(rejected)
    report.update(sources=sources, mode='import', tool_runs=[])
    return report


def command(tool, prefix, target, output, regexes=()):
    if tool == 'dalfox':
        origin = urlsplit(target)
        args = prefix + ['scan', target, '--workers', '1', '--max-concurrent-targets', '1',
                         '--rate-limit', '1', '--scan-timeout', '60', '--max-payloads-per-param', '10',
                         '--skip-mining', '--waf-bypass', 'off', '--insecure=false',
                         '--include-url', '^' + re.escape(origin.scheme + '://' + origin.netloc) + r'(?:/|$)',
                         '--format', 'json', '--include-all', '--output', str(output)]
        for regex in regexes:
            args.extend(['--exclude-url', regex.pattern])
        return args
    return prefix + ['-host', target, '-Tuning', '123b', '-Pause', '1', '-timeout', '5',
                     '-maxtime', '60s', '-nointeractive', '-Format', 'json', '-output', str(output)]


def run_tools(data, base):
    scope, regexes = policy(data)
    target = parse_target(str(data.get('target', '')).strip())
    if not scope.allows(target[1]) or blocked(target[4], regexes):
        raise ValueError('Target blocked by scope; no scanner was started')
    selected = data.get('tools')
    if not isinstance(selected, list) or not selected or len(selected) != len(set(selected)) or set(selected) - set(READERS):
        raise ValueError('Select Dalfox and/or Nikto')
    prefixes = {tool: executable(tool) for tool in selected}
    if 'nikto' in selected and regexes:
        raise ValueError('Nikto cannot enforce these per-path regex exclusions. Import its report, or use a separately authorized whole-origin scope without regex exclusions.')
    if not all(prefixes.values()):
        raise ValueError('Selected scanner unavailable. Install it on the server or import a report.')
    if not RUN_LOCK.acquire(blocking=False):
        raise ValueError('Another tool run is active; wait for it to finish')
    try:
        root = Path(base) / 'rg_runs'
        root.mkdir(exist_ok=True)
        # Keep source output and bounded-run diagnostics for operator review.
        folder = Path(tempfile.mkdtemp(prefix='scan-', dir=root))
        reports, runs = {}, []
        for tool in selected:
            prefix = prefixes[tool]
            if tool == 'dalfox':
                help_result = subprocess.run(prefix + ['scan', '--help'], capture_output=True, text=True, timeout=10, shell=False)
                if help_result.returncode != 0 or '--rate-limit' not in help_result.stdout or '--include-all' not in help_result.stdout:
                    raise ValueError('Dalfox v3 CLI required; use report import for other versions')
            output = folder / (tool + '.json')
            run = {'engine': tool, 'state': 'incomplete', 'source_file': output.name}
            try:
                with (folder / (tool + '.log')).open('wb') as log:
                    completed = subprocess.run(command(tool, prefix, target[4], output, regexes), stdout=log, stderr=log, timeout=120, shell=False)
                run['exit_code'] = completed.returncode
                run['state'] = 'finished' if completed.returncode in ((0, 1) if tool == 'dalfox' else (0,)) else 'failed'
            except subprocess.TimeoutExpired:
                run['state'] = 'timed_out'
            # Never parse a partial/failed result as a clean scan.
            if run['state'] == 'finished' and output.exists():
                reports[tool] = read_limited(output).decode('utf-8-sig')
            elif run['state'] == 'finished':
                run['state'] = 'missing_output'
            runs.append(run)
        report = intake(dict(data, reports=reports)) if reports else dict(results=[], blocked=[], confirmed_vulnerabilities=0, sources=[])
        report.update(mode='native', tool_runs=runs, run_folder=folder.name,
                      policy='External tools ran only after target scope checks. Tools may test additional paths/parameters on the supplied origin. No redirect-follow flags enabled. Review source output; no vulnerability auto-confirmation.')
        return report
    finally:
        RUN_LOCK.release()


def handle(handler, base, method):
    path = urlsplit(handler.path).path
    if not path.startswith('/api/reconguard/integrations/'):
        return False
    try:
        host_header = handler.headers.get('Host', '')
        host = urlsplit('http://' + host_header).hostname
        try:
            local = host == 'localhost' or ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
        origin = handler.headers.get('Origin')
        if not local or (origin and urlsplit(origin).netloc != host_header):
            handler._send_json(403, {'error': 'Local same-origin requests required'})
            return True
        if method == 'GET' and path.endswith('/status'):
            handler._send_json(200, {'tools': status()})
        elif method == 'GET' and path.endswith('/results'):
            file = Path(base) / 'rg_integrations_results.json'
            handler._send_json(200, json.loads(file.read_text(encoding='utf-8')) if file.exists() else {'results': [], 'blocked': [], 'sources': [], 'confirmed_vulnerabilities': 0})
        elif method == 'POST' and path.rsplit('/', 1)[-1] in ('import', 'scan'):
            origin = handler.headers.get('Origin')
            if origin and urlsplit(origin).netloc != handler.headers.get('Host'):
                handler._send_json(403, {'error': 'Same-origin requests required'})
                return True
            if 'application/json' not in handler.headers.get('Content-Type', '').lower():
                handler._send_json(415, {'error': 'JSON required'})
                return True
            data = handler._read_json_body()
            if data is None:
                return True
            report = intake(data) if path.endswith('/import') else run_tools(data, base)
            file = Path(base) / 'rg_integrations_results.json'
            with RUN_LOCK:
                file.write_text(json.dumps(report, indent=2), encoding='utf-8')
            handler._send_json(200, report)
        else:
            handler._send_json(404, {'error': 'Unknown integration route'})
    except (ValueError, KeyError, TypeError, AttributeError, re.error, OSError, subprocess.SubprocessError) as error:
        handler._send_json(400, {'error': str(error)})
    return True
