"""ReconGuard: explicit-scope HTTP asset scanner, Python standard library only."""
import argparse
import hashlib
import http.client
import ipaddress
import json
import math
import re
import ssl
import time
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def hostname(value):
    value = value.rstrip('.').lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        value = value.encode('idna').decode('ascii')
        if len(value) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')):
            raise ValueError('Invalid hostname')
        return value


def parse_target(value):
    p = urlsplit(value if '://' in value else 'https://' + value)
    if p.scheme not in ('https', 'http') or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError('Targets must be HTTP(S) URLs without credentials')
    if p.fragment or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError('Whitespace, control characters and fragments are not allowed')
    host = hostname(p.hostname)
    port = p.port if p.port is not None else (443 if p.scheme == 'https' else 80)
    if not 1 <= port <= 65535:
        raise ValueError('Invalid port')
    authority = '[' + host + ']' if ':' in host else host
    authority += ':' + str(port)
    path = p.path or '/'
    if p.query:
        path += '?' + p.query
    path.encode('ascii')  # Require percent-encoded URL paths.
    return p.scheme, host, port, path, p.scheme + '://' + authority + path


class Scope:
    def __init__(self, include, exclude=()):
        if not include:
            raise ValueError('Explicit --scope is required')
        self.include = [self.rule(x) for x in include]
        self.exclude = [self.rule(x) for x in exclude]

    @staticmethod
    def rule(value):
        wildcard = value.startswith('*.')
        root = hostname(value[2:] if wildcard else value)
        if wildcard:
            try:
                ipaddress.ip_address(root)
            except ValueError:
                pass
            else:
                raise ValueError('IP addresses cannot use wildcard rules')
        return wildcard, root

    @staticmethod
    def matches(host, rule):
        wildcard, root = rule
        return host.endswith('.' + root) if wildcard else host == root

    def allows(self, host):
        return (any(self.matches(host, x) for x in self.include)
                and not any(self.matches(host, x) for x in self.exclude))


def probe(target, timeout):
    scheme, host, port, path, url = target
    result = {'url': url, 'checked_at': datetime.now(timezone.utc).isoformat(),
              'state': 'unreachable', 'observations': []}
    connection = None
    start = time.monotonic()
    try:
        if scheme == 'https':
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.request('GET', path, headers={'User-Agent': 'ReconGuard-ScopeScanner/1.0', 'Accept-Encoding': 'identity', 'Connection': 'close'})
        response = connection.getresponse()
        body = response.read(65537)
        result.update(state='responded', status=response.status,
                      headers={key: response.getheader(key) for key in ('Content-Type', 'Server', 'Location', 'Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options') if response.getheader(key) is not None},
                      sampled_bytes=min(len(body), 65536), body_truncated=len(body) > 65536,
                      body_sample_sha256=hashlib.sha256(body[:65536]).hexdigest())
        if response.status in (429, 503):
            result['state'] = 'rate_limited_or_unavailable'
        if 300 <= response.status < 400:
            result['observations'].append('Redirect recorded; destination was not requested.')
        if scheme == 'http':
            result['observations'].append('This endpoint responded over plaintext HTTP; HTTPS availability was not tested.')
        if scheme == 'https' and response.getheader('Strict-Transport-Security') is None:
            result['observations'].append('HSTS header absent on this response; informational observation only.')
    except ssl.SSLCertVerificationError as error:
        result.update(state='tls_verification_failed', error=str(error))
    except (OSError, http.client.HTTPException, ValueError) as error:
        result['error'] = str(error)
    finally:
        if connection:
            connection.close()
    result['elapsed_ms'] = round((time.monotonic() - start) * 1000)
    return result


def assess(samples, controls=()):
    """Classify HTTP evidence, never infer exploitability from status or length."""
    assessment = {'classification': 'inconclusive', 'severity': 'informational',
                  'confirmed_vulnerability': False}
    if len(samples) < 2 or any(x.get('state') != 'responded' for x in samples):
        return dict(assessment, reason='At least two successful responses are required.')
    signature = lambda x: (x.get('status'), x.get('headers', {}).get('Content-Type'),
                            x.get('headers', {}).get('Location'), x.get('body_sample_sha256'))
    if any(signature(x) != signature(samples[0]) for x in samples[1:]):
        return dict(assessment, reason='Response status, content type, redirect or body sample changed across checks.')
    if any(x.get('body_truncated') for x in samples):
        return dict(assessment, reason='Response body exceeds sample limit; complete-body equivalence is unknown.')
    if controls:
        if len(controls) < 2 or any(x.get('state') != 'responded' or x.get('body_truncated') for x in controls):
            return dict(assessment, reason='Control responses are incomplete or unavailable.')
        if signature(controls[0]) != signature(controls[1]):
            return dict(assessment, reason='Random-path controls differ; fallback behavior is uncertain.')
        if signature(samples[0]) == signature(controls[0]):
            return dict(assessment, classification='suppressed_fallback', reason='Target matches both random nonexistent-path controls; no unique endpoint evidence.')
        return dict(assessment, classification='repeatable_distinct_response', reason='Repeated response differs from stable controls. This establishes a response difference, not a vulnerability.')
    return dict(assessment, classification='repeatable_observation', reason='Response repeated consistently; fallback behavior was not checked.')


def main(argv=None):
    parser = argparse.ArgumentParser(description='ReconGuard explicit-scope HTTP scanner')
    parser.add_argument('--scope', action='append', required=True, help='Exact hostname or *.domain; repeat for multiple rules')
    parser.add_argument('--exclude', action='append', default=[], help='Excluded hostname or wildcard; exclusion wins')
    parser.add_argument('--target', action='append', default=[], help='HTTP(S) URL or hostname; repeatable')
    parser.add_argument('--targets-file', type=Path, help='One target per line; # comments supported')
    parser.add_argument('--rate', type=float, default=1, help='Maximum request starts per second (0.1–10)')
    parser.add_argument('--timeout', type=float, default=5, help='Socket timeout in seconds (1–30)')
    parser.add_argument('--dry-run', action='store_true', help='Validate scope without DNS or HTTP requests')
    parser.add_argument('--verify', type=int, default=2, choices=range(2, 5), help='Repeat each supplied URL 2–4 times (default 2)')
    parser.add_argument('--calibrate', action='store_true', help='Also request two random root paths per origin to identify identical fallback responses')
    parser.add_argument('--output', type=Path, default=Path('reconguard-report.json'))
    args = parser.parse_args(argv)
    try:
        if not math.isfinite(args.rate) or not .1 <= args.rate <= 10 or not math.isfinite(args.timeout) or not 1 <= args.timeout <= 30:
            raise ValueError('Rate must be 0.1–10 and timeout must be 1–30')
        scope = Scope(args.scope, args.exclude)
        values = list(args.target)
        if args.targets_file:
            values.extend(x.strip() for x in args.targets_file.read_text(encoding='utf-8').splitlines() if x.strip() and not x.lstrip().startswith('#'))
        if not values or len(values) > 1000:
            raise ValueError('Supply between 1 and 1000 targets')
        targets = list(dict.fromkeys(parse_target(x) for x in values))
    except (ValueError, OSError, UnicodeError) as error:
        parser.error(str(error))
    report = {'product': 'ReconGuard ASM Scope Scanner', 'scope': args.scope, 'exclude': args.exclude,
              'dry_run': args.dry_run, 'results': [], 'limitations': 'HTTP observations only; no guarantee of zero false positives, vulnerability verification, discovery, or IP ownership validation. Scope rules authorize hostnames on any explicitly supplied port.'}
    next_start = 0
    controls_by_origin = {}
    stopped = False

    def request(target):
        nonlocal next_start, stopped
        time.sleep(max(0, next_start - time.monotonic()))
        next_start = time.monotonic() + 1 / args.rate
        evidence = probe(target, args.timeout)
        if evidence['state'] == 'rate_limited_or_unavailable':
            stopped = True
        return evidence

    for target in targets:
        if not scope.allows(target[1]):
            result = {'url': target[4], 'state': 'blocked_out_of_scope'}
        elif args.dry_run:
            result = {'url': target[4], 'state': 'allowed_dry_run'}
        else:
            samples = []
            for _ in range(args.verify):
                samples.append(request(target))
                if stopped:
                    break
            origin = target[:3]
            if args.calibrate and not stopped and origin not in controls_by_origin:
                controls_by_origin[origin] = []
                for _ in range(2):
                    path = '/reconguard-control-' + secrets.token_hex(16)
                    control = (*origin, path, target[4].split('://', 1)[0] + '://' + urlsplit(target[4]).netloc + path)
                    controls_by_origin[origin].append(request(control))
                    if stopped:
                        break
            controls = controls_by_origin.get(origin, [])
            result = {'url': target[4], 'state': 'checked', 'samples': samples,
                      'controls': controls, 'assessment': assess(samples, controls)}
            if args.calibrate and not controls:
                result['assessment'] = {'classification': 'inconclusive', 'severity': 'informational',
                                        'confirmed_vulnerability': False, 'reason': 'Requested calibration did not complete.'}
        report['results'].append(result)
        if stopped:
            report['stopped_reason'] = 'Stopped after HTTP 429/503; remaining targets were not scanned.'
            break
    report['targets_requested'] = len(targets)
    report['targets_processed'] = len(report['results'])
    report['verification_repeats'] = args.verify
    report['calibration_enabled'] = args.calibrate
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'Report: {args.output.resolve()} | {len(report["results"])} targets processed')


if __name__ == '__main__':
    main()
