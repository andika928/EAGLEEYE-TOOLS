"""Offline Dalfox and Nikto adapters; scanner claims are never confirmation."""
import json
import re
from .scope import hostname, parse_target


def dalfox_document(data):
    """v2 arrays, v3 results/meta envelopes, and finding-only JSONL."""
    text = data.decode('utf-8-sig')
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = [json.loads(line) for line in text.splitlines() if line.strip()]
    metadata = {}
    if isinstance(value, dict):
        if 'results' in value:
            metadata = value.get('meta', {})
            value = value['results']
        elif isinstance(value.get('data'), list):
            value = value['data']
        elif 'type' in value and isinstance(value.get('data'), str):
            value = [value]
        else:
            raise ValueError('Unsupported Dalfox JSON shape; export a finding array or results/meta JSON envelope')
    if not isinstance(value, list) or not isinstance(metadata, dict):
        raise ValueError('Invalid Dalfox report')
    return value, metadata


def dalfox_records(data):
    findings, metadata = dalfox_document(data)
    records = []
    for x in findings:
        if x == {}:  # Legacy v2 array terminator.
            continue
        tier = x['type'].upper()
        if tier not in ('V', 'A', 'R', 'I', 'G', 'GREP'):
            raise ValueError('Unsupported Dalfox tier: ' + tier)
        target = parse_target(x.get('data') or x.get('poc') or '')
        proof = x.get('raw_response') or x.get('response') or x.get('evidence') or ''
        if not isinstance(proof, str):
            raise ValueError('Dalfox evidence must be text')
        records.append(dict(engine='Dalfox', host=target[1], port=target[2], protocol=target[0],
                            location=target[4], rule='dalfox-' + str(x.get('cwe', 'unmapped')),
                            matcher=json.dumps([tier, x.get('method', 'GET'), x.get('param', ''), x.get('inject_type', '')]),
                            title=str(x.get('message_str') or 'Dalfox ' + tier + ' observation'),
                            reported_severity=str(x.get('severity', 'unknown')).lower(), evidence=proof,
                            timestamp=str(x.get('timestamp', 'not supplied')), cves=[],
                            dalfox_tier=tier, engine_verification_claim=tier == 'V',
                            observation_only=tier in ('R', 'I', 'G', 'GREP'),
                            evidence_kind='response_capture' if x.get('raw_response') or x.get('response') else 'scanner_assertion',
                            scan_incomplete=bool(metadata.get('incomplete', False))))
    return records


def nikto_records(data):
    hosts = json.loads(data.decode('utf-8-sig'))
    if isinstance(hosts, dict):
        hosts = [hosts]
    if not isinstance(hosts, list):
        raise ValueError('Expected Nikto host object or host array')
    records = []
    for source in hosts:
        host = hostname(source['host'])
        port = int(source['port'])
        if not 1 <= port <= 65535 or not isinstance(source.get('vulnerabilities'), list):
            raise ValueError('Invalid Nikto host/port/vulnerabilities')
        for x in source['vulnerabilities']:
            path = x['url']
            if '://' in path:
                target = parse_target(path)
                if target[1:3] != (host, port):
                    raise ValueError('Nikto finding URL contradicts report host/port')
                protocol, location = target[0], target[4]
            else:
                if not path.startswith('/') or path.startswith('//') or any(ord(c) < 32 for c in path):
                    raise ValueError('Invalid Nikto finding path')
                authority = '[' + host + ']' if ':' in host else host
                protocol, location = 'http-scheme-unspecified', f'{authority}:{port}{path}'
            records.append(dict(engine='Nikto', host=host, port=port, protocol=protocol,
                                location=location, rule=str(x['id']), matcher=str(x.get('method', 'GET')),
                                title=str(x['msg']), reported_severity='unknown', evidence='',
                                timestamp=str(source.get('start_time', 'not supplied')),
                                cves=sorted(set(re.findall(r'CVE-\d{4}-\d{4,}', str(x.get('references', '')), re.I))),
                                evidence_kind='scanner_message_only'))
    return records
