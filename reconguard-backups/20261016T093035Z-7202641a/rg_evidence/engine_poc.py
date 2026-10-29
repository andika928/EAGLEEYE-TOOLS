"""Offline Nuclei, Nessus, Dalfox and Nikto intake. Does not launch scanners."""
import argparse
import hashlib
import html
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from .scope import Scope, hostname, parse_target
from .tool_imports import dalfox_document, dalfox_records, nikto_records


def read_limited(path):
    with Path(path).open('rb') as source:
        data = source.read(20 * 1024 * 1024 + 1)
    if len(data) > 20 * 1024 * 1024:
        raise ValueError('PoC input limit is 20 MiB per file')
    return data


def nuclei_records(data):
    records = []
    for line in data.decode('utf-8-sig').splitlines():
        if not line.strip():
            continue
        x = json.loads(line)
        if x.get('type') != 'http':
            raise ValueError('PoC supports HTTP Nuclei records only')
        target = parse_target(x['matched-at'])
        info = x.get('info') or {}
        proof = x.get('response') or ''
        records.append(dict(engine='Nuclei', host=target[1], port=target[2], protocol=target[0],
                            location=target[4], rule=str(x['template-id']), matcher=str(x.get('matcher-name', '')),
                            title=str(info.get('name', x['template-id'])), reported_severity=str(info.get('severity', 'unknown')),
                            evidence=proof, timestamp=str(x.get('timestamp', 'not supplied')),
                            cves=(info.get('classification') or {}).get('cve-id', [])))
    return records


def nessus_records(data):
    text = data.decode('utf-8-sig')
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValueError('DTD/entity declarations are not accepted')
    root = ET.fromstring(text)
    if root.tag != 'NessusClientData_v2':
        raise ValueError('Expected NessusClientData_v2 XML export')
    records = []
    for host in root.findall('./Report/ReportHost'):
        # Deliberately do not trust reported DNS aliases as scope authorization.
        name = hostname(host.attrib['name'])
        for item in host.findall('ReportItem'):
            port = int(item.attrib['port'])
            if not 0 <= port <= 65535:
                raise ValueError('Invalid Nessus port')
            records.append(dict(engine='Nessus', host=name, port=port, protocol=item.get('protocol', 'unknown'),
                                location=f'{name}:{port}', rule=item.attrib['pluginID'], matcher='',
                                title=item.get('pluginName', 'Unnamed plugin'),
                                reported_severity={'0': 'info', '1': 'low', '2': 'medium', '3': 'high', '4': 'critical'}.get(item.get('severity'), 'unknown'),
                                evidence=item.findtext('plugin_output', ''), timestamp='not supplied',
                                cves=[x.text for x in item.findall('cve') if x.text]))
    return records


def triage(records, scope):
    accepted, blocked, seen = [], [], set()
    for original in records:
        row = dict(original)
        if not scope.allows(row['host']):
            blocked.append({'engine': row['engine'], 'location': row['location'], 'reason': 'outside configured hostname scope'})
            continue
        key = (row['engine'], row['rule'], row['matcher'], row['location'], row['protocol'])
        if key in seen:
            continue
        seen.add(key)
        proof = row.pop('evidence')
        row['evidence_present'] = bool(proof.strip())
        row['evidence_sha256'] = hashlib.sha256(proof.encode()).hexdigest() if proof else None
        row['evidence_excerpt'] = proof[:1200]
        row['status'] = 'informational' if row.get('observation_only') or row['reported_severity'] == 'info' else 'needs_review' if proof.strip() else 'insufficient_evidence'
        row['confirmed_vulnerability'] = False
        row['validation_required'] = 'Check affected version/configuration, backports, repeatability and authorized security impact. Scanner severity or CVE mapping alone is not proof.'
        if row['engine'] == 'Dalfox':
            row['validation_required'] = 'Reflection or AST analysis alone does not prove XSS. Independently reproduce browser execution on the intended origin, with a negative control and verified session/context. Dalfox V remains an engine claim.'
        elif row['engine'] == 'Nikto':
            row['validation_required'] = 'Nikto JSON messages are leads, not captured HTTP evidence. Capture the exact response, compare negative controls and verify security impact before reporting a bug.'
        accepted.append(row)
    return {'results': accepted, 'blocked': blocked, 'confirmed_vulnerabilities': 0,
            'policy': 'Offline triage only. Import filtering cannot prevent an external scanner from scanning out of scope. No auto-confirmation or cross-engine severity escalation.'}


def render(report):
    esc = lambda x: html.escape(str(x))
    cards = ''.join('<article><div class="tag">' + esc(x['engine']) + ' · ' + esc(x['status']) + '</div><h3>' + esc(x['title']) + '</h3><p>' + esc(x['location']) + '</p><p>Scanner severity: ' + esc(x['reported_severity']) + ' · Rule: ' + esc(x['rule']) + '</p><details><summary>Inspect evidence</summary><pre>' + esc(x['evidence_excerpt'] or 'No response evidence supplied') + '</pre><p>SHA-256: ' + esc(x['evidence_sha256']) + '</p></details><p class="muted">' + esc(x['validation_required']) + '</p></article>' for x in report['results'])
    document = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ReconGuard · Evidence Preview</title>
<style>body{margin:0;background:#09111e;color:#e5eefc;font:16px system-ui}main{max-width:1080px;margin:auto;padding:48px 24px}h1{font-size:44px;margin:16px 0}h2{font-size:24px}.tag{color:#6ee7cb;letter-spacing:1px;font-size:13px}p{line-height:1.6}.muted{color:#9caec6}section{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px}article,.metric{padding:24px;background:#111e30;border:1px solid #26374e;border-radius:12px;margin:12px 0}.metric strong{display:block;font-size:32px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080f19;padding:16px}summary{cursor:pointer;color:#6ee7cb}.notice{border-left:3px solid #f4c16c;padding:12px 20px;background:#241f1a}</style><main>
<div class="tag">RECONGUARD / NUCLEI + NESSUS</div><h1>Evidence before escalation.</h1><p class="notice">''' + ('SIMULATED DEMO — synthetic fixtures; no live scanner results.' if report.get('demo') else 'IMPORTED RESULTS — scanner claims await independent validation.') + '''</p><p class="muted">Scope-controlled intake · inspectable evidence · no automatic vulnerability claims</p><section>
<div class="metric"><strong>''' + str(len(report['results'])) + '''</strong>Imported observations</div><div class="metric"><strong>0</strong>Confirmed vulnerabilities</div><div class="metric"><strong>''' + str(len(report['blocked'])) + '''</strong>Blocked at intake</div></section><h2>Review queue</h2>''' + cards + '<h2>Operational status</h2><p class="muted">Nuclei / Nessus execution: not connected. DNS telemetry, continuous discovery, multi-port scanning and SOC staffing: not implemented by this PoC. Intake supports per-port Nessus evidence.</p><p>' + esc(report['policy']) + '</p></main></html>'


    document = document.replace('NUCLEI + NESSUS', 'NUCLEI + NESSUS + DALFOX + NIKTO')
    document = document.replace('Nuclei / Nessus execution:', 'Nuclei / Nessus / Dalfox / Nikto execution:')
    if any(x.get('scan_metadata', {}).get('incomplete') for x in report.get('sources', [])):
        document = document.replace('<h2>Review queue</h2>', '<p class="notice">INCOMPLETE SCAN: imported metadata reports unfinished testing. Zero findings does not establish safety.</p><h2>Review queue</h2>')
    return document


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scope', action='append', required=True)
    p.add_argument('--exclude', action='append', default=[])
    p.add_argument('--nuclei', type=Path)
    p.add_argument('--nessus', type=Path)
    p.add_argument('--dalfox', type=Path, help='Dalfox JSON array, results/meta envelope or finding-only JSONL')
    p.add_argument('--nikto', type=Path, help='Nikto JSON host object or host array')
    p.add_argument('--demo', action='store_true', help='Use bundled synthetic fixtures')
    p.add_argument('--output', type=Path, default=Path('engine-report.json'))
    p.add_argument('--html', type=Path, default=Path('engine-preview.html'))
    args = p.parse_args()
    try:
        scope = Scope(args.scope, args.exclude)
        if args.demo and (args.nuclei or args.nessus or args.dalfox or args.nikto):
            raise ValueError('Demo fixtures cannot be mixed with live imports')
        if args.demo:
            args.nuclei = Path(__file__).parent / 'fixtures/demo-nuclei.jsonl'
            args.nessus = Path(__file__).parent / 'fixtures/demo-nessus.nessus'
            args.dalfox = Path(__file__).parent / 'fixtures/demo-dalfox.json'
            args.nikto = Path(__file__).parent / 'fixtures/demo-nikto.json'
        records, sources = [], []
        for source, reader in [(args.nuclei, nuclei_records), (args.nessus, nessus_records), (args.dalfox, dalfox_records), (args.nikto, nikto_records)]:
            if source:
                data = read_limited(source)
                sources.append({'file': source.name, 'sha256': hashlib.sha256(data).hexdigest(),
                                'scan_metadata': dalfox_document(data)[1] if reader == dalfox_records else {}})
                records.extend(reader(data))
        if not sources:
            raise ValueError('Supply --demo, --nuclei, --nessus, --dalfox or --nikto')
        report = triage(records, scope)
        report.update(demo=args.demo, sources=sources, scope=args.scope, exclusions=args.exclude)
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
        args.html.write_text(render(report), encoding='utf-8')
        print(f'Preview: {args.html.resolve()}')
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ET.ParseError) as error:
        p.error(str(error))


if __name__ == '__main__':
    main()
