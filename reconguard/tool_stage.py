"""Automatic Dalfox/Nikto stages for the shared ReconGuard scan flow."""
import hashlib
from pathlib import Path
from urllib.parse import urlsplit
from .models import FindingEvidence, DiffSummary


def automatic_tool_stages(target, config, log, base=None):
    # Keep executable discovery lazy; unavailable tools must not break legacy recon.
    import rg_tools_api as adapter
    base = Path(base) if base is not None else Path(__file__).resolve().parent.parent
    data = dict(target=target, in_scope=config.in_scope_domains, out_of_scope=config.out_of_scope_regex)
    findings, runs, sources = [], [], []
    for stage, engine in [(5, 'dalfox'), (6, 'nikto')]:
        log(f'STAGE {stage} // [{engine.title()}] Starting automatic tool stage')
        if not adapter.executable(engine):
            runs.append(dict(engine=engine, state='unavailable', message='Executable not installed on server PATH'))
            log(f'[!] [{engine.title()}] Unavailable; this stage was not tested')
            continue
        if engine == 'nikto' and config.out_of_scope_regex:
            runs.append(dict(engine=engine, state='skipped_scope', message='Nikto cannot enforce configured regex exclusions'))
            log('[!] [Nikto] Skipped: configured regex exclusions cannot be enforced')
            continue
        try:
            report = adapter.run_tools(dict(data, tools=[engine]), base)
            runs.extend(report['tool_runs'])
            sources.extend(report.get('sources', []))
            for row in report['results']:
                identity = '|'.join(str(row[k]) for k in ('engine', 'rule', 'matcher', 'location'))
                external_path = urlsplit(row['location']).path if '://' in row['location'] else ''
                findings.append(FindingEvidence(
                    id='RG-' + engine.upper() + '-' + hashlib.sha256(identity.encode()).hexdigest()[:12],
                    asset_host=row['host'], endpoint_path=external_path, url=row['location'],
                    status_code=0, confidence_score=row['status'], severity=row['reported_severity'].upper(),
                    category=row['title'], raw_request='', raw_response_headers={},
                    raw_response_body=row['evidence_excerpt'],
                    diff_summary=DiffSummary('Not measured by ReconGuard', 0, 0, 'Not measured', row['validation_required']),
                    curl_cmd='', timestamp=row['timestamp'], source_engine=row['engine'],
                    review_status=row['status'], evidence_kind=row.get('evidence_kind', 'source evidence'),
                    evidence_sha256=row.get('evidence_sha256') or '', confirmed_vulnerability=False))
            for run in report['tool_runs']:
                log(f"[{engine.title()}] {run['state']}; no automatic vulnerability confirmation")
        except Exception as error:
            runs.append(dict(engine=engine, state='failed', message=str(error)))
            log(f'[!] [{engine.title()}] Stage failed: {error}')
    return findings, runs, sources
