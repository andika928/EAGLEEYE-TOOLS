import unittest
from unittest.mock import patch
from pathlib import Path
from reconguard.models import ScopeConfig
from reconguard.pipeline import ReconGuardPipeline
from reconguard.tool_stage import automatic_tool_stages
from reconguard.evidence_engine import EvidenceEngine


class UnifiedPipelineTests(unittest.TestCase):
    def config(self, exclusions=None):
        return ScopeConfig(in_scope_domains=['example.com'], out_of_scope_regex=exclusions or [])

    def response(self, engine):
        return dict(results=[dict(engine=engine.title(), rule='test', matcher='test', location='https://example.com/',
                                 host='example.com', status='needs_review', reported_severity='unknown',
                                 title='Observation', evidence_excerpt='scanner assertion', timestamp='test',
                                 validation_required='Independent validation required', evidence_kind='scanner_assertion')],
                    tool_runs=[dict(engine=engine, state='finished')], sources=[])

    def test_both_tools_automatic_and_evidence_merged(self):
        with patch('rg_tools_api.executable', return_value=['tool']), patch('rg_tools_api.run_tools', side_effect=lambda data, base: self.response(data['tools'][0])) as run:
            findings, runs, _ = automatic_tool_stages('https://example.com/', self.config(), lambda _: None)
        self.assertEqual([call.args[0]['tools'] for call in run.call_args_list], [['dalfox'], ['nikto']])
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(not row.confirmed_vulnerability for row in findings))
        self.assertTrue(all(row.status_code == 0 for row in findings))

    def test_unavailable_is_not_a_clean_scan(self):
        with patch('rg_tools_api.executable', return_value=None), patch('reconguard.pipeline.SubfinderCore') as sub, patch('reconguard.pipeline.HttpxCore') as http:
            sub.return_value.run.return_value = {'discovered_assets': []}
            http.return_value.run.return_value = []
            report = ReconGuardPipeline(self.config()).execute('example.com')
        self.assertEqual(report.summary['status'], 'COMPLETED_WITH_GAPS')
        self.assertEqual([run['state'] for run in report.tool_runs], ['unavailable', 'unavailable'])
        self.assertEqual(len(report.to_dict()['tool_runs']), 2)
        self.assertIn('Dalfox', '\n'.join(report.telemetry_logs))
        markdown = EvidenceEngine.generate_markdown_report(report)
        self.assertIn('unavailable', markdown)
        self.assertNotIn('Target returned zero false-positive', markdown)

    def test_failure_does_not_skip_following_tool(self):
        with patch('rg_tools_api.executable', return_value=['tool']), patch('rg_tools_api.run_tools', side_effect=[ValueError('failed preflight'), self.response('nikto')]):
            findings, runs, _ = automatic_tool_stages('https://example.com/', self.config(), lambda _: None)
        self.assertEqual([x['state'] for x in runs], ['failed', 'finished'])
        self.assertEqual(findings[0].source_engine, 'Nikto')

    def test_scope_restriction_kept_without_user_tool_choice(self):
        with patch('rg_tools_api.executable', return_value=['tool']), patch('rg_tools_api.run_tools', return_value=self.response('dalfox')) as run:
            _, runs, _ = automatic_tool_stages('https://example.com/', self.config(['logout']), lambda _: None)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(runs[-1]['state'], 'skipped_scope')

    def test_unified_export_uses_source_evidence_without_fake_http_status(self):
        with patch('rg_tools_api.executable', return_value=['tool']), patch('rg_tools_api.run_tools', side_effect=lambda data, base: self.response(data['tools'][0])), patch('reconguard.pipeline.SubfinderCore') as sub, patch('reconguard.pipeline.HttpxCore') as http:
            sub.return_value.run.return_value = {'discovered_assets': []}
            http.return_value.run.return_value = []
            report = ReconGuardPipeline(self.config()).execute('https://example.com/')
        self.assertEqual(report.summary['status'], 'COMPLETED')
        self.assertEqual(len(report.findings), 2)
        markdown = EvidenceEngine.generate_markdown_report(report)
        self.assertIn('Dalfox: Observation', markdown)
        self.assertIn('Nikto: Observation', markdown)
        self.assertNotIn('HTTP/1.1 0', markdown)

    def test_dashboard_has_single_launch_and_no_tool_picker(self):
        root = Path(__file__).parent
        index = (root / 'web/index.html').read_text(encoding='utf-8')
        self.assertIn('/rg-unified.js', index)
        self.assertNotIn('/rg-tools.js', index)
        self.assertIn('rgPipe7', index)
        script = (root / 'web/rg-unified.js').read_text(encoding='utf-8')
        self.assertNotIn('type="file"', script)
        self.assertNotIn('checkbox', script)
        self.assertNotIn('rgRunTools', script)


if __name__ == '__main__':
    unittest.main()
