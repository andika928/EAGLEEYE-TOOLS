import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dalfox_api as api


class DalfoxToolTests(unittest.TestCase):
    def test_url_only_validation_requires_explicit_authorization(self):
        target = api.validate({'target': 'https://example.test/search', 'authorized': True})
        self.assertEqual(target[1], 'example.test')
        with self.assertRaises(ValueError):
            api.validate({'target': 'https://example.test/search', 'authorized': False})
        with self.assertRaises(ValueError):
            api.validate({'target': 'https://user:secret@example.test/', 'authorized': True})

    def test_command_keeps_discovery_and_caps_scope(self):
        target = api.validate({'target':'https://example.test:8443/page', 'authorized':True})
        args = api.command(['dalfox'], target, Path('out.json'))
        self.assertIn('https://example.test:8443/page', args)
        self.assertIn('--include-url', args)
        scope = args[args.index('--include-url') + 1]
        self.assertIn('https://example\\.test:8443', scope)
        self.assertNotIn('--skip-mining', args)
        self.assertNotIn('--follow-redirects', args)
        self.assertEqual(args[args.index('--rate-limit') + 1], '1')
        self.assertEqual(args[args.index('--max-targets-per-host') + 1], '5')
        self.assertEqual(args[args.index('--max-payloads-per-param') + 1], '10')
        self.assertNotIn('--min-confidence', args)
        default = api.command(['dalfox'], api.validate({'target':'https://example.test/', 'authorized':True}), Path('out.json'))
        self.assertIn('(?::443)?', default[default.index('--include-url') + 1])

    def test_v_tier_is_only_scanner_reported_not_confirmed(self):
        raw = json.dumps({'meta': {'incomplete': False}, 'results': [
            {'type':'V','data':'https://example.test/?q=x','param':'q','method':'GET','inject_type':'inHTML','severity':'High','message_str':'verification claim'}]}).encode()
        findings, meta = api.dalfox_document(raw)
        rows = api.triage(api.dalfox_records(raw), api.Scope(['example.test']))
        self.assertFalse(meta['incomplete'])
        self.assertEqual(findings[0]['type'], 'V')
        self.assertFalse(rows['results'][0]['confirmed_vulnerability'])
        self.assertEqual(rows['results'][0]['dalfox_tier'], 'V')

    def test_dalfox_v3_findings_meta_envelope_and_clean_result(self):
        # Dalfox v3.2.4 writes this envelope when --include-all --format json
        # is used. In particular, a clean report has findings: [] and meta.
        raw = json.dumps({'findings': [], 'meta': {
            'dalfox_version': '3.2.4', 'findings_count': 0,
            'incomplete': False, 'total_requests': 65,
        }}).encode()
        findings, metadata = api.dalfox_document(raw)
        self.assertEqual(findings, [])
        self.assertEqual(metadata['dalfox_version'], '3.2.4')
        self.assertEqual(api.dalfox_records(raw), [])

        finding_raw = json.dumps({'findings': [{
            'type': 'R', 'data': 'https://example.test/search?q=marker',
            'param': 'q', 'method': 'GET', 'message_str': 'reflection only',
        }], 'meta': {'incomplete': False}}).encode()
        rows = api.dalfox_records(finding_raw)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['dalfox_tier'], 'R')
        self.assertTrue(rows[0]['observation_only'])

    def test_ambiguous_or_malformed_dalfox_envelopes_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            api.dalfox_document(json.dumps({'results': [], 'findings': []}).encode())
        with self.assertRaisesRegex(ValueError, 'objects'):
            api.dalfox_document(json.dumps({'findings': ['not a finding']}).encode())

    def test_missing_binary_fails_without_starting_worker(self):
        with patch.object(api, 'executable', return_value=None), patch.object(api.threading, 'Thread') as thread:
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                api.start({'target':'https://example.test/', 'authorized':True}, '.')
            thread.assert_not_called()

    def test_complete_v_tier_report_is_scanner_reported(self):
        report = {'meta': {'incomplete': False}, 'results': [
            {'type':'V','data':'https://example.test/?q=proof','param':'q','method':'GET','inject_type':'inHTML','severity':'High','message_str':'synthetic fixture'}]}
        class Completed:
            returncode = 1
            def poll(self): return 0
            def wait(self): return self.returncode
        def fake_popen(args, **kwargs):
            output = Path(args[args.index('--output') + 1])
            output.write_text(json.dumps(report), encoding='utf-8')
            return Completed()
        with tempfile.TemporaryDirectory(dir=Path(api.__file__).resolve().parent / 'bin') as base, patch.object(api.subprocess, 'run', return_value=type('Help', (), {'returncode':0,'stdout':'--rate-limit --include-all --max-targets-per-host --include-url'})()), patch.object(api.subprocess, 'Popen', side_effect=fake_popen):
            target = api.validate({'target':'https://example.test/', 'authorized':True})
            api.LOCK.acquire()
            job = {'id':'synthetic-test','target':target[4]}
            api.worker(base, job, target, ['dalfox'])
            self.assertEqual(job['verdict'], 'SCANNER_REPORTED', job)
            self.assertEqual(job['confirmed_vulnerabilities'], 0)
            self.assertTrue((Path(base)/'dalfox_runs'/'synthetic-test'/'report.json').is_file())


if __name__ == '__main__':
    unittest.main()
