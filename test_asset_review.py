import unittest
from unittest.mock import patch
import server


class AssetEvidenceTests(unittest.TestCase):
    def run_scan(self, fail=False, gated=False):
        def tool(name, target, options):
            if name == 'subenum':
                return {'subdomains': []}
            if name == 'portscanner':
                raise RuntimeError('Unavailable')
            if fail:
                raise RuntimeError('HTTP timeout')
            return {'status': 200, 'transport': 'https', 'final_url': target,
                    'missing_headers': [{'header': 'Permissions-Policy'}],
                    'response_headers': {'Content-Type': 'text/html'},
                    'site_gate': {'detected': True} if gated else None}
        with patch.object(server._rt_tools, 'run_tool', side_effect=tool), patch.object(server, '_pick_scheme', return_value='https'), patch.object(server.socket, 'gethostbyname', return_value='192.0.2.1'):
            return server._run_full_scan('example.test')

    def test_evidence_and_coverage(self):
        r = self.run_scan()
        self.assertEqual(r['assets'][0]['response_headers'], {'Content-Type': 'text/html'})
        self.assertEqual(r['assets'][0]['ports'], '')
        self.assertTrue(r['observed_at'])
        self.assertIn('Port scan failed', r['coverage_gaps'][0])
        self.assertEqual(r['findings'][0]['confidence'], 'observation')

    def test_http_failure_not_secure(self):
        r = self.run_scan(fail=True)
        self.assertEqual(r['assets'][0]['grade'], '?')
        self.assertEqual(r['findings'], [])
        self.assertTrue(r['coverage_gaps'])

    def test_other_host_response_not_attributed(self):
        r = self.run_scan(gated=True)
        self.assertEqual(r['findings'], [])
        self.assertIn('attribution', r['assets'][0]['error'])


if __name__ == '__main__':
    unittest.main()
