import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sqlmap_api as api

SUMMARY = '''sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE clause
    Payload: id=1 AND 1=1
---
[*] ending @ 12:00:00 /2026-10-18/
'''


class SQLmapTests(unittest.TestCase):
    def test_url_only_detects_parameters_and_scope(self):
        target, parameters = api.validate({'target':'https://example.test/item?id=1&category=books', 'authorized':True})
        self.assertEqual(target[1], 'example.test')
        self.assertEqual(parameters, 'id,category')
        self.assertEqual(len(api.classify(SUMMARY, 0, parameter='category,id')['observations']), 1)
        args = api.command(['sqlmap'], target[4], parameters, Path('output'))
        self.assertEqual(args[args.index('-p') + 1], 'id,category')

    def test_parameterless_url_without_discoverable_get_inputs_does_not_start_scanner(self):
        target, parameters = api.validate({'target':'https://example.test/login', 'authorized':True})
        self.assertEqual(parameters, '')
        with tempfile.TemporaryDirectory() as base, patch.object(api, 'discover', return_value=([], [])) as discover, patch.object(api, 'probe') as probe, patch.object(api.subprocess, 'Popen') as popen:
            api.LOCK.acquire()
            job = {'id':'no-parameters'}
            api.worker(base, job, target, parameters, None)
            discover.assert_called_once_with(target)
            probe.assert_not_called()
            popen.assert_not_called()
            self.assertEqual(job['verdict'], 'INCONCLUSIVE')
            self.assertIn('No testable query links or GET forms', job['reason'])

    def test_auto_discovery_rejects_ambiguous_names(self):
        for query in ['id=1&id=2', 'id%2Cx=1', '&'.join('p%d=1' % i for i in range(11))]:
            with self.subTest(query=query), self.assertRaises(ValueError):
                api.validate({'target':'https://example.test/?'+query, 'authorized':True})

    def data(self, **changes):
        result = dict(target='https://example.test/item?id=1', parameter='id', scope_host='example.test', authorized=True)
        result.update(changes)
        return result

    def test_exact_scope(self):
        self.assertEqual(api.validate(self.data())[1], 'id')
        for change in [dict(scope_host='other.test'), dict(authorized=False), dict(authorized='yes'), dict(target='https://example.test/item?id=1&id=2'), dict(parameter='id,x'), dict(target='https://example.test/item?id=%2a'), dict(target='file:///tmp/a'), dict(target='https://name:secret@example.test/?id=1'), dict(options='--dump')]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                api.validate(self.data(**change))

    def test_fixed_detection_command(self):
        args = api.command(['sqlmap'], 'https://example.test/?id=1&x=2', 'id', Path('output'))
        self.assertIn('--url=https://example.test/?id=1&x=2', args)
        for flag in ['--risk=1', '--level=1', '--technique=BE', '--threads=1', '--ignore-redirects', '--flush-session']:
            self.assertIn(flag, args)
        self.assertNotIn('--dump', args)
        self.assertNotIn('--os-shell', args)

    def test_final_summary_is_claim_not_confirmation(self):
        r = api.classify(SUMMARY, 0, parameter='id')
        self.assertEqual(r['verdict'], 'SCANNER_REPORTED')
        self.assertEqual(len(r['observations']), 1)
        self.assertEqual(r['confirmed_vulnerabilities'], 0)

    def test_wrong_parameter_is_not_attributed(self):
        self.assertEqual(api.classify(SUMMARY, 0, parameter='other')['observations'], [])

    def test_heuristics_never_promoted(self):
        for text in ['[INFO] GET parameter id might be injectable', 'SQL syntax error', '[WARNING] heuristic test shows injectable']:
            self.assertEqual(api.classify(text, 0)['verdict'], 'INCONCLUSIVE')

    def test_partial_failure_and_waf_remain_inconclusive(self):
        for code, state, log in [(1,'completed',SUMMARY),(0,'limited',SUMMARY),(0,'completed',SUMMARY+'[WARNING] WAF detected'),(0,'completed',SUMMARY.split('[*] ending')[0])]:
            self.assertEqual(api.classify(log, code, state)['verdict'], 'INCONCLUSIVE')

    def test_negative_only_when_complete(self):
        log = 'all tested parameters do not appear to be injectable\n[*] ending @ 12:00'
        self.assertEqual(api.classify(log, 0)['verdict'], 'NO_DETECTION')
        self.assertEqual(api.classify('', 0)['verdict'], 'INCONCLUSIVE')

    def test_baseline_requires_successful_stable_complete_responses(self):
        good = dict(state='responded',status=200,body_sample_sha256='abc',sampled_bytes=3,headers={})
        self.assertTrue(api.baseline_ok([good, good]))
        for change in [dict(status=403),dict(status=302),dict(body_truncated=True),dict(body_sample_sha256='different'),dict(state='unreachable')]:
            self.assertFalse(api.baseline_ok([good, dict(good, **change)]))

    def test_unavailable_does_not_start(self):
        with patch.object(api, 'executable', return_value=None), patch.object(api.threading, 'Thread') as thread:
            with self.assertRaises(ValueError):
                api.start(self.data(), '.')
            thread.assert_not_called()

    def test_bad_baseline_does_not_spawn_scanner(self):
        with tempfile.TemporaryDirectory() as base, patch.object(api, 'probe', return_value={'state':'unreachable'}), patch.object(api.subprocess, 'Popen') as popen:
            job = {'id':'test-job'}
            api.LOCK.acquire()
            api.worker(base, job, api.validate(self.data())[0], 'id', ['sqlmap'])
            popen.assert_not_called()
            self.assertEqual(job['verdict'], 'INCONCLUSIVE')
            self.assertFalse(api.LOCK.locked())
            self.assertEqual(json.loads((Path(base)/'sqlmap_last.json').read_text())['state'], 'inconclusive')

    def test_shell_wrappers_rejected(self):
        with tempfile.TemporaryDirectory() as base:
            f = Path(base)/'sqlmap.cmd'
            f.write_text('echo test')
            with patch.dict(api.os.environ, {'RECONGUARD_SQLMAP':str(f)}):
                self.assertIsNone(api.executable(base))


if __name__ == '__main__':
    unittest.main()
