import json
from pathlib import Path
import re
import unittest
from unittest.mock import Mock, patch, mock_open
import rg_tools_api as api


class DashboardToolsTests(unittest.TestCase):
    def data(self):
        return dict(target='http://127.0.0.1:8080/', in_scope=['127.0.0.1'], out_of_scope=[], tools=['dalfox'])

    def test_outside_scope_never_starts_process(self):
        with patch.object(api.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                api.run_tools(dict(self.data(), target='https://outside.invalid/'), Path('.'))
            run.assert_not_called()

    def test_missing_tool_returns_actionable_error(self):
        with patch.object(api, 'executable', return_value=None), patch.object(api.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                api.run_tools(self.data(), Path('.'))
            run.assert_not_called()

    def test_nikto_refuses_unenforceable_regex_scope(self):
        with patch.object(api, 'executable', return_value=['nikto']), patch.object(api.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'cannot enforce'):
                api.run_tools(dict(self.data(), tools=['nikto'], out_of_scope=['logout']), Path('.'))
            run.assert_not_called()

    def test_import_applies_host_and_url_exclusions(self):
        text = json.dumps([{'type': 'R', 'data': 'http://127.0.0.1:8080/logout', 'severity': 'Medium'}, {'type': 'V', 'data': 'https://outside.invalid/', 'severity': 'High'}])
        report = api.intake(dict(self.data(), out_of_scope=['logout'], reports={'dalfox': text}))
        self.assertEqual(len(report['blocked']), 2)
        self.assertEqual(report['confirmed_vulnerabilities'], 0)

    def test_malformed_exclusion_fails_closed(self):
        with self.assertRaises(re.error):
            api.policy(dict(self.data(), out_of_scope=['[']))

    def test_commands_use_fixed_arguments_and_no_redirect_flags(self):
        target = 'https://example.com:443/?q=a&x=b'
        args = api.command('dalfox', ['dalfox'], target, Path('out.json'), [re.compile('logout')])
        self.assertEqual(args[2], target)
        self.assertIn('--include-url', args)
        self.assertIn('--exclude-url', args)
        self.assertNotIn('--follow-redirects', args)
        args = api.command('nikto', ['perl', 'nikto.pl'], target, Path('out.json'))
        self.assertNotIn('-followredirects', args)
        self.assertIn('-maxtime', args)

    def test_foreign_origin_or_rebound_host_is_rejected(self):
        for headers in [{'Host': 'evil.invalid'}, {'Host': 'localhost:8080', 'Origin': 'https://evil.invalid'}]:
            handler = Mock(path='/api/reconguard/integrations/scan', headers=headers)
            self.assertTrue(api.handle(handler, Path('.'), 'POST'))
            self.assertEqual(handler._send_json.call_args.args[0], 403)

    def test_status_reports_missing_executables(self):
        with patch.object(api, 'executable', return_value=None):
            self.assertFalse(api.status()['dalfox']['available'])
            self.assertFalse(api.status()['nikto']['available'])

    def test_timeout_never_appears_as_finished_or_clean(self):
        help_result = Mock(returncode=0, stdout='--rate-limit --include-all')
        with patch.object(api, 'executable', return_value=['dalfox']), patch.object(api.Path, 'mkdir'), patch.object(api.tempfile, 'mkdtemp', return_value='mock-run'), patch.object(api.Path, 'open', mock_open()), patch.object(api.subprocess, 'run', side_effect=[help_result, api.subprocess.TimeoutExpired('dalfox', 120)]):
            report = api.run_tools(self.data(), Path('.'))
        self.assertEqual(report['tool_runs'][0]['state'], 'timed_out')
        self.assertEqual(report['confirmed_vulnerabilities'], 0)
        self.assertEqual(report['results'], [])


if __name__ == '__main__':
    unittest.main()
