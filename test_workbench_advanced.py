import time
import unittest
from unittest.mock import patch

import web_workbench_api as wb
import workbench_advanced as adv


class AdvancedWorkbenchTests(unittest.TestCase):
    def setUp(self):
        wb.configure({'scope_url': 'https://example.test/search', 'authorized': True})

    def test_sniper_preview_and_one_use_start(self):
        data = {'mode': 'sniper', 'request': {'method': 'GET',
                'url': 'https://example.test/search?q={{1}}', 'headers': {}, 'body': ''},
                'payloads': ['alpha', 'beta']}
        preview = adv.intruder_preview(data)
        self.assertEqual(preview['request_count'], 2)
        self.assertIn('q=alpha', preview['first_request'])
        with patch.object(wb, '_perform', return_value={'status': 200, 'elapsed_ms': 5,
                'body_sha256': 'abc', 'body_bytes': 3, 'url': 'https://example.test/search?q=alpha'}):
            started = adv.intruder_start({**data, 'approval_token': preview['approval_token']})
            with self.assertRaisesRegex(ValueError, 'changed'):
                adv.intruder_start({**data, 'approval_token': preview['approval_token']})
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                run = next(item for item in adv.state()['runs'] if item['id'] == started['id'])
                if run['status'] == 'complete':
                    break
                time.sleep(.05)
        self.assertEqual(run['status'], 'complete')
        self.assertEqual(len(run['results']), 2)

    def test_intruder_rejects_out_of_scope_and_bad_payloads(self):
        request = {'method': 'GET', 'url': 'https://evil.test/search?q={{1}}', 'headers': {}, 'body': ''}
        with self.assertRaisesRegex(ValueError, 'outside'):
            adv.intruder_preview({'mode': 'sniper', 'request': request, 'payloads': ['test']})
        request['url'] = 'https://example.test/search?q={{1}}'
        with self.assertRaisesRegex(ValueError, '1 to 12'):
            adv.intruder_preview({'mode': 'sniper', 'request': request, 'payloads': ['x'] * 13})
        request['url'] = 'https://example.test/search?q={{5}}'
        with self.assertRaisesRegex(ValueError, 'Only position'):
            adv.intruder_preview({'mode': 'sniper', 'request': request, 'payloads': ['x']})

    def test_battering_ram_uses_same_payload_in_all_positions(self):
        data = {'mode': 'battering_ram', 'request': {'method': 'POST',
                'url': 'https://example.test/search?q={{1}}',
                'headers': {'X-Test': '{{2}}'}, 'body': 'value={{2}}'},
                'payloads': ['alpha', 'beta']}
        preview = adv.intruder_preview(data)
        self.assertEqual(preview['request_count'], 2)
        self.assertIn('q=alpha', preview['first_request'])
        self.assertIn('X-Test: alpha', preview['first_request'])

    def test_intercept_forward_validates_edits_and_drop_on_disable(self):
        adv.set_intercept({'enabled': True})
        original = {'method': 'GET', 'url': 'https://example.test/search?q=a', 'headers': {}, 'body': ''}
        item = {'request': original, 'event': __import__('threading').Event(), 'decision': None,
                'created_at': wb._utc()}
        with wb.LOCK:
            adv.PENDING['one'] = item
        with self.assertRaisesRegex(ValueError, 'outside'):
            adv.decide({'id': 'one', 'action': 'forward',
                        'request': {**original, 'url': 'https://evil.test/'}})
        self.assertFalse(item['event'].is_set())
        adv.decide({'id': 'one', 'action': 'forward', 'request': original})
        self.assertTrue(item['event'].is_set())
        self.assertEqual(item['decision'], 'forward')
        item['event'].clear()
        adv.set_intercept({'enabled': False})
        self.assertEqual(item['decision'], 'drop')


if __name__ == '__main__':
    unittest.main()
