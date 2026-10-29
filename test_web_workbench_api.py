import unittest
from unittest.mock import patch

import web_workbench_api as wb


class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        with wb.LOCK:
            wb.PROJECT = None
            wb.PREVIEWS.clear()
            wb.HISTORY.clear()

    def test_preview_requires_explicit_scope_and_one_use_approval(self):
        request = {'method': 'GET', 'url': 'https://example.test/admin/login',
                   'headers': {}, 'body': ''}
        with self.assertRaisesRegex(ValueError, 'scope first'):
            wb.preview(request)
        with self.assertRaisesRegex(ValueError, 'authorization'):
            wb.configure({'scope_url': 'https://example.test/admin/', 'authorized': False})
        wb.configure({'scope_url': 'https://example.test/admin/', 'authorized': True})
        approval = wb.preview(request)
        self.assertIn('GET /admin/login HTTP/1.1', approval['request_preview'])
        with self.assertRaisesRegex(ValueError, 'outside'):
            wb.preview({**request, 'url': 'https://example.test/api/private'})
        with self.assertRaisesRegex(ValueError, 'outside'):
            wb.preview({**request, 'url': 'https://another.test/admin/login'})
        with self.assertRaisesRegex(ValueError, 'changed'):
            wb.send({**request, 'url': 'https://example.test/admin/other',
                     'approval_token': approval['approval_token']})
        with self.assertRaisesRegex(ValueError, 'changed'):
            wb.send({**request, 'approval_token': approval['approval_token']})

    def test_query_url_sets_path_scope_and_preserves_repeater_target(self):
        project = wb.configure({'scope_url': 'https://example.test/search?keyword=imgurl',
                                'authorized': True})
        self.assertEqual(project['scope_url'], 'https://example.test:443/search')
        self.assertEqual(project['initial_url'], 'https://example.test:443/search?keyword=imgurl')
        approval = wb.preview({'method': 'GET', 'url': project['initial_url'],
                               'headers': {}, 'body': ''})
        self.assertIn('GET /search?keyword=imgurl HTTP/1.1', approval['request_preview'])
        with self.assertRaisesRegex(ValueError, 'outside'):
            wb.preview({'method': 'GET', 'url': 'https://example.test/admin/',
                        'headers': {}, 'body': ''})

    def test_manual_send_redacts_secrets_and_never_confirms_observations(self):
        wb.configure({'scope_url': 'http://localhost:8844/', 'authorized': True})
        request = {'method': 'POST', 'url': 'http://localhost:8844/login',
                   'headers': {'Authorization': 'Bearer test-secret', 'Content-Type': 'text/plain'},
                   'body': 'test body'}
        approval = wb.preview(request)
        self.assertNotIn('test-secret', approval['request_preview'])

        class Response:
            status = 302
            reason = 'Found'
            def read(self, count): return b'preview body'
            def getheaders(self):
                return [('Location', 'https://elsewhere.test/'),
                        ('Set-Cookie', 'PHPSESSID=secret-value; Path=/; HttpOnly'),
                        ('Content-Type', 'text/html')]

        class Connection:
            def __init__(self, *args, **kwargs): self.called = False
            def request(self, method, path, body, headers):
                self.called = True
                self.request_data = (method, path, body, headers)
            def getresponse(self): return Response()
            def close(self): pass

        with patch.object(wb, '_resolve', return_value='127.0.0.1'), patch.object(wb, '_PinnedHTTP', Connection):
            result = wb.send({**request, 'approval_token': approval['approval_token']})
        self.assertEqual(result['status'], 302)
        self.assertEqual(result['confirmed_vulnerabilities'], 0)
        self.assertTrue(any('not requested' in note for note in result['observations']))
        self.assertIn('PHPSESSID=[redacted]', str(result['headers']))
        self.assertNotIn('secret-value', str(result))
        self.assertNotIn('preview body', str(wb.state()['history']))
        self.assertNotIn('test-secret', str(wb.state()['history']))
        with self.assertRaisesRegex(ValueError, 'changed'):
            wb.send({**request, 'approval_token': approval['approval_token']})

    def test_rejects_unsafe_headers_and_private_dns(self):
        wb.configure({'scope_url': 'https://example.test/', 'authorized': True})
        request = {'method': 'GET', 'url': 'https://example.test/', 'body': ''}
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            wb.preview({**request, 'headers': {'Host': 'other.test'}})
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            wb.preview({**request, 'headers': {'X-Test': 'a\r\nInjected: true'}})
        with patch.object(wb.socket, 'getaddrinfo', return_value=[(None,None,None,None,('10.1.2.3',443))]):
            with self.assertRaisesRegex(ValueError, 'Private'):
                wb._resolve('example.test', 443)


if __name__ == '__main__':
    unittest.main()
