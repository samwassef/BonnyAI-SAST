"""Assert the training fixture remains vulnerable using real local HTTP requests.

No external requests, real credentials, or persistent database are used.
Browser-only XSS execution and click overlay behavior are checked manually or by CDP.
"""

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest
from urllib.parse import urlencode

from app import ADMIN_PASSWORD, ADMIN_USERNAME, LabState, make_handler


class VulnerableLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = LabState()
        cls.target = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        cls.attacker = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        cls.target_origin = f"http://127.0.0.1:{cls.target.server_port}"
        cls.attacker_origin = f"http://127.0.0.1:{cls.attacker.server_port}"
        for server, attacker in [(cls.target, False), (cls.attacker, True)]:
            server.RequestHandlerClass = make_handler(cls.state, cls.target_origin, cls.attacker_origin, attacker=attacker)
            Thread(target=server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for server in [cls.target, cls.attacker]:
            server.shutdown()
            server.server_close()
        cls.state.database.close()

    def request(self, path, method="GET", data=None, headers=None, attacker=False):
        conn = http.client.HTTPConnection("127.0.0.1", (self.attacker if attacker else self.target).server_port, timeout=5)
        conn.request(method, path, body=urlencode(data) if data is not None else None,
                     headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read().decode()
        conn.close()
        return result

    def login(self):
        status, headers, _ = self.request('/login', 'POST', {'username': ADMIN_USERNAME, 'password': ADMIN_PASSWORD})
        self.assertEqual(status, 303)
        return {'Cookie': headers['Set-Cookie'].split(';')[0]}

    def test_reflected_xss_reaches_html_unescaped(self):
        payload = '<script>document.body.dataset.xss="executed"</script>'
        status, _, html = self.request('/search?' + urlencode({'q': payload}))
        self.assertEqual(status, 200)
        self.assertIn(payload, html)
        self.assertNotIn('&lt;script&gt;', html)

    def test_csrf_changes_authenticated_state_from_another_origin(self):
        headers = {**self.login(), 'Origin': self.attacker_origin, 'Referer': self.attacker_origin + '/csrf'}
        status, _, _ = self.request('/profile/email', 'POST', {'email': 'attacker@example.test'}, headers)
        self.assertEqual(status, 303)
        self.assertIn('Email: attacker@example.test', self.request('/account', headers=headers)[2])
        self.assertEqual(self.request('/profile/email', 'POST', {'email': 'unauthenticated@example.test'})[0], 401)
        html = self.request('/csrf', attacker=True)[2]
        self.assertIn(self.target_origin + '/profile/email', html)

    def test_clickjacking_target_is_frameable_and_action_changes_state(self):
        headers = self.login()
        status, response_headers, html = self.request('/account?frame=1', headers=headers)
        self.assertEqual(status, 200)
        self.assertNotIn('X-Frame-Options', response_headers)
        self.assertNotIn('Content-Security-Policy', response_headers)
        self.assertIn('/profile/subscribe', html)
        self.assertIn('<iframe', self.request('/clickjacking', attacker=True)[2])
        self.assertEqual(self.request('/profile/subscribe', 'POST', {}, headers)[0], 303)
        self.assertIn('Newsletter: enabled', self.request('/account', headers=headers)[2])

    def test_sql_injection_exposes_hidden_product(self):
        baseline = self.request('/products?category=office')[2]
        self.assertNotIn('Unreleased demo product', baseline)
        status, _, html = self.request('/products?' + urlencode({'category': "' OR 1=1 -- "}))
        self.assertEqual(status, 200)
        self.assertIn('Unreleased demo product', html)

    def test_hardcoded_credentials_authenticate(self):
        self.assertEqual(self.request('/login', 'POST', {'username': 'admin', 'password': 'wrong'})[0], 401)
        self.assertIn('Signed in as admin', self.request('/account', headers=self.login())[2])

    def test_sensitive_comments_are_served_to_anonymous_visitors(self):
        status, _, html = self.request('/')
        self.assertEqual(status, 200)
        comment = html.split('<!-- VULN-06:', 1)[1].split('-->', 1)[0]
        self.assertIn(ADMIN_PASSWORD, comment)
        self.assertIn('DEMO-RESET-TOKEN-DO-NOT-USE', comment)
        self.assertIn('/internal/backups/payroll-demo.csv', comment)

    def test_account_reset(self):
        headers = self.login()
        self.request('/profile/email', 'POST', {'email': 'changed@example.test'}, headers)
        self.request('/profile/subscribe', 'POST', {}, headers)
        self.assertEqual(self.request('/profile/reset', 'POST', {}, headers)[0], 303)
        html = self.request('/account', headers=headers)[2]
        self.assertIn('Email: admin@example.test', html)
        self.assertIn('Newsletter: disabled', html)


if __name__ == '__main__':
    unittest.main(verbosity=2)
