"""Offline checks for linked JavaScript discovery and clue reporting."""

import unittest
import json
from types import SimpleNamespace
from unittest.mock import patch

from app.chat import HFChat
from app.fetcher import HTTPFetcher, PageEvidence
from app.js_inspection import PATTERNS, scan_js, script_urls
from test_fetcher import response


class JavaScriptInspectionTests(unittest.TestCase):
    def test_script_urls_resolve_relative_and_deduplicate(self):
        html = ('<script src="/app.js"></script><script src="https://cdn.example.com/lib.js"></script>'
                '<script src="/app.js"></script><script>inline()</script>')
        self.assertEqual(script_urls(html, 'https://example.com/page'),
                         ['https://example.com/app.js', 'https://cdn.example.com/lib.js'])

    def test_categories_have_lines_without_leaking_values(self):
        source = ('// TODO remove before prod\n'
                  'const apiKey = "SUPER-SECRET-VALUE";\n'
                  'fetch("/api/v1/users"); location.search; node.innerHTML = value;\n')
        matches = scan_js(source)
        categories = {item['category'] for item in matches}
        self.assertTrue({'Interesting comments', 'Secrets', 'Hidden endpoints',
                         'DOM XSS sources', 'DOM XSS sinks'} <= categories)
        self.assertIn(2, next(item['lines'] for item in matches if item['category'] == 'Secrets'))
        self.assertNotIn('SUPER-SECRET-VALUE', str(matches))

    def test_every_requested_category_has_a_representative_match(self):
        source = ('// TODO sourceMappingURL=app.js.map\n'
                  'admin apiKey AWS_KEY localhost featureFlag role location.search innerHTML '
                  'window.location node.src= postMessage( WebSocket( sessionStorage '
                  'withCredentials mutation FormData __proto__ eval( /api/\n')
        self.assertEqual({item['category'] for item in scan_js(source)}, set(PATTERNS))

    def test_fetch_collects_and_scans_linked_script(self):
        page = response(b'<script src="/app.js"></script>')
        script = response(b'const apiKey="SECRET-VALUE"; fetch("/api/data");')
        with patch('app.fetcher.resolve', return_value=['93.184.216.34']), \
             patch('app.fetcher.PinnedConnection') as connection:
            connection.return_value.getresponse.side_effect = [page, script]
            evidence = HTTPFetcher().fetch('https://example.com/')
        self.assertEqual(len(evidence.scripts), 1)
        self.assertEqual(evidence.scripts[0]['url'], 'https://example.com/app.js')
        self.assertTrue(evidence.scripts[0]['matches'])
        self.assertNotIn('SECRET-VALUE', str(evidence.scripts))

    def test_script_query_values_are_redacted_and_private_hosts_are_blocked(self):
        page = response(b'<script src="/app.js?key=PRIVATE-VALUE"></script>'
                        b'<script src="http://127.0.0.1/private.js"></script>')
        script = response(b'const token="SECRET-VALUE";')
        with patch('app.fetcher.resolve', return_value=['93.184.216.34']), \
             patch('app.fetcher.PinnedConnection') as connection:
            connection.return_value.getresponse.side_effect = [page, script]
            evidence = HTTPFetcher().fetch('https://example.com/')
        self.assertEqual(len(evidence.scripts), 2)
        self.assertEqual(evidence.scripts[0]['url'], 'https://example.com/app.js?[redacted]')
        self.assertEqual(evidence.scripts[1]['url'], '[blocked script URL]')
        self.assertEqual(connection.call_count, 2)
        self.assertNotIn('PRIVATE-VALUE', str(evidence.scripts))

    def test_script_count_and_file_size_are_bounded(self):
        html = ''.join(f'<script src="/file-{n}.js"></script>' for n in range(13)).encode()
        with patch('app.fetcher.resolve', return_value=['93.184.216.34']), \
             patch('app.fetcher.PinnedConnection') as connection:
            connection.return_value.getresponse.side_effect = [response(html)] + [
                response(b'a' * 300001) for _ in range(12)]
            evidence = HTTPFetcher().fetch('https://example.com/')
        self.assertEqual(len(evidence.scripts), 12)
        self.assertEqual(evidence.scripts_skipped, 1)
        self.assertTrue(all(item['truncated'] and item['bytes'] <= 300000
                            for item in evidence.scripts if 'truncated' in item))

    def test_model_gets_only_bounded_script_summary(self):
        evidence = PageEvidence('https://example.com/', 'https://example.com/', [
            {'html': '<html></html>', 'headers': [], 'status': 200}],
            scripts=[{'url': 'https://example.com/app.js', 'matches': [
                {'category': 'Secrets', 'term': 'apiKey', 'count': 1, 'lines': [2]}],
                'raw_source': 'SECRET-VALUE'}])
        with patch('app.chat.InferenceClient') as factory:
            call = factory.return_value.__enter__.return_value.chat_completion
            call.return_value = SimpleNamespace(choices=[SimpleNamespace(
                message=SimpleNamespace(content='Review clues'), finish_reason='stop')])
            HFChat('test-token').analyze('Analyze', evidence)
            payload = json.loads(call.call_args.kwargs['messages'][-1]['content'])
        self.assertEqual(payload['scripts'][0]['categories'], ['Secrets'])
        self.assertNotIn('SECRET-VALUE', json.dumps(payload))
        self.assertNotIn('matches', payload['scripts'][0])


if __name__ == '__main__':
    unittest.main()
