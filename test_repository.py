"""Offline repository review tests: no GitHub or inference calls."""
# Test tools and application objects; external services are replaced with mocks.
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from app.chat import ChatError, ChatReply, HFChat
from app.fetcher import FetchError
from app.main import create_app
from app.repository import RepositoryEvidence, RepositoryFetcher, render_report, repository_name

COMMIT = 'a' * 40


# Build a fake GitHub file listing with byte sizes matching the supplied contents.
def source_tree(entries):
    return {"truncated": False, "tree": [
        {"path": path, "type": "blob", "mode": "100644", "size": len(content.encode() if isinstance(content, str) else content)}
        for path, content in entries]}


# Simulate individual source downloads so selection tests run entirely offline.
def collect(entries):
    collector = RepositoryFetcher()
    contents = {path: content.encode() if isinstance(content, str) else content for path, content in entries}
    from urllib.parse import unquote
    collector._get = Mock(side_effect=lambda url, *args, **kwargs: contents[unquote(url.split(COMMIT + "/", 1)[1])])
    return collector.read_tree(source_tree(entries), "o/r", COMMIT, float("inf"))


# Check GitHub collection boundaries and source selection without network calls.
class CollectionTests(unittest.TestCase):
    # Regression check: url boundary.
    def test_url_boundary(self):
        self.assertEqual(repository_name('https://github.com/owner/repo.git/'), 'owner/repo')
        for url in ('http://github.com/o/r', 'https://github.com.evil.test/o/r',
                    'https://github.com@evil.test/o/r', 'https://127.0.0.1/o/r',
                    'https://github.com/o/r/tree/main', 'https://github.com/o/..',
                    'https://github.com/o/r?x=1', 'https://github.com/o/r#x'):
            with self.subTest(url=url), self.assertRaises(FetchError):
                repository_name(url)

    # Regression check: commit pinned and ref encoded.
    def test_commit_pinned_and_ref_encoded(self):
        collector = RepositoryFetcher()
        tree = source_tree([('app.py', 'print(1)\n')])
        tree['tree'].append({'path': 'huge.png', 'type': 'blob', 'mode': '100644', 'size': 900_000_000})
        collector._get = Mock(side_effect=[COMMIT.encode(),
            json.dumps({'tree': {'sha': 'b' * 40}}).encode(), json.dumps(tree).encode(), b'print(1)\n'])
        evidence = collector.fetch('https://github.com/o/r', 'feature/security')
        self.assertEqual(evidence.commit, COMMIT)
        calls = collector._get.call_args_list
        self.assertIn('feature%2Fsecurity', calls[0].args[0])
        self.assertEqual(calls[0].kwargs['accept'], 'application/vnd.github.sha')
        self.assertEqual(calls[3].args[0], f'https://raw.githubusercontent.com/o/r/{COMMIT}/app.py')
        self.assertEqual(len(calls), 4)
        self.assertEqual(evidence.skipped[0]['path'], 'huge.png')

    # Regression check: selection and coverage.
    def test_selection_and_coverage(self):
        evidence = collect([
            ('app.py', 'line one\nline two\n'),
            ('node_modules/lib.js', 'dependency'), ('image.png', b'\xff'),
            ('large.py', 'x' * 30001), ('binary.py', b'\x00'),
        ])
        self.assertEqual(evidence.files, [{'path': 'app.py', 'content': 'line one\nline two\n'}])
        self.assertEqual(len(evidence.skipped), 4)

    # Regression check: total source budget is reported.
    def test_total_source_budget_is_reported(self):
        evidence = collect([(f'{n}.py', 'a' * 30000) for n in range(3)])
        self.assertEqual(len(evidence.files), 2)
        self.assertEqual(evidence.skipped[0]['reason'], 'review input limit')

    # Regression check: unsafe paths and empty selection.
    def test_unsafe_paths_and_empty_selection(self):
        for entries in ([('../app.py', 'x')], [('/app.py', 'x')],
                        [('image.png', 'x')], [('a\\b.py', 'x')]):
            with self.subTest(entries=entries), self.assertRaises(FetchError):
                collect(entries)

    # Regression check: incomplete tree fails before download.
    def test_incomplete_tree_fails_before_download(self):
        collector = RepositoryFetcher()
        collector._get = Mock()
        with self.assertRaisesRegex(FetchError, 'incomplete file list'):
            collector.read_tree({'truncated': True, 'tree': []}, 'o/r', COMMIT, float('inf'))
        collector._get.assert_not_called()

    # Regression check: symlinks submodules and lfs are not reviewed.
    def test_symlinks_submodules_and_lfs_are_not_reviewed(self):
        collector = RepositoryFetcher()
        tree = source_tree([('app.py', 'x'), ('link.py', 'target')])
        tree['tree'][1]['mode'] = '120000'
        tree['tree'].append({'path': 'sub', 'type': 'commit', 'mode': '160000'})
        collector._get = Mock(return_value=b'x')
        result = collector.read_tree(tree, 'o/r', COMMIT, float('inf'))
        self.assertEqual(len(result.skipped), 2)
        collector._get.assert_called_once()
        result = collect([('app.py', 'x'), ('lfs.py', 'version https://git-lfs.github.com/spec/v1\noid sha256:abc')])
        self.assertIn('Git LFS', result.skipped[0]['reason'])

    # Regression check: source only filter runs before download.
    def test_source_only_filter_runs_before_download(self):
        excluded = [
            '.github/workflows/check.py', '.gitlab/ci/check.sh', '.circleci/test.js',
            'pipelines/run.ps1', 'CI/check.py', 'docker/entrypoint.sh',
            'Dockerfile', 'Dockerfile.py', 'service.Dockerfile', 'Containerfile',
            'docker-compose.yml', 'Jenkinsfile.js', 'infra/main.py',
            'deployment/start.sh', 'docs/example.py', 'README.md',
            'package.json', 'settings.yaml', 'schema.xml', 'pyproject.toml',
            'main.tf', 'build.gradle', 'build.gradle.kts', 'Makefile',
            'setup.py', 'build.rs', 'webpack.config.js', 'vite.config.ts',
        ]
        included = ['src/app.py', 'src/config/settings.py', 'src/DockerClient.ts',
                    'tests/test_app.py', 'web/page.html', 'scripts/tool.sh']
        collector = RepositoryFetcher()
        collector._get = Mock(return_value=b'x')
        evidence = collector.read_tree(source_tree([(p, 'x') for p in excluded + included]),
                                       'o/r', COMMIT, float('inf'))
        self.assertEqual([f['path'] for f in evidence.files], sorted(included))
        self.assertEqual({f['path'] for f in evidence.skipped}, set(excluded))
        self.assertEqual(collector._get.call_count, len(included))
        for call in collector._get.call_args_list:
            self.assertIn(call.args[0].split(COMMIT + '/')[1], included)

    # Regression check: source size mismatch fails.
    def test_source_size_mismatch_fails(self):
        collector = RepositoryFetcher()
        collector._get = Mock(return_value=b'too long')
        with self.assertRaisesRegex(FetchError, 'size differs'):
            collector.read_tree(source_tree([('app.py', 'x')]), 'o/r', COMMIT, float('inf'))

    # Regression check: redirect host is revalidated.
    def test_redirect_host_is_revalidated(self):
        response = Mock(status=302)
        response.getheader.return_value = 'https://127.0.0.1/private'
        with patch('app.repository.resolve', return_value=['140.82.112.5']), \
             patch('app.repository.PinnedConnection') as connection:
            connection.return_value.getresponse.return_value = response
            with self.assertRaises(FetchError):
                RepositoryFetcher()._get('https://api.github.com/repos/o/r/git/trees/HEAD', 100, float('inf'))
            self.assertEqual(connection.call_count, 1)
            connection.return_value.close.assert_called_once()

    # Regression check: download size limit.
    def test_download_size_limit(self):
        response = Mock(status=200)
        response.getheader.return_value = 'identity'
        response.read1.return_value = b'123456'
        with patch('app.repository.resolve', return_value=['140.82.112.5']), \
             patch('app.repository.PinnedConnection') as connection:
            connection.return_value.getresponse.return_value = response
            with self.assertRaises(FetchError):
                RepositoryFetcher()._get('https://api.github.com/repos/o/r', 5, float('inf'))
            connection.return_value.close.assert_called_once()


# Check GLM review instructions, HTML escaping, and the repository-review API.
class ReviewTests(unittest.TestCase):
    # Create fresh fixtures for each test so state does not leak between cases.
    def setUp(self):
        self.evidence = RepositoryEvidence('https://github.com/o/r', COMMIT,
            [{'path': 'app.py', 'content': 'eval(user_input)\n'}],
            [{'path': '<img src=x onerror=alert(1)>.png', 'reason': 'unsupported file type'}])

    # Regression check: provider prompt and output budget.
    def test_provider_prompt_and_output_budget(self):
        with patch('app.chat.InferenceClient') as factory:
            call = factory.return_value.__enter__.return_value.chat_completion
            call.return_value = SimpleNamespace(choices=[SimpleNamespace(
                message=SimpleNamespace(content='Proposed fix'), finish_reason='stop')])
            answer = HFChat('fake-token').review_repository(self.evidence)
            self.assertEqual(answer.answer, 'Proposed fix')
            args = call.call_args.kwargs
            self.assertEqual(args['max_tokens'], 8192)
            self.assertIn('UNTRUSTED', args['messages'][0]['content'])
            self.assertIn('proposed fix', args['messages'][0]['content'])
            self.assertEqual(json.loads(args['messages'][1]['content'])['files'], self.evidence.files)
            self.assertNotIn('tools', args)

    # Regression check: report escapes model and paths and marks incomplete.
    def test_report_escapes_model_and_paths_and_marks_incomplete(self):
        html = render_report(self.evidence, '<script>alert(1)</script>', 'length', 'GLM')
        self.assertNotIn('<script>', html)
        self.assertNotIn('<img', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('Incomplete', html)
        self.assertIn(COMMIT, html)
        self.assertIn('unsupported file type', html)

    # Regression check: api success errors validation and lock release.
    def test_api_success_errors_validation_and_lock_release(self):
        collector = Mock(spec=RepositoryFetcher)
        collector.fetch.return_value = self.evidence
        chat = Mock(spec=HFChat)
        chat.review_repository.return_value = ChatReply(answer='Finding and fix', finish_reason='stop')
        client = TestClient(create_app(chat, repository_fetcher=collector), base_url='http://127.0.0.1:8000')
        headers = {'Origin': 'http://127.0.0.1:8000', 'X-Chat-Request': '1'}
        body = {'url': self.evidence.url}
        self.assertEqual(client.post('/api/review-repository', json=body).status_code, 403)
        response = client.post('/api/review-repository', json=body, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Finding and fix', response.json()['report_html'])
        self.assertEqual(response.json()['skipped_files'], 1)
        self.assertEqual(client.post('/api/review-repository', json={'url': 'x', 'ref': 'x' * 201}, headers=headers).status_code, 422)
        collector.fetch.side_effect = FetchError('Collection failed')
        self.assertEqual(client.post('/api/review-repository', json=body, headers=headers).status_code, 400)
        collector.fetch.side_effect = None
        chat.review_repository.side_effect = ChatError('Provider unavailable')
        self.assertEqual(client.post('/api/review-repository', json=body, headers=headers).status_code, 502)
        chat.review_repository.side_effect = None
        self.assertEqual(client.post('/api/review-repository', json=body, headers=headers).status_code, 200)


# Run this entry point only when invoked directly, not when imported.
if __name__ == '__main__':
    unittest.main()
