"""Offline pipeline regressions; these tests do not measure model detection accuracy."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch, Mock

from fastapi.testclient import TestClient

from app.chat import HFChat, ChatError
from app.main import create_app
from app.repository import RepositoryEvidence, RepositoryFetcher, render_report
from app.review import ReviewBatch, plan_batches, validate_batch, run_review, review_text
from test_repository import collect


def finding(path='src/routes.py', **updates):
    value = dict(title='SQL injection', category='SQLi', severity='High', confidence='High',
                 status='confirmed', intentional=True, description='Input changes the query.',
                 root_cause='Query concatenation', evidence=[dict(path=path, start_line=1, end_line=1)],
                 source_to_sink='Request input reaches execute without parameterization.',
                 impact='Unauthorized access to synthetic records.', prerequisites='Local test instance.',
                 exploitation_steps=['Seed a synthetic record.', 'Submit a quote and check query behavior.'],
                 code_fix='db.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                 regression_test='Assert input remains a parameter.', missing_evidence='')
    value.update(updates)
    return value


def response(findings=None, finish='stop'):
    return SimpleNamespace(answer=json.dumps({'findings': findings or [], 'limitations': []}), finish_reason=finish)


class BatchTests(unittest.TestCase):
    def evidence(self, files):
        return RepositoryEvidence('https://github.com/o/r', 'a' * 40, files, [])

    def test_webgoat_style_tests_cannot_starve_application_source(self):
        entries = [(f'src/it/java/Integration{n}Test.java', 't' * 1000) for n in range(100)]
        entries += [('src/main/java/lessons/sql/SqlEndpoint.java', 'source' * 1000),
                    ('src/main/java/lessons/xss/XssEndpoint.java', 'source' * 1000)]
        with patch.object(RepositoryFetcher, 'MAX_SOURCE', 12000):
            evidence = collect(entries)
        self.assertEqual(len(evidence.files), 2)
        self.assertTrue(all('src/main/' in f['path'] for f in evidence.files))
        self.assertEqual(len(evidence.skipped), 100)

    def test_multiple_batches_and_related_dependency_context(self):
        files = [{'path': 'src/controllers/Route.py', 'content': 'Service.run()\n' + '# padding\n' * 3500},
                 {'path': 'src/services/Service.py', 'content': 'def run(): pass\n'},
                 {'path': 'src/other.py', 'content': '# other\n' * 4000}]
        evidence = self.evidence(files)
        batches, omitted = plan_batches(evidence, max_bytes=80000, max_chars=140000)
        self.assertGreater(len(batches), 1)
        self.assertFalse(omitted)
        self.assertEqual(sorted(p for b in batches for p in b.primary_paths), sorted(f['path'] for f in files))
        route_batch = next(b for b in batches if files[0]['path'] in b.primary_paths)
        self.assertIn('src/services/Service.py', [f['path'] for f in route_batch.files])

    def test_default_batch_size_keeps_all_small_source_files(self):
        files = [{'path': f'src/module_{n}.py', 'content': 'x' * 10000} for n in range(8)]
        batches, omitted = plan_batches(self.evidence(files))
        self.assertFalse(omitted)
        self.assertEqual({p for batch in batches for p in batch.primary_paths},
                         {f['path'] for f in files})
        self.assertTrue(all(sum(len(f['content'].encode()) for f in batch.files) <= 32000
                            for batch in batches))

    def test_serialized_escaping_and_batch_limit_are_accounted_for(self):
        evidence = self.evidence([{'path': f'src/{n}.py', 'content': '\x01' * 29000} for n in range(3)])
        batches, omitted = plan_batches(evidence)
        self.assertFalse(batches)
        self.assertEqual(len(omitted), 3)
        evidence = self.evidence([{'path': f'src/{n}.py', 'content': 'x' * 30000} for n in range(6)])
        batches, omitted = plan_batches(evidence, max_batches=1, max_bytes=80000, max_chars=140000)
        self.assertEqual(len(batches), 1)
        self.assertEqual(len(omitted), 4)

    def test_schema_rejects_hallucinated_paths_lines_and_missing_fields(self):
        batch = ReviewBatch([{'path': 'src/routes.py', 'content': 'execute(user_input)\n'}], ['src/routes.py'])
        validate_batch(response([finding()]).answer, batch)
        for value in [finding(path='missing.py'), finding(evidence=[dict(path='src/routes.py', start_line=1, end_line=9)]),
                      finding(severity='Severe'), finding(status='needs_verification'), {'title': 'Missing fields'}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_batch(response([value]).answer, batch)

    def test_malformed_or_truncated_output_is_not_a_clean_review(self):
        evidence = self.evidence([{'path': 'src/routes.py', 'content': 'execute(user_input)\n'}])
        for reply in [SimpleNamespace(answer='not JSON', finish_reason='stop'), response(finish='length')]:
            result = run_review(evidence, lambda batch: reply)
            self.assertTrue(result['partial'])
            self.assertEqual(result['reviewed_paths'], [])
            self.assertEqual(len(result['failed_batches']), 1)
            self.assertEqual(len(result['skipped']), 1)
            self.assertIn('Insufficient coverage', review_text(result))

    def test_provider_failure_preserves_previous_results_and_stops_further_calls(self):
        evidence = self.evidence([{'path': f'src/{n}.py', 'content': 'x\n' * 15000} for n in range(6)])
        request = Mock(side_effect=[response([finding(path='src/0.py')]), RuntimeError('sensitive provider data')])
        progress = Mock()
        with patch('app.review.plan_batches', side_effect=lambda value: plan_batches(value, max_bytes=80000, max_chars=140000)):
            result = run_review(evidence, request, progress)
        self.assertEqual(len(result['reviewed_paths']), 2)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(len(result['skipped']), 4)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(progress.call_args.args[0]['reviewed_files'], 2)
        self.assertEqual(progress.call_args.args[0]['skipped_files'], 4)
        self.assertEqual(progress.call_args.args[0]['failed_batches'], 1)
        self.assertNotIn('sensitive provider data', json.dumps(result))

    def test_deduplication_and_structured_report_escape_every_field(self):
        evidence = self.evidence([{'path': 'src/routes.py', 'content': 'execute(user_input)\n'}])
        item = finding(title='<script>SQLi</script>', code_fix='<img src=x onerror=alert(1)>')
        result = run_review(evidence, lambda batch: response([item, item]))
        self.assertEqual(len(result['findings']), 1)
        html = render_report(evidence, review_text(result), 'stop', 'GLM', result)
        self.assertIn('class="severity high"', html)
        self.assertIn('<h3>&lt;script&gt;SQLi&lt;/script&gt;</h3>', html)
        self.assertIn('<pre><code>&lt;img', html)
        self.assertIn('Intentional educational vulnerability', html)
        self.assertIn('<ol><li>', html)
        self.assertNotIn('<script>', html)
        self.assertNotIn('<img', html)
        self.assertIn('Reviewed 1 files; skipped 0 files.', html)

    def test_empty_findings_and_skipped_files_are_partial_not_safe(self):
        evidence = self.evidence([{'path': 'src/routes.py', 'content': 'pass\n'}])
        evidence.skipped = [{'path': 'src/omitted.py', 'reason': 'review input limit'}]
        result = run_review(evidence, lambda batch: response())
        html = render_report(evidence, '', 'stop', 'GLM', result)
        self.assertIn('Partial coverage / insufficient coverage', html)
        self.assertIn('Reviewed 1 files; skipped 1 files.', html)

    def test_real_chat_orchestration_reports_failure_without_losing_inventory(self):
        evidence = self.evidence([{'path': 'src/routes.py', 'content': 'pass\n'}])
        with patch.object(HFChat, '_complete', side_effect=ChatError('Provider unavailable')):
            answer = HFChat('fake').review_repository(evidence)
        self.assertEqual(answer.finish_reason, 'incomplete')
        self.assertEqual(answer.review['reviewed_paths'], [])
        self.assertEqual(len(answer.review['skipped']), 1)

    def test_retry_transient_provider_error_once_then_report_safe_category(self):
        evidence = self.evidence([{'path': 'src/routes.py', 'content': 'pass\n'}])
        with patch.object(HFChat, '_review_batch', side_effect=[
                ChatError('secret timeout detail', 'timeout', True), response()]):
            with patch('app.chat.sleep') as pause:
                answer = HFChat('fake').review_repository(evidence)
        self.assertEqual(answer.review['reviewed_paths'], ['src/routes.py'])
        self.assertEqual(answer.review['failed_batches'], [])
        pause.assert_called_once_with(1)

        with patch.object(HFChat, '_review_batch', side_effect=ChatError('secret billing detail', 'billing')) as request:
            answer = HFChat('fake').review_repository(evidence)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(answer.review['failed_batches'][0]['reason'], 'provider billing or credits required (HTTP 402)')
        self.assertNotIn('secret', json.dumps(answer.review))

        with patch.object(HFChat, '_review_batch', side_effect=ChatError('secret timeout detail', 'timeout', True)) as request:
            with patch('app.chat.sleep'):
                answer = HFChat('fake').review_repository(evidence)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(answer.review['reviewed_paths'], [])
        self.assertEqual(answer.review['failed_batches'][0]['reason'], 'provider request timed out')
        self.assertNotIn('secret', json.dumps(answer.review))

    def test_no_progress_retrieval_and_api_uses_actual_reviewed_counts(self):
        evidence = self.evidence([{'path': 'src/routes.py', 'content': 'pass\n'}])
        collector = Mock()
        collector.fetch.return_value = evidence
        client = TestClient(create_app(HFChat('fake'), repository_fetcher=collector), base_url='http://127.0.0.1:8000')
        headers = {'Origin': 'http://127.0.0.1:8000', 'X-Chat-Request': '1'}
        self.assertEqual(client.get('/api/review-progress').status_code, 404)
        with patch.object(HFChat, '_complete', return_value=SimpleNamespace(answer='bad output', finish_reason='stop')):
            reply = client.post('/api/review-repository', json={'url': evidence.url}, headers=headers)
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json()['reviewed_files'], 0)
        self.assertEqual(reply.json()['skipped_files'], 1)
        self.assertEqual(client.get('/api/review-progress', headers=headers).status_code, 404)


if __name__ == '__main__':
    unittest.main()
