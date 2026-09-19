"""Visitor isolation, streaming and cancellation regressions, without live inference."""

import asyncio
import json
from threading import Event, Lock, Thread
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.chat import ChatReply, HFChat
from app.main import create_app
from app.operation import Operation, checkpoint
from app.repository import RepositoryEvidence
from test_review import finding, response


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.headers = {"Origin": "https://scan.example.com", "X-Chat-Request": "1",
                        "X-HF-Token": "hf_visitorA123"}
        self.body = {"messages": [{"role": "user", "content": "Hello"}]}

    def client(self, factory, **kwargs):
        return TestClient(create_app(domain="scan.example.com", client_factory=factory, **kwargs),
                          base_url="https://scan.example.com")

    def test_each_operation_uses_its_own_token_and_never_returns_it(self):
        clients = []
        def factory(token):
            client = Mock(spec=HFChat)
            client.reply.return_value = ChatReply(answer="Answer", finish_reason="stop")
            clients.append((token, client))
            return client
        client = self.client(factory)
        for token in ["hf_visitorA123", "hf_visitorB456"]:
            reply = client.post('/api/chat', json=self.body, headers={**self.headers, 'X-HF-Token': token})
            self.assertEqual(reply.status_code, 200)
            self.assertNotIn(token, reply.text)
            self.assertEqual(reply.headers['cache-control'], 'no-store')
        self.assertEqual([item[0] for item in clients], ['hf_visitorA123', 'hf_visitorB456'])
        self.assertIsNot(clients[0][1], clients[1][1])
        self.assertTrue(client.get('/api/config').json()['token_required'])
        for path in ['/api/review-progress', '/api/reports', '/api/history']:
            self.assertEqual(client.get(path).status_code, 404)

    def test_public_boundary_requires_token_and_https_origin(self):
        factory = Mock()
        client = self.client(factory)
        for token in ['', 'invalid secret']:
            reply = client.post('/api/chat', json=self.body, headers={**self.headers, 'X-HF-Token': token})
            self.assertEqual(reply.status_code, 401)
            self.assertNotIn('invalid secret', reply.text)
        reply = client.post('/api/chat', json=self.body, headers={**self.headers, 'Origin': 'http://scan.example.com'})
        self.assertEqual(reply.status_code, 403)
        factory.assert_not_called()
        with self.assertRaises(ValueError):
            create_app(HFChat('fake'), domain='scan.example.com')
        for value in ['https://scan.example.com', 'scan.example.com:80', '*.example.com', 'example.com/path']:
            with self.assertRaises(ValueError):
                create_app(domain=value)

    def test_all_features_require_visitor_token(self):
        factory = Mock()
        client = self.client(factory)
        headers = {k: v for k, v in self.headers.items() if k != 'X-HF-Token'}
        for path, body in [('/api/chat', self.body),
                           ('/api/analyze', {'url': 'https://example.com', 'question': 'Inspect'}),
                           ('/api/review-repository', {'url': 'https://github.com/o/r'})]:
            self.assertEqual(client.post(path, json=body, headers=headers).status_code, 401)
        factory.assert_not_called()

    def test_busy_slot_spans_requests_then_releases(self):
        entered, release = Event(), Event()
        def reply(body):
            entered.set()
            release.wait(5)
            return ChatReply(answer='done', finish_reason='stop')
        service = Mock(spec=HFChat)
        service.reply.side_effect = reply
        client = self.client(lambda token: service)
        worker = Thread(target=lambda: client.post('/api/chat', json=self.body, headers=self.headers))
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            rejected = client.post('/api/chat', json=self.body, headers=self.headers)
            self.assertEqual(rejected.status_code, 429)
            self.assertEqual(client.get('/healthz').status_code, 200)
        finally:
            release.set()
            worker.join(5)
        self.assertEqual(client.post('/api/chat', json=self.body, headers=self.headers).status_code, 200)

    def test_stream_delivers_validated_partial_report_before_final_failure(self):
        evidence = RepositoryEvidence('https://github.com/o/r', 'a' * 40,
            [{'path': f'src/{n}.py', 'content': 'x\n' * 15000} for n in range(4)], [])
        collector = Mock()
        collector.fetch.return_value = evidence
        client = self.client(HFChat, repository_fetcher=collector)
        replies = [response([finding(path='src/0.py')]), response(finish='length')]
        with patch.object(HFChat, '_complete', side_effect=replies):
            reply = client.post('/api/review-repository', json={'url': evidence.url},
                headers={**self.headers, 'Accept': 'application/x-ndjson'})
        events = [json.loads(line) for line in reply.text.splitlines()]
        self.assertEqual(events[-1]['type'], 'complete')
        snapshots = [e['data'] for e in events if e['type'] == 'snapshot']
        self.assertEqual(snapshots[0]['reviewed_files'], 2)
        self.assertEqual(snapshots[0]['skipped_files'], 2)
        self.assertTrue(snapshots[0]['review']['partial'])
        self.assertIn('SQL injection', snapshots[0]['report_html'])
        self.assertEqual(len(events[-1]['data']['review']['failed_batches']), 1)
        self.assertNotIn(self.headers['X-HF-Token'], reply.text)

    def test_cancel_holds_slot_until_call_returns_and_stops_next_call(self):
        entered, release = Event(), Event()
        calls = []
        def work(emit):
            entered.set()
            release.wait(5)
            checkpoint()
            calls.append('next provider request')
            return {}
        lock = Lock()
        lock.acquire()
        operation = Operation(work, lock)
        operation.thread.start()
        try:
            self.assertTrue(entered.wait(3))
            operation.cancelled.set()
            self.assertTrue(lock.locked())
        finally:
            release.set()
            operation.thread.join(5)
        self.assertFalse(lock.locked())
        self.assertEqual(calls, [])
        self.assertTrue(operation.done.is_set())

    def test_deadline_and_unexpected_errors_are_safe_stream_errors(self):
        for timeout, work in [(-1, lambda emit: {}), (10, Mock(side_effect=Exception('private-token')))]:
            lock = Lock()
            lock.acquire()
            operation = Operation(work, lock, timeout=timeout)
            operation.thread.start()
            async def consume():
                return [event async for event in operation.events_async()]
            events = asyncio.run(consume())
            self.assertEqual(events[-1]['type'], 'error')
            self.assertNotIn('private-token', json.dumps(events))
            self.assertFalse(lock.locked())


if __name__ == '__main__':
    unittest.main()
