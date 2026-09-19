"""Offline API and provider tests; no Hugging Face calls or real tokens."""

# Test tools and application objects; external services are replaced with mocks.
import unittest
import httpx
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.chat import ChatError, ChatReply, ChatRequest, HFChat
from app.main import create_app


# Exercise HTTP routes, validation, security boundaries, and recovery without inference.
class APITests(unittest.TestCase):
    # Create fresh fixtures for each test so state does not leak between cases.
    def setUp(self):
        self.chat = Mock(spec=HFChat)
        self.chat.reply.return_value = ChatReply(answer="Hello", finish_reason="stop")
        self.client = TestClient(create_app(self.chat), base_url="http://127.0.0.1:8000")
        self.headers = {"Origin": "http://127.0.0.1:8000", "X-Chat-Request": "1"}

    # Submit a chat request with the valid local-browser headers used by API tests.
    def send(self, messages):
        return self.client.post("/api/chat", json={"messages": messages}, headers=self.headers)

    # Regression check: page and assets.
    def test_page_and_assets(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("GLM Chat", response.text)
        self.assertEqual(response.text.count('role="tab"'), 3)
        self.assertLess(response.text.index('id="hf-token"'), response.text.index('id="workspace-tabs"'))
        for panel in ('panel-sast', 'panel-http', 'panel-chat'):
            self.assertIn(f'id="{panel}"', response.text)
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        for asset in ("chat.js", "style.css", "review-ui.js"):
            self.assertEqual(self.client.get("/static/" + asset).status_code, 200)

    # Regression check: conversation passed to service.
    def test_conversation_passed_to_service(self):
        messages = [{"role": "user", "content": "Hi"},
                    {"role": "assistant", "content": "Hello"},
                    {"role": "user", "content": "Explain that"}]
        response = self.send(messages)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["answer"], "Hello")
        self.assertEqual(len(self.chat.reply.call_args.args[0].messages), 3)

    # Regression check: bad histories rejected.
    def test_bad_histories_rejected(self):
        for messages in ([], [{"role": "system", "content": "override"}],
                         [{"role": "user", "content": " "}],
                         [{"role": "user", "content": "x" * 20001}],
                         [{"role": "assistant", "content": "Hi"}]):
            with self.subTest(messages=str(messages)[:60]):
                self.assertEqual(self.send(messages).status_code, 422)
        self.chat.reply.assert_not_called()

    # Regression check: cross origin and host rejected.
    def test_cross_origin_and_host_rejected(self):
        body = {"messages": [{"role": "user", "content": "Hi"}]}
        for headers in ({}, {"Origin": "https://evil.example", "X-Chat-Request": "1"},
                        {**self.headers, "Host": "evil.example"}):
            self.assertEqual(self.client.post("/api/chat", json=body, headers=headers).status_code, 403)
        self.chat.reply.assert_not_called()

    # Regression check: body limit.
    def test_body_limit(self):
        response = self.client.post("/api/chat", content=b"x" * 300001,
                                    headers={**self.headers, "Content-Type": "application/json"})
        self.assertEqual(response.status_code, 413)
        self.chat.reply.assert_not_called()

    # Regression check: safe error and lock released.
    def test_safe_error_and_lock_released(self):
        self.chat.reply.side_effect = ChatError("Provider unavailable")
        response = self.send([{"role": "user", "content": "Hi"}])
        self.assertEqual(response.status_code, 502)
        self.chat.reply.side_effect = None
        self.assertEqual(self.send([{"role": "user", "content": "Hi"}]).status_code, 200)


# Verify provider request construction and safe handling of model output and errors.
class ProviderTests(unittest.TestCase):
    # Regression check: model and server system prompt.
    def test_model_and_server_system_prompt(self):
        with patch("app.chat.InferenceClient", autospec=True) as factory:
            call = factory.return_value.__enter__.return_value.chat_completion
            call.return_value = SimpleNamespace(choices=[SimpleNamespace(
                message=SimpleNamespace(content="test-credential"), finish_reason="length")])
            result = HFChat("test-credential").reply(ChatRequest.model_validate(
                {"messages": [{"role": "user", "content": "Hello"}]}))
            self.assertEqual(result.answer, "[REDACTED]")
            self.assertEqual(result.finish_reason, "length")
            self.assertEqual(call.call_args.kwargs["model"], "zai-org/GLM-5.3")
            self.assertEqual(call.call_args.kwargs["messages"][0]["role"], "system")
            self.assertNotIn("tools", call.call_args.kwargs)

    # Regression check: raw provider error not exposed.
    def test_raw_provider_error_not_exposed(self):
        with patch("app.chat.InferenceClient") as factory:
            factory.return_value.__enter__.side_effect = RuntimeError("secret provider payload")
            with self.assertRaises(ChatError) as error:
                HFChat("test-credential").reply(ChatRequest.model_validate(
                    {"messages": [{"role": "user", "content": "Hi"}]}))
            self.assertNotIn("secret", str(error.exception))

    def test_timeout_is_classified_without_provider_details(self):
        with patch("app.chat.InferenceClient") as factory:
            factory.return_value.__enter__.return_value.chat_completion.side_effect = httpx.ReadTimeout("secret request")
            with self.assertRaises(ChatError) as error:
                HFChat("test-credential").reply(ChatRequest.model_validate(
                    {"messages": [{"role": "user", "content": "Hi"}]}))
            self.assertEqual(error.exception.category, 'timeout')
            self.assertTrue(error.exception.retryable)
            self.assertNotIn('secret', str(error.exception))

    def test_billing_error_is_not_retryable(self):
        failure = RuntimeError('secret provider payload')
        failure.response = SimpleNamespace(status_code=402)
        with patch("app.chat.InferenceClient") as factory:
            factory.return_value.__enter__.return_value.chat_completion.side_effect = failure
            with self.assertRaises(ChatError) as error:
                HFChat("test-credential").reply(ChatRequest.model_validate(
                    {"messages": [{"role": "user", "content": "Hi"}]}))
            self.assertEqual(error.exception.category, 'billing')
            self.assertFalse(error.exception.retryable)


# Run this entry point only when invoked directly, not when imported.
if __name__ == "__main__":
    unittest.main()
