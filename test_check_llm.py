"""Offline tests; inference calls are mocked and no real credentials are used."""

# Test tools and application objects; external services are replaced with mocks.
import contextlib
import io
import inspect
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import check_llm

CHAT_SIGNATURE = inspect.signature(check_llm.InferenceClient.chat_completion)


# Check CLI exit codes, credential handling, and mocked provider responses.
class ConnectionCheckTests(unittest.TestCase):
    # Capture CLI output and replace credentials and provider calls with test doubles.
    def run_check(self, token="", response=None, error=None):
        output = io.StringIO()
        with patch.dict("os.environ", {"HF_TOKEN": token}), \
             patch("sys.argv", ["check_llm.py"]), \
             patch("check_llm.InferenceClient") as factory, \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            call = factory.return_value.__enter__.return_value.chat_completion
            call.return_value = response
            call.side_effect = error
            code = check_llm.main()
        return code, output.getvalue(), factory

    # Regression check: missing token never calls provider.
    def test_missing_token_never_calls_provider(self):
        code, _, factory = self.run_check()
        self.assertEqual(code, 2)
        factory.assert_not_called()

    # Regression check: answer received.
    def test_answer_received(self):
        response = SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(content="Connection successful"), finish_reason="stop")])
        code, output, factory = self.run_check("test-credential", response)
        self.assertEqual(code, 0)
        self.assertIn("Connection successful", output)
        self.assertNotIn("test-credential", output)
        call = factory.return_value.__enter__.return_value.chat_completion
        self.assertEqual(call.call_args.kwargs["model"], "zai-org/GLM-5.3")
        self.assertNotIn("tools", call.call_args.kwargs)
        CHAT_SIGNATURE.bind(None, **call.call_args.kwargs)

    # Regression check: empty answer fails.
    def test_empty_answer_fails(self):
        code, _, _ = self.run_check("test-credential", SimpleNamespace(choices=[]))
        self.assertEqual(code, 1)

    # Regression check: provider error does not leak details.
    def test_provider_error_does_not_leak_details(self):
        error = RuntimeError("sensitive provider response")
        error.response = SimpleNamespace(status_code=403)
        code, output, _ = self.run_check("test-credential", error=error)
        self.assertEqual(code, 1)
        self.assertIn("Access denied", output)
        self.assertNotIn("sensitive", output)


# Run this entry point only when invoked directly, not when imported.
if __name__ == "__main__":
    unittest.main()
