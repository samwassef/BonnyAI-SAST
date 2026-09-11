"""One bounded GLM-5.3 chat request through Hugging Face Inference Providers."""

# Command-line, credential, and runtime dependencies.
import argparse
import getpass
import os
import sys

from huggingface_hub import InferenceClient

MODEL = "zai-org/GLM-5.3"


# Run a small authenticated model request and return a meaningful CLI exit code.
def main() -> int:
    """Check authenticated inference without printing credentials or raw errors."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt-token", action="store_true",
                        help="Read token securely from the terminal without saving it")
    parser.add_argument("--provider", default="novita",
                        help="Hugging Face inference provider (default: novita)")
    args = parser.parse_args()
    # Obtain credentials from the environment or a hidden prompt without saving them.
    token = os.environ.get("HF_TOKEN", "").strip()
    if args.prompt_token:
        if not sys.stdin.isatty():
            print("Token entry requires an interactive terminal.", file=sys.stderr)
            return 2
        token = getpass.getpass("Hugging Face token (hidden): ").strip()
    if not token:
        print("No HF_TOKEN configured. Run with --prompt-token in your terminal.",
              file=sys.stderr)
        return 2

    # Make one small inference request to verify the token and provider route.
    try:
        with InferenceClient(provider=args.provider, api_key=token, timeout=90) as client:
            result = client.chat_completion(
                model=MODEL,
                messages=[{"role": "user", "content": "Reply with exactly: Connection successful"}],
                max_tokens=256,
                extra_body={"reasoning_effort": "low"},
            )
        if not result.choices or not result.choices[0].message.content:
            print("API responded but returned no answer; access is not fully verified. "
                  "The model may have exhausted its output budget.", file=sys.stderr)
            return 1
        print(f"Model: {MODEL}\nProvider: {args.provider}")
        # Treat output as untrusted text; do not allow terminal control characters.
        answer = result.choices[0].message.content.replace(token, "[REDACTED]")
        print("Answer: " + ascii(answer))
        print(f"Finish reason: {result.choices[0].finish_reason}")
        return 0
    except Exception as exc:
        # Provider error bodies may contain sensitive request data: never print them.
        status = getattr(getattr(exc, "response", None), "status_code", None)
        messages = {
            401: "Authentication failed. Check your Hugging Face token.",
            402: "Billing or inference credits are required.",
            403: "Access denied. Check Inference Providers permissions and model access.",
            404: "Model or provider route is unavailable.",
            429: "Rate limit reached. Try again later.",
        }
        print(messages.get(status, "Inference failed. Check connectivity, provider availability, "
                           "and supported request parameters."), file=sys.stderr)
        return 1


# Run this entry point only when invoked directly, not when imported.
if __name__ == "__main__":
    raise SystemExit(main())
