"""Start the local webpage without storing the Hugging Face token."""

# Command-line, credential, and runtime dependencies.
import argparse
import getpass
import os
import sys

import uvicorn

from app.chat import HFChat
from app.main import create_app


# Parse startup options, obtain a token, and launch the loopback-only web server.
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt-token", action="store_true")
    parser.add_argument("--provider", default="novita")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    # Prefer the environment token unless hidden interactive entry is requested.
    token = os.environ.get("HF_TOKEN", "").strip()
    if args.prompt_token:
        if not sys.stdin.isatty():
            parser.error("Hidden token entry requires an interactive terminal")
        token = getpass.getpass("Hugging Face token (hidden): ").strip()
    if not token:
        print("Run with --prompt-token or configure HF_TOKEN.", file=sys.stderr)
        return 2
    print(f"Open http://127.0.0.1:{args.port} in your browser. Press Ctrl+C to stop.")
    # Bind only to loopback and disable access logs and proxy-header interpretation.
    uvicorn.run(create_app(HFChat(token, args.provider), args.port), host="127.0.0.1",
                port=args.port, access_log=False, proxy_headers=False)
    return 0


# Run this entry point only when invoked directly, not when imported.
if __name__ == "__main__":
    raise SystemExit(main())
