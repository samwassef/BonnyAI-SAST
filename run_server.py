"""Start the visitor-token server; public mode is intended behind Caddy only."""

import argparse
import os

import uvicorn

from app.main import create_app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", action="store_true", help="Use browser tokens on localhost without TLS")
    parser.add_argument("--tunnel-port", type=int, help="Container mode behind a loopback-only SSH tunnel proxy")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    if args.tunnel_port is not None and not 1 <= args.tunnel_port <= 65535:
        parser.error("Tunnel port must be between 1 and 65535")
    domain = None if args.local or args.tunnel_port else os.environ.get("APP_DOMAIN", "").strip().lower()
    if not args.local and not args.tunnel_port and not domain:
        parser.error("Set APP_DOMAIN to the public HTTPS hostname, or use --local")
    app = create_app(port=args.tunnel_port or args.port, domain=domain)
    uvicorn.run(app, host="127.0.0.1" if args.local else "0.0.0.0", port=args.port,
                workers=1, access_log=False, proxy_headers=False,
                timeout_graceful_shutdown=100, log_level="warning")


if __name__ == "__main__":
    main()
