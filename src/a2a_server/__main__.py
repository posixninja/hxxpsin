"""``python3 -m a2a_server`` — boot the hxxpsin A2A HTTP server."""

from __future__ import annotations

import argparse
import logging
import sys

from aiohttp import web

from .app import build_app


def main() -> int:
    parser = argparse.ArgumentParser(description="hxxpsin A2A HTTP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9851)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s a2a_server %(levelname)s %(message)s",
    )

    app = build_app(public_url=f"http://{args.host}:{args.port}")
    web.run_app(app, host=args.host, port=args.port, print=None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
