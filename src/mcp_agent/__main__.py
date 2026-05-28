"""``python3 -m mcp_agent`` — boot the hxxpsin MCP stdio server.

Mirrors how secretarius launches its registered MCP servers (see
``servus/docs/agents.example.json``). Stderr is left as the log channel;
stdout MUST stay reserved for JSON-RPC envelopes only.
"""

from __future__ import annotations

import logging
import sys

from .server import HxxpsinMCPServer


def main() -> int:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s mcp_agent %(levelname)s %(message)s",
    )
    server = HxxpsinMCPServer()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("mcp_agent: interrupted; shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
