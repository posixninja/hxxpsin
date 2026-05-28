"""Agentic MCP gateway for hxxpsin.

Exposes a small architect-style tool surface over MCP stdio so the
secretarius (servus) assistant — and any other MCP host — can drive
hxxpsin's recon, classification, and per-finding solver as tools.

Entrypoint: ``python3 -m mcp_agent`` (see [__main__.py](__main__.py)).

Design notes:

- The package name is ``mcp_agent`` (not ``mcp``) to avoid shadowing the
  upstream ``mcp`` SDK on sys.path. hxxpsin's wrapper inserts ``src/`` at
  position 0, so a package called ``mcp`` here would win over the SDK
  for any consumer running under the same interpreter.
- We speak MCP 2024-11-05 directly (stdio JSON-RPC, one envelope per
  line). No ``mcp`` SDK dependency — matches the dep-free approach used
  by the secretarius client at ``servus/secretarius/mcp_client.py`` and
  keeps hxxpsin's ``requirements.txt`` unchanged.
- Long-running scans return a ``scan_id`` immediately; progress is
  persisted to ``output/<scan_id>/state.json`` so the MCP process can
  restart without losing in-flight work. See [task_store.py](task_store.py).
"""
