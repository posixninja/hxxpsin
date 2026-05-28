"""A2A HTTP server for hxxpsin.

Exposes the wire shape servus's ``A2AClient`` consumes:

- ``GET  /.well-known/agent.json`` — agent card with skills array
- ``POST /``                       — JSON-RPC 2.0 ``tasks/send``
- ``GET  /tasks/{task_id}``        — poll
- ``DELETE /tasks/{task_id}``      — cancel

Why an HTTP server in addition to the MCP stdio gateway in
[mcp_agent](../mcp_agent/): MCP's single-round-trip ``tools/call`` is a
poor fit for hxxpsin's long-running work (a full scan is 5–30 min, a
single per-probe-family run can also take minutes when OOB callbacks
are involved). A2A's submit / poll / cancel lifecycle is what the
caller actually wants.

Each skill is dispatched through the shared ``InboundGate`` so
cognitiond policy applies uniformly to MCP and A2A invocations.

Boot::

    python3 -m a2a_server --port 9851
"""
