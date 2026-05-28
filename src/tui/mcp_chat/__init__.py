"""Dashboard chat panel — talks to the hxxpsin MCP server via stdio JSON-RPC
and drives a ReAct-style tool-use loop over the existing servus-routed LLM
clients.

- [mcp_stdio.py](mcp_stdio.py) — subprocess + line-delimited JSON-RPC client
- [react_loop.py](react_loop.py) — system-prompt builder + tool-call parser
- [controller.py](controller.py) — glues the two together for the TUI panel
"""
