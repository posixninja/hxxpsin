# MCP integration

hxxpsin can run as an MCP stdio server so an LLM host (secretarius /
servus, Claude Desktop, Cursor, etc.) can drive its recon, classify,
probe, and solver capabilities as tools. The implementation lives under
[src/mcp_agent/](../src/mcp_agent/).

## Launch

```bash
python3 -m mcp_agent       # from /Users/posix/Desktop/Projects/hxxpsin/src
# or, with PYTHONPATH pointing at src/:
PYTHONPATH=/Users/posix/Desktop/Projects/hxxpsin/src python3 -m mcp_agent
```

Stderr is the log channel; stdout is reserved for JSON-RPC envelopes.

## Wire protocol

[MCP 2024-11-05](https://spec.modelcontextprotocol.io) over stdio
JSON-RPC. One envelope per line. Methods implemented:

| Method | Notes |
| --- | --- |
| `initialize` | Returns serverInfo `{name: "hxxpsin", version: "0.1.0"}` |
| `notifications/initialized` | No-op |
| `tools/list` | Enumerates the tool surface (below) |
| `tools/call` | Dispatches by name; result wrapped in `content: [{type:"text", text:<json>}]` |

No `mcp` SDK dependency — the dispatcher is stdlib-only. See
[server.py](../src/mcp_agent/server.py).

## Tool surface

The tools follow an architect-gateway shape (cf.
[boogeraids/vivasecuris/mcp_launcher.py](../../boogeraids/vivasecuris/mcp_launcher.py))
rather than exposing every internal probe as its own tool.

### Synchronous probes — answer in one round-trip

| Tool | Purpose |
| --- | --- |
| `stackprint` | Fingerprint a URL's web stack and surface interesting paths / recommended tests. |
| `decode` | Recursively decode opaque tokens / cookies / params; returns the decode tree. |
| `encode_variants` | Produce labeled re-encodings of a payload for sink-decoder matching. |
| `jwt_inspect` | Structural JWT analysis + which automated attacks would apply. No network. |
| `repeat` | Burp Repeater equivalent: send one HTTP request N times with replacements. |

### Long-running scans — return a `scan_id`, poll for status

| Tool | Purpose |
| --- | --- |
| `scan_start` | Kick off a full scan or quick fingerprint. Returns immediately. |
| `scan_status` | Status (`queued` / `running` / `completed` / `failed` / `cancelled`) + elapsed. |
| `scan_list` | Recent scans (most recent first). |
| `scan_report` | `report.md` (and optionally `report.json`) for a finished scan. |
| `scan_findings` | Just the top scored findings — cheaper than the full report. |
| `scan_cancel` | SIGTERM the scan's process group. |

### Solver results

| Tool | Purpose |
| --- | --- |
| `scan_solver_results` | Verdicts from the three-stage agentic solver. Requires `scan_start(solve=true)`. |

The solver itself (`challenge_solver.py`) runs as part of the scan
pipeline rather than as a callable tool — it needs the full
`ClassifierResult` + a provider client wired up, both of which already
exist in `main.py`. The MCP surface just reads `solver.json` after the
scan finishes.

## State

Each scan owns a directory under `output/<scan_id>/`:

```
output/
  <host>-<timestamp>-<rand4>/
    state.json     ← TaskStore ledger (status, pid, exit_code, …)
    scan.log       ← combined stdout+stderr of the scan subprocess
    report.md
    report.json
    solver.json    ← only when --solve was passed
    … other artifacts (verify.json, jwt_attack.json, etc.)
```

`state.json` is the source of truth so the MCP server can restart
without losing track of in-flight work. See
[task_store.py](../src/mcp_agent/task_store.py).

## Register with servus / secretarius

1. Copy the hxxpsin entry from
   [servus/docs/agents.example.json](../../servus/docs/agents.example.json)
   into `~/.config/secretarius/agents.json`.
2. Flip `"enabled": true`.
3. Restart secretarius.

The LLM will then see tools as `mcp__hxxpsin__<name>`
(e.g. `mcp__hxxpsin__scan_start`). Scope prefix
`assistant:tool:hxxpsin` is the gating key in cognitiond policy.

## Authorization model

Every scan and probe takes an EXPLICIT target URL — no defaults from
env. Off-host targets must be supplied as request body/query in an
on-target call (matches the `--solve` host-pin enforced by
`challenge_solver.py`). Only run this against EXPLICITLY AUTHORIZED
targets: CTFs, the bundled `vm/` stack, or your own apps.

## Smoke test

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_capabilities","arguments":{}}}' \
  | PYTHONPATH=src python3 -m mcp_agent
```

Expect three JSON-RPC responses on stdout (init, tools list, capabilities).
