# SecurisNexus + servus integration

hxxpsin is a SecurisNexus-registered workload that:

1. **Exposes itself to servus** over both MCP stdio
   ([mcp_agent](../src/mcp_agent/)) and A2A HTTP
   ([a2a_server](../src/a2a_server/)).
2. **Routes ALL outbound LLM traffic** through servus's
   `POST /v1/chat/complete`. The Anthropic / OpenAI / Ollama clients in
   [src/claude_client.py](../src/claude_client.py),
   [src/openai_client.py](../src/openai_client.py),
   [src/llm_client.py](../src/llm_client.py) are now thin shims over
   [src/servus_client.py](../src/servus_client.py).
3. **Gates inbound calls** (MCP tool calls, A2A task submissions) through
   SecurisNexus cognitiond via
   [src/mcp_agent/inbound_gate.py](../src/mcp_agent/inbound_gate.py).
   Outbound probe traffic to authorized targets is NOT gated — that's a
   deliberate scope choice (gating that would need a per-host policy
   model that doesn't exist yet).

## Architecture

```
                       ┌─────────────────────┐
                       │  SecurisNexus       │
                       │  (snctl, certd,     │
                       │   plugin_supervisor)│
                       └────────┬────────────┘
                                │ identity + policy bootstrap
                                ▼
   servus ─MCP stdio→ hxxpsin   ─── HTTP probes ───►  authorized
          ─A2A HTTP→  (mcp_agent +                       targets
                      a2a_server +
                      ServusLLMClient)
                                ▲
                                │ POST /v1/chat/complete (bearer)
                                ▼
                       servus chat-complete
                       (gates via cognitiond)
```

## Inbound — MCP

`python3 -m mcp_agent`. Exposes atomic ops + scan lookups (full list:
[docs/mcp.md](mcp.md)). 11 tools total after the A2A refactor — anything
that does work moved to A2A.

Smoke:

```bash
HXXPSIN_COGNITION_INSECURE=1 PYTHONPATH=src python3 -m mcp_agent
```

In servus's `~/.config/secretarius/agents.json`:

```json
"hxxpsin": {
  "enabled": true,
  "command": "python3",
  "args": ["-m", "mcp_agent"],
  "cwd": "/Users/posix/Desktop/Projects/hxxpsin",
  "env": {"PYTHONPATH": "src"},
  "scope_prefix": "assistant:tool:hxxpsin"
}
```

## Inbound — A2A

`scripts/run_hxxpsin.sh` (or `python3 -m a2a_server --port 9851`).
Endpoints:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | GET | Liveness probe |
| `/.well-known/agent.json` | GET | Agent card — 29 skills across 3 agents |
| `/` | POST JSON-RPC | `tasks/send` |
| `/tasks/{task_id}` | GET | Poll task state |
| `/tasks/{task_id}` | DELETE | Cancel |

Agent surface:

- **scan** (4 skills): `scan_full`, `scan_quick`, `scan_triage`, `confirm_finding`
- **probe** (20 skills): `probe_open_redirect`, `probe_idor`, `probe_jwt`,
  `probe_ssrf`, `probe_dom_xss`, `probe_desync`, `probe_upload`,
  `probe_sql_injection`, `probe_command_injection`, `probe_xxe`,
  `probe_ssti`, `probe_path_traversal`, `probe_ldap`, `probe_nosql`,
  `probe_ws`, `probe_crlf`, `probe_auth_bypass`, `probe_cloud_metadata`,
  `probe_scm_exposure`, `probe_ct_confusion`
- **burp** (5 skills): `repeater`, `intruder_sniper`,
  `intruder_battering_ram`, `intruder_pitchfork`, `intruder_cluster_bomb`

In servus's `~/.config/secretarius/agents.json` under `a2a`:

```json
"hxxpsin": {
  "enabled": true,
  "base_url": "http://127.0.0.1:9851",
  "default_task_timeout_s": 1800,
  "scope_prefix": "assistant:agent:hxxpsin"
}
```

## Outbound — servus chat-complete

Every LLM call in hxxpsin (verifier, briefing, verdict, future tool-use
loops) goes through [src/servus_client.py](../src/servus_client.py):

```python
from servus_client import default_client

reply = await default_client().generate(
    messages=[{"role": "user", "content": "explain this finding"}],
    system="You are a senior pentester.",
    provider="claude",   # claude | openai | ollama
)
print(reply.reply, reply.cognitive_decision)
```

The three legacy provider clients (`ClaudeClient`, `OpenAIClient`,
`LLMClient`) preserve their public API for back-compat — internally
they all just instantiate `ServusLLMClient` and set `provider=...`.

Env vars (or `[servus]` in `hxxpsin.toml`):

- `SERVUS_ASSISTANT_URL` (default `http://127.0.0.1:9847`)
- `SERVUS_AGENT_TOKEN` — bearer
- `HXXPSIN_INITIATOR_SUBJECT` — caller subject for audit/cognitiond
- `HXXPSIN_DEFAULT_LLM_PROVIDER` — `claude` | `openai` | `ollama`

## Identity — SecurisNexus

Register the workload:

```bash
cd ~/Desktop/Projects/servus
export TENANT=your-company-id
export HXXPSIN_BIN="$HOME/Desktop/Projects/hxxpsin/scripts/run_hxxpsin.sh"
./securisnexus/register.sh
# writes ./securisnexus/state/hxxpsin.json with:
#   identity_id, spiffe_id, company_id, bootstrap_token, endpoint
```

The manifest lives at
[servus/securisnexus/manifests/hxxpsin.json](../../servus/securisnexus/manifests/hxxpsin.json).
Capabilities advertised: `mcp_server`, `a2a_server`, `webapp_recon`,
`webapp_probe`, `agentic_solver`. Depends on `secretarius-assistant` so
plugin_supervisor brings servus up first.

At boot, [src/identity.py](../src/identity.py) reads the state file and
exposes `Identity.actor_id` (SPIFFE URI when managed, falls back to a
local string when not). The inbound gate uses this as `actor_id` in
its cognitiond `evaluate` calls.

## Authorization model

| Channel | Gate | Authz field |
| --- | --- | --- |
| Inbound MCP `tools/call` | InboundGate → cognitiond evaluate/commit | `assistant:tool:hxxpsin:<tool>` |
| Inbound A2A `tasks/send` | InboundGate → cognitiond evaluate/commit | `assistant:tool:hxxpsin:<agent>.<skill>` |
| Outbound LLM | servus's own cognitiond pass | servus picks the scope |
| Outbound probe HTTP | NOT GATED | Caller is responsible for authorization |

Dev-mode escape hatch: `HXXPSIN_COGNITION_INSECURE=1` allows every
inbound call without contacting cognitiond. Logs a warning on boot.

## Verification

### MCP smoke

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"jwt_inspect","arguments":{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln"}}}' \
  | HXXPSIN_COGNITION_INSECURE=1 PYTHONPATH=src python3 -m mcp_agent
```

Expect 11 tools and a JWT inspection result.

### A2A smoke

```bash
HXXPSIN_COGNITION_INSECURE=1 ./scripts/run_hxxpsin.sh &
sleep 2

# Agent card — expect 29 skills
curl -s http://127.0.0.1:9851/.well-known/agent.json \
  | python3 -c "import sys,json; c=json.load(sys.stdin); print(sum(len(a['skills']) for a in c['agents']))"

# Submit an intruder task
curl -s -X POST http://127.0.0.1:9851/ -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"t1","method":"tasks/send","params":{"agentId":"burp","skillId":"intruder_sniper","params":{"url":"http://localhost:8080/§x§","payloads":["a","b"]},"metadata":{"initiatorSubject":"alice"}}}'
# → returns {result: {id: "<task_id>", state: "submitted"}}

# Poll
curl -s http://127.0.0.1:9851/tasks/<task_id>
```

### Outbound LLM through servus

Run a scan with `--solve`; servus's `/v1/chat/complete` access log
should show one POST per solver turn, and hxxpsin should make ZERO
direct requests to api.anthropic.com / api.openai.com /
localhost:11434.

```bash
export SERVUS_ASSISTANT_URL=http://127.0.0.1:9847
export SERVUS_AGENT_TOKEN=$(cat ~/.config/servus/agent_token)
python3 hxxpsin.py scan http://localhost:8080 --solve
```

### SecurisNexus end-to-end

```bash
cd ~/Desktop/Projects/servus
export TENANT=test-company
./securisnexus/register.sh
cat securisnexus/state/hxxpsin.json
# Expect identity_id, spiffe_id, bootstrap_token populated.
```

## Out of scope (next phase)

- Outbound probe gating per origin (we'd need a per-target authorization
  model that doesn't exist yet)
- Streaming responses from servus chat-complete (servus is single-shot today)
- mTLS between hxxpsin and servus (start with bearer; tighten later)
- Multi-tenant `company_id` propagation beyond what the
  `delegation_chain` already carries
