# hxxpsin

Speed-run the recon, attack-surface mapping, and triage phase of a web app
pentest or CTF challenge. Output a prioritized report — plus confirmed
findings, extracted data, and verifier evidence — so you spend the 3-hour
window on judgement calls, not crawling.

## How it works

Every web vulnerability fits one of six classes. The pipeline maps directly
to them:

| Vulnerability class | Modules |
|---|---|
| Identity confusion — IDOR, BOLA, BFLA, mass assignment | `classifier.py`, `idor_probe.py`, `data_extractor.py` |
| State transition abuse — race, workflow bypass | `classifier.py`, `active_scanner.py`, `auth_bypass.py` |
| Parser differentials — H2↓H1 desync, CT confusion, CRLF | `desync_probe.py`, `ct_probe.py`, `crlf_probe.py` |
| Trust boundary violations — SSRF, upload, webhooks | `active_scanner.py`, `upload_probe.py`, `payload_server.py` |
| Data exposure via caching/sharing | `desync_probe.py`, `js_deep_analyzer.py`, `file_grabber.py` |
| Injection into interpreter — SQLi, XSS, NoSQL, LDAP, XXE, SSTI | `active_scanner.py`, `dom_xss_probe.py`, `sql_dump.py`, `ldap_dump.py`, `nosql_probe.py` |

### Full pipeline (`scan`)

```
python3 hxxpsin.py scan https://target.com --auth auth.json

[0]  surface_mapper    OPT-IN — passive subdomain/ASN/vhost mapping
[1]  stackprint        HTTP fingerprint
[2]  crawler / HAR     Playwright BFS (Phase A → AutoAuth → Phase B)
[3]  js_deep_analyzer  routes, secrets, DOM-XSS, source maps
[4]  classifier        risk scoring across 12+ bug categories
[5]  jwt_attack        alg=none, weak HS256, kid traversal, alg confusion
[6]  param_miner       hidden parameter discovery
[7]  verifier          active probes for "likely" findings (+ optional --llm)
[8]  open_redirect     49 bypass classes × 14 redirect surfaces
[9]  active_scanner    OPT-IN — SQLi, CMDi, LDAPi, XXE, path traversal, SSTI
[10] desync_probe      cache/protocol/unkeyed-header probes
[11] crlf / auto-fuzz / ct_probe / ws_probe / access_replay / challenge tracker
[12] enricher          users, hosts, secrets, images + data_extractor + file_grabber
[13] reporter          report.md + report.json + briefing.md
```

### Quick mode (no browser, ~60s)

```
python3 hxxpsin.py quick https://target.com
```

Use this at minute 0 while you manually log in and explore the app. Switch
to `scan` once you have `auth.json` (or let AutoAuth provision one).

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

The wrapper at `./hxxpsin.py` re-execs under `.venv/bin/python` automatically,
adds `src/` to `sys.path`, defaults a sensible `--out` directory, and
forwards everything else to `src/main.py`. Subcommands: `scan | quick | repeat | fuzz`.

## Operator config

Layered TOML controls mail backends, captcha mode, the public tunnel, the
payload server, and per-target overrides (real email for click-link
verification, TOTP secret for 2FA, etc.). Loaded in this order — later
sources win:

1. `~/.config/hxxpsin/config.toml` — personal, recommended (`chmod 600`)
2. `./hxxpsin.toml` — per-project, in scan CWD (gitignored)
3. `--auth-config PATH` — explicit override

Any `*_pass` / `*_secret` / `*_token` field can be left blank in the file and
supplied via env var instead, e.g. `HXXPSIN_MAIL_DEFAULT_IMAP_PASS=...`.

Per-target settings auto-match by longest hostname suffix against
`[targets.<host>]` keys — `api.acme-staging.com` resolves to
`[targets."acme-staging.com"]` with no flag needed.

See [`hxxpsin.toml.example`](hxxpsin.toml.example) for the full schema.

### Metasploit Framework workspace

Optional integration with an existing MSF workspace. When enabled, Stage 0
recon dedupe-merges MSF hosts/services into `scope.json`, and the enricher
folds workspace creds/loot/notes/vulns into `output/enrichment/`. Opt-in
push (`push_findings = true`) writes confirmed hxxpsin findings back as
MSF vulns — idempotent via `output/msf_pushed.json`. Two backends auto-
fallback: `msfrpcd` (msgpack-RPC, preferred) → direct PostgreSQL.

```toml
[msf]
enabled        = true
rpc_pass       = ""              # HXXPSIN_MSF_RPC_PASS
workspace      = "default"
push_findings  = false           # opt-in
push_min_score = 50
```

Optional runtime deps (install only when `[msf].enabled = true`):
`pip install msgpack "psycopg[binary]"`. The integration fails soft — if
msfrpcd is unreachable and DB creds are missing, the scan continues with
a warning and the MSF section is omitted from the report.

## Usage

```bash
# Full scan
python3 hxxpsin.py scan https://target.com --auth auth.json --out ./output

# Two-account IDOR mode (cross-account access testing)
python3 hxxpsin.py scan https://target.com \
  --auth-a attacker.json \
  --auth-b victim.json

# Auto register + log in (uses operator config)
python3 hxxpsin.py scan https://target.com --auth-config ~/.config/hxxpsin/config.toml

# Operator-supplied creds (skip registration)
python3 hxxpsin.py scan https://target.com \
  --auth-email me@example.com --auth-password 'hunter2'

# Stage 0 attack-surface expansion
python3 hxxpsin.py scan https://target.com --auto-scope --port-scan web

# Active injection + auto-fuzz + OOB callbacks
python3 hxxpsin.py scan https://target.com --auth auth.json \
  --active-scan --auto-fuzz --oob interactsh

# HAR import (skip the live crawl)
python3 hxxpsin.py scan https://target.com --har ./capture.har

# Local LLM verification (Ollama, qwen2.5:7b)
python3 hxxpsin.py scan https://target.com --auth auth.json --llm

# Agentic solver (claude | openai | ollama)
python3 hxxpsin.py scan https://target.com --auth auth.json \
  --solve --solve-provider claude

# No browser — fingerprint only
python3 hxxpsin.py quick https://target.com

# Burp Repeater equivalent
python3 hxxpsin.py repeat --url https://target.com/api/users/1 \
  --header 'Authorization: Bearer ...' --replace 1 2

# Burp Intruder equivalent
python3 hxxpsin.py fuzz --url 'https://target.com/api/users/§1§' \
  --payloads ids --mode sniper --grep '"email"'

# Standalone TUI (live dashboard + load prior output)
python3 hxxpsin.py --tui
python3 hxxpsin.py --tui --load ./output

# Individual modules
python3 src/stackprint.py https://target.com
python3 src/desync_probe.py https://target.com/api/users https://target.com/dashboard
```

## Output

```
output/
  report.md             read this first
  report.json           machine-readable
  briefing.md           plain-English operator brief
  stackprint.json       raw stack fingerprint
  collector.json        raw crawl data (requests, responses, WS, JS routes)
  js_analysis.json      JS bundle routes, secrets, DOM-XSS, source maps
  verify.json           per-finding verifier verdicts
  jwt_attack.json
  param_mine.json
  active_scan.json      only with --active-scan
  desync.json
  open_redirect.json
  crlf_probe.json
  ct_probe.json
  ws_probe.json
  upload_probe.json
  access_replay.json
  enrichment/           per-entity folders
    users/  hosts/  secrets/  images/
    passwords.txt       <user>:<plaintext_or_cracked>
  recon/                Stage 0 — scope.json (when --auto-scope)
  grabbed/              source maps, .git, backups recovered
  data_extract/         per-victim records from confirmed IDOR
  solver.json           only with --solve
  nuclei/
    targets.txt
    idor_targets.txt
    run-nuclei.sh
    generated/*.yaml
```

## Source modules

Stage 0 / recon:
`surface_mapper.py`, `dns_recon.py`, `recon_collector.py`.

Capture:
`stackprint.py`, `playbooks.py`, `crawler.py`, `collector.py`,
`har_import.py`, `spa_router.py`.

Auth automation:
`auto_auth.py`, `auth_config.py`, `mailbox.py`, `captcha.py`,
`tunnel.py`, `payload_server.py`.

Analysis:
`js_deep_analyzer.py`, `browser_verifier.py`, `dom_xss_probe.py`,
`classifier.py`, `jwt_attack.py`, `param_miner.py`, `secrets.py`,
`codec.py`.

Verification & probes:
`verifier.py`, `llm_verifier.py`, `open_redirect.py`, `desync_probe.py`,
`ct_probe.py`, `crlf_probe.py`, `ws_probe.py`, `upload_probe.py`,
`auth_bypass.py`, `idor_probe.py`, `nosql_probe.py`.

Active testing:
`active_scanner.py`, `intruder.py`, `fuzz.py`, `repeater.py`,
`payloads.py`, `access_replay.py`, `canary.py`.

Post-exploit / extract:
`enricher.py`, `data_extractor.py`, `file_grabber.py`,
`image_analyzer.py`, `sql_dump.py`, `ldap_dump.py`.

Agentic solver:
`challenge_solver.py`, `claude_client.py`, `openai_client.py`,
`ollama_agent.py`, `llm_client.py`, `challenge_tracker.py`.

Output:
`reporter.py`, `briefing_generator.py`, `tui/`.

## TUI

`./hxxpsin.py --tui` launches a Textual interface with tabs for
**Dashboard / Wizard / Target / Spider / Endpoints / Requests / Repeater /
Intruder / Probes / Findings / Enrichment / Report**. It can drive a fresh
scan or load a prior `--out` directory for offline review:

```bash
python3 hxxpsin.py --tui                    # blank dashboard
python3 hxxpsin.py --tui --load ./output    # post-mortem on a prior scan
```

While a scan is running from the CLI, the TUI streams live pipeline
events (requests captured, stage progress, canary callbacks) into the
Dashboard.

## Test VM

A local stack of intentionally vulnerable apps for regression testing and
detection-rate benchmarking.

### Start (main stack)

```bash
cd vm && docker compose up -d
```

| Service | URL | What it tests |
|---|---|---|
| hxxpsin-target | http://localhost:8080 | Purpose-built — all 6 bug classes |
| juice-shop | http://localhost:3000 | Angular SPA + REST + GraphQL + WebSocket |
| vampi | http://localhost:5050 | OWASP API Top 10 (Flask) — :5050 because :5000 clashes with macOS AirPlay |
| webgoat | http://localhost:9090 | Guided OWASP Top 10 (Java) |
| dvwa | http://localhost:4280 | SQLi, XSS, CSRF, file upload (PHP/MySQL) |
| dvga | http://localhost:5013 | GraphQL-specific attacks |
| dvna | http://localhost:9191 | OWASP Node.js vulnerable app |
| wrongsecrets | http://localhost:7080 | 65 secrets-exposure challenges |
| vAPI | http://localhost:8000 | OWASP API Top 10 (PHP/Laravel) |
| mutillidae | http://localhost:8180 | SQLi, XSS, LFI, LDAP, XPATH, CMDi |

### Start (multi-container apps — separate docker-compose)

```bash
bash vm/crapi/setup.sh        # OWASP crAPI — 7 microservices
```

| Service | URL | What it tests |
|---|---|---|
| crAPI | http://localhost:8888 | OWASP API Top 10 — microservices, business logic, SSRF |

### Run the test suite

```bash
# All apps, capture auth automatically
python3 vm/testsuite.py --save-auth vm/auth.json

# Single app
python3 vm/testsuite.py --app juice-shop --auth vm/sessions/juice-shop.json

# Verbose output with results file
python3 vm/testsuite.py --verbose --out vm/results.json

# Sane long-run defaults for expanded app sets
python3 vm/testsuite.py --timeout 10 --max-html-pages 50 --max-js-bundles 12 --max-seed-paths 30
```

The suite runs the full hxxpsin pipeline against each registered app,
scores findings against the expected vulnerability specs in `vm/expected/`,
and produces a cross-app detection-rate report by category.

### Expected findings specs

`vm/expected/` contains one JSON file per app that defines the ground-truth
findings the tool should detect. Used by the test suite for scoring and by
`vm/compare.py` for ad-hoc comparison runs.

| File | App |
|---|---|
| `hxxpsin-target.json` | Purpose-built target |
| `juice-shop.json` | OWASP Juice Shop |
| `vampi.json` | VAmPI |
| `dvga.json` | DVGA |
| `dvwa.json` | DVWA |
| `webgoat.json` | WebGoat |
| `crapi.json` | crAPI |

### Auth configuration

`vm/auth-config.json` configures automated auth capture for each app.
Supported types: `bearer_json`, `cookie_form`, `static`, `basic`.

Captured sessions are saved to `vm/sessions/<app>.json` and can be passed
to any command with `--auth`.

### Nuclei templates

`external/templates/` contains hxxpsin-specific nuclei templates that
supplement the dynamically generated ones:

| Template | What it finds |
|---|---|
| `hxxpsin-auth-bypass.yaml` | Authentication bypass patterns |
| `hxxpsin-debug-endpoints.yaml` | Exposed debug/admin endpoints |
| `hxxpsin-graphql-detect.yaml` | GraphQL introspection and schema exposure |
| `hxxpsin-idor-confirm.yaml` | IDOR/BOLA confirmation probes |
| `hxxpsin-jwt-detect.yaml` | JWT none-alg, weak secrets, algorithm confusion |
| `hxxpsin-open-api.yaml` | OpenAPI/Swagger spec exposure |
| `hxxpsin-reflect.yaml` | Reflected parameter probes |
| `hxxpsin-source-map.yaml` | JavaScript source map exposure |

## LLM-assisted modes

### Local verification (`--llm`)

After the classifier scores endpoints, hand "likely" findings to a local
Ollama model for plausibility triage. All inference stays on the operator's
machine.

```bash
python3 hxxpsin.py scan https://target.com --auth auth.json \
  --llm --llm-model qwen2.5:7b
```

| Flag | Default | Purpose |
|---|---|---|
| `--llm` | off | Enable local LLM verification |
| `--llm-host` | `http://localhost:11434` | Ollama HTTP endpoint |
| `--llm-model` | `qwen2.5:7b` | Ollama model tag (must be `ollama pull`-ed) |
| `--llm-budget` | 50 | Max LLM calls per scan (cached calls free) |

### Agentic solver (`--solve`)

For each of the top findings, run a tool-use loop (the same Burp Repeater
work a human operator would do, but driven by an LLM). Per-finding result
goes to `output/solver.json` and is rendered as a `Solver` section in
`report.md` with confirmed / refuted / inconclusive verdicts.

| Tool | What the model does with it |
|---|---|
| `http_request` | Send arbitrary requests (auth headers attached) to confirm IDOR, mass-assign, SSRF, etc. |
| `browser_eval` | Open the target in headless Chromium with captured auth and run JS — DOM-XSS, SPA flows, postMessage probes |
| `read_finding` | Pull the full evidence + request/response the classifier captured |
| `run_nuclei` | Execute one of the generated nuclei templates against the target |

All providers now route through **servus** (the cognition-gated LLM
gateway). API keys live on servus, not in hxxpsin's environment.

```bash
export SERVUS_ASSISTANT_URL=http://127.0.0.1:9847   # default
export SERVUS_AGENT_TOKEN=$(cat ~/.config/servus/agent_token)
python3 hxxpsin.py scan https://target.com --auth auth.json --solve
```

See [docs/integration.md](docs/integration.md) for the full MCP + A2A +
SecurisNexus wiring (and the dev-mode escape hatch
`HXXPSIN_COGNITION_INSECURE=1` for local work without cognitiond).

| Flag | Default | Purpose |
|---|---|---|
| `--solve` | off | Enable the solver |
| `--solve-provider` | `claude` | `claude` (Anthropic) / `openai` (function-calling) / `ollama` (local ReAct) |
| `--solve-model` | per provider | `claude-opus-4-7` / `gpt-5.5` / `qwen2.5:7b` |
| `--solve-top` | 5 | Number of top classifier findings to investigate |
| `--solve-max-turns` | 10 | Max agent turns per finding |
| `--solve-budget` | 40 | Hard cap on total API calls per scan |
| `--solve-thinking` | 0 | Claude extended-thinking tokens per turn |
| `--solve-verbose` | off | Stream prompts / tool calls to stderr |
| `--nuclei-bin` | `nuclei` | Path to the nuclei binary for `run_nuclei` |

The solver is host-pinned: every `http_request` and `browser_eval` URL must
be on the scanned target's host. Off-host URLs (SSRF metadata IPs, etc.)
belong inside body/query parameters of an on-target request.

Use this only on EXPLICITLY AUTHORIZED targets (CTF apps, the bundled `vm/`
stack, your own apps). Unlike `--llm` (local Ollama), `--solve-provider
claude|openai` ships classifier findings and target responses to the
chosen API.

## Integration mode (MCP + A2A + SecurisNexus)

hxxpsin can run as a SecurisNexus-registered agent inside the
servus / secretarius stack:

- **MCP stdio** ([src/mcp_agent/](src/mcp_agent/)) — atomic ops and
  scan lookups. Servus invokes this per-tool-call.
- **A2A HTTP** ([src/a2a_server/](src/a2a_server/)) — 29 skills across
  three agents (`scan` / `probe` / `burp`) with the submit / poll /
  cancel lifecycle. Boot with `./scripts/run_hxxpsin.sh` (or
  `python3 -m a2a_server --port 9851`).
- **Outbound LLM** — every call goes through servus's
  `POST /v1/chat/complete`. The provider clients in
  [src/claude_client.py](src/claude_client.py),
  [src/openai_client.py](src/openai_client.py),
  [src/llm_client.py](src/llm_client.py) are thin shims over
  [src/servus_client.py](src/servus_client.py).
- **Inbound gate** — every MCP/A2A call is authorized through
  SecurisNexus cognitiond by
  [src/mcp_agent/inbound_gate.py](src/mcp_agent/inbound_gate.py).
- **Workload identity** — register with
  `servus/securisnexus/register.sh` using the manifest at
  `servus/securisnexus/manifests/hxxpsin.json`.

See [docs/integration.md](docs/integration.md) for the operator guide
and [docs/mcp.md](docs/mcp.md) for the MCP tool surface.

## Docs

- [Architecture](docs/architecture.md) — pipeline design, module reference, CLI
- [Methodology](docs/methodology.md) — 6-class model, priority order, step-by-step
- [Challenge simulation](docs/challenge_simulation.md) — timed CTF/interview playbook
- [Expected findings](docs/expected_findings.md) — ground-truth format reference
- [Integration](docs/integration.md) — MCP + A2A + SecurisNexus + servus wiring
- [MCP tool surface](docs/mcp.md) — exposed MCP tools and the agent card
