# hxxpsin — Architecture

## Purpose

Speed-run the recon/mapping and triage phase of a web app pentest or CTF
challenge. Output a prioritized attack-surface report — plus confirmed
findings, extracted data, and verifier evidence — so the tester spends a
3-hour window on judgement calls, not crawling.

---

## The Unifying Model

Every web vulnerability fits one of six classes. The pipeline maps directly
to them:

| Vulnerability class | hxxpsin modules |
|---|---|
| **Identity confusion** — IDOR, BOLA, BFLA, mass assignment | `classifier.py`, `idor_probe.py`, `data_extractor.py` |
| **State transition abuse** — race conditions, workflow bypass | `classifier.py`, `active_scanner.py` (race), `auth_bypass.py` |
| **Parser differentials** — H2↓H1 desync, request smuggling, CT confusion | `desync_probe.py`, `ct_probe.py`, `crlf_probe.py` |
| **Trust boundary violations** — SSRF, file upload, webhooks | `classifier.py`, `upload_probe.py`, `active_scanner.py` (SSRF), `payload_server.py` |
| **Data exposure via caching/sharing** — cache poisoning, cookie leakage, source maps | `desync_probe.py`, `js_deep_analyzer.py`, `file_grabber.py` |
| **Injection into an interpreter** — SQLi, XSS, template injection, NoSQL, LDAP, command, XXE | `classifier.py`, `active_scanner.py`, `dom_xss_probe.py`, `sql_dump.py`, `ldap_dump.py`, `nosql_probe.py` |

---

## Full Pipeline

```
python3 hxxpsin.py scan https://target.com --auth auth.json

[0]  surface_mapper    OPT-IN — passive subdomain/ASN/vhost mapping
[1]  stackprint        HTTP fingerprint, ~10s
[2]  crawler / HAR     Playwright BFS (Phase A pre-auth → AutoAuth → Phase B post-auth)
[3]  js_deep_analyzer  routes, secrets, DOM-XSS sources/sinks, source maps
[4]  classifier        risk scoring across 12+ bug categories
[5]  jwt_attack        alg=none, weak HS256, kid path traversal, alg confusion
[6]  param_miner       hidden parameter discovery (top-N endpoints)
[7]  verifier          active probes for "likely" findings + CORS + JS verify
[8]  open_redirect     49 bypass classes × 14 redirect surfaces
[9]  active_scanner    OPT-IN — blind SQLi, CMDi, LDAPi, XXE, path traversal, SSTI
[10] desync_probe      cache/protocol/unkeyed-header probes
[11] crlf_probe / auto-fuzz / ct_probe / ws_probe / access_replay / challenge tracker
[12] enricher          response-body mining — users, hosts, secrets, images
                       + data_extractor (when IDOR confirmed)
                       + file_grabber (source maps, .git, backups)
[13] reporter          report.md + report.json + briefing
```

Two-phase crawl: when AutoAuth is enabled and no `--auth` is supplied,
the crawler runs **Phase A** (unauthenticated discovery) before AutoAuth
registers/logs in, then **Phase B** (authenticated) with the harvested
session. The post-classifier flow then runs once across the merged
collector.

### Quick mode (no browser, ~60s)

```
python3 hxxpsin.py quick https://target.com

[0] surface_mapper (opt-in)
[1] stackprint
    └─ collector seeded from probe hits + OpenAPI spec (if any)
[3..13] same pipeline, JS/DOM-XSS/upload/etc. degrade gracefully when no
        Playwright session is available.
```

Use quick mode at minute 0 while you manually log in and explore the app.
Switch to `scan` once you have `auth.json` (or let AutoAuth provision one).

### Stage 0 — surface_mapper (opt-in)

Disabled by default. Three flags turn it on:

| Flag | What it does |
|---|---|
| `--auto-scope` | RDAP whois + passive subdomain enum (crt.sh + Wayback CDX) + ASN/CIDR via Team Cymru |
| `--port-scan {web,full}` | Per-host TCP scan (curated web ports or +50 non-web) — refuses RFC1918, link-local, and shared-CDN ranges |
| `--analyze-block` | Reverse-DNS sweep the ASN-owned CIDR — refuses prefixes wider than `--analyze-block-max` (default /20) |

Multi-host vhost differencing fires automatically when several hostnames
resolve to the same IP. Output: `output/recon/scope.json`.

---

## Source modules

| File | Role |
|---|---|
| `main.py` | CLI entry point — `scan`, `quick`, `repeat`, `fuzz` subcommands |
| `surface_mapper.py` | Stage 0 — passive subdomain/ASN/CIDR + vhost differencing |
| `dns_recon.py` | DNS recon helpers (crt.sh, Wayback CDX, RDAP, Team Cymru) |
| `stackprint.py` | Async HTTP fingerprinter — tech definitions, path probes, JS bundle hints |
| `playbooks.py` | Stack-specific test playbooks — concrete steps per tech key |
| `crawler.py` | Playwright BFS driver — network intercept, WS capture, JS harvest |
| `collector.py` | Deduplicating request/response/WS/JS-route store |
| `har_import.py` | HAR-file ingest as a substitute for live crawl |
| `auto_auth.py` | Auto register + login — wires mailbox/captcha/tunnel for verification flows |
| `auth_config.py` | Loads layered TOML operator config + env-var overrides |
| `mailbox.py` | IMAP / Mailhog / mail.tm backends for click-link / OTP verification |
| `captcha.py` | Captcha detection + headed-browser handoff |
| `tunnel.py` | cloudflared / ngrok / static public-tunnel manager |
| `payload_server.py` | Local aiohttp app serving SSRF redirect chains, hosted XXE DTDs, upload echo |
| `js_deep_analyzer.py` | Deep JS analysis — routes, secrets, DOM-XSS, source maps |
| `browser_verifier.py` | Headless Chromium for DOM-XSS / SPA verification |
| `dom_xss_probe.py` | Drives BrowserVerifier against static DOM-XSS candidates |
| `classifier.py` | Risk scorer — independent checks across 12 bug categories |
| `jwt_attack.py` | JWT attacks — alg=none, weak HS256, kid path traversal, alg confusion |
| `param_miner.py` | Hidden parameter discovery (status/length-delta heuristic) |
| `verifier.py` | Verifier subsystem — active probes for classifier "likely" findings |
| `llm_verifier.py` | Local Ollama verifier for ambiguous findings (`--llm`) |
| `open_redirect.py` | 49 bypass classes × query/body/path/header/SPA surfaces |
| `active_scanner.py` | OPT-IN injection scan — SQLi, CMDi, LDAPi, XXE, path traversal, SSTI |
| `auth_bypass.py` | Header/method-override based auth bypass discovery |
| `idor_probe.py` | Two-account cross-tenant access tests |
| `nosql_probe.py` | NoSQL operator injection |
| `desync_probe.py` | H2↓H1 desync, cache/unkeyed-header probes |
| `ct_probe.py` | Content-Type confusion (CORS-as-CSRF bypass) |
| `crlf_probe.py` | CRLF injection — response splitting / header injection |
| `ws_probe.py` | CSWSH, null-origin, unauthenticated WS, channel IDOR |
| `upload_probe.py` | Upload bypass — magic-byte spoof, double-ext, SVG XSS, polyglots |
| `access_replay.py` | Replay crawl-time 401/403 URLs with discovered bypass tokens |
| `fuzz.py` | Intruder-equivalent payload engine (sniper / battering_ram / pitchfork / cluster_bomb) |
| `repeater.py` | Single-request replay engine (Burp Repeater equivalent) |
| `intruder.py` | Auto-fuzz orchestration over discovered params |
| `payloads.py` | Built-in payload sets (xss, sqli, lfi, bypass, ids, etc.) |
| `codec.py` | Encoding helpers — URL/Base64/Unicode/HTML/JS escape variants |
| `enricher.py` | Response-body mining — users, hosts, secrets, images, unvisited URLs |
| `data_extractor.py` | Pulls per-victim records via confirmed IDOR endpoints |
| `file_grabber.py` | Source maps, .git, backup-file enumeration |
| `image_analyzer.py` | EXIF / steganography / OCR on captured images |
| `secrets.py` | Secret-pattern regexes + entropy heuristics |
| `sql_dump.py` | Schema dump + table extract after confirmed SQLi |
| `ldap_dump.py` | LDAP/AD attribute extraction after confirmed LDAP injection |
| `canary.py` | Per-scan canary tokens for OOB callback correlation |
| `recon_collector.py` | Stage-0 result aggregator (scope, hosts, ports, ASN, vhosts) |
| `challenge_solver.py` | Agentic solver — runs tool-use loop per top finding |
| `claude_client.py` | Anthropic native tool-use client |
| `openai_client.py` | OpenAI function-calling client |
| `ollama_agent.py` | Local Ollama ReAct-style JSON tool loop |
| `llm_client.py` | Shared LLM call/cache/budget plumbing |
| `challenge_tracker.py` | Juice-Shop-style challenge progress snapshot/diff |
| `briefing_generator.py` | Plain-English operator brief from the report |
| `reporter.py` | Markdown + JSON report writer |
| `tui/` | Textual TUI — Dashboard, Spider, Endpoints, Enrichment, Findings, Report, etc. |

---

## CLI reference

```bash
# Full pipeline (requires playwright install chromium)
python3 hxxpsin.py scan https://target.com --auth auth.json --out ./output

# Two-account IDOR mode
python3 hxxpsin.py scan https://target.com \
  --auth-a attacker.json \
  --auth-b victim.json

# Auto register + log in (no auth needed)
python3 hxxpsin.py scan https://target.com --auth-config ~/.config/hxxpsin/config.toml

# Operator-supplied creds (skip registration)
python3 hxxpsin.py scan https://target.com \
  --auth-email me@example.com --auth-password 'hunter2'

# Stage 0 surface expansion
python3 hxxpsin.py scan https://target.com --auto-scope --port-scan web

# Active injection scan + OOB callbacks + auto-fuzz
python3 hxxpsin.py scan https://target.com --auth auth.json \
  --active-scan --auto-fuzz --oob interactsh

# HAR import instead of live crawl
python3 hxxpsin.py scan https://target.com --har ./capture.har

# Local LLM verification (Ollama)
python3 hxxpsin.py scan https://target.com --auth auth.json \
  --llm --llm-model qwen2.5:7b

# Agentic solver (Claude / OpenAI / Ollama)
python3 hxxpsin.py scan https://target.com --auth auth.json \
  --solve --solve-provider claude --solve-top 5

# No browser — use first in a challenge while logging in manually
python3 hxxpsin.py quick https://target.com

# Standalone TUI
python3 hxxpsin.py --tui                    # blank dashboard
python3 hxxpsin.py --tui --load ./output    # load prior scan output

# Burp Repeater equivalent
python3 hxxpsin.py repeat --url https://target.com/api/users/1 \
  --header 'Authorization: Bearer ...' --replace 1 2

# Burp Intruder equivalent
python3 hxxpsin.py fuzz --url 'https://target.com/api/users/§1§' \
  --payloads ids --mode sniper --grep '"email"'

# Individual modules
python3 src/stackprint.py https://target.com
python3 src/desync_probe.py https://target.com/api/users https://target.com/dashboard
```

---

## Output structure

```
output/
  report.md             ← read this first
  report.json           ← machine-readable, feed to other tools
  briefing.md           ← plain-English operator brief
  stackprint.json       ← raw stack fingerprint
  collector.json        ← raw crawl data (requests, responses, WS, JS routes)
  js_analysis.json      ← JS bundle routes, secrets, DOM-XSS, source maps
  verify.json           ← per-finding verifier verdicts (confirmed/likely/not)
  jwt_attack.json
  param_mine.json
  active_scan.json      ← only with --active-scan
  desync.json
  open_redirect.json
  crlf_probe.json
  ct_probe.json
  ws_probe.json
  upload_probe.json
  access_replay.json
  enrichment/           ← per-entity folders
    users/
    hosts/
    secrets/
    images/
    passwords.txt       ← <user>:<plaintext_or_cracked> list
  recon/                ← Stage 0 outputs (when --auto-scope/--port-scan)
    scope.json
  grabbed/              ← source maps, .git, backups recovered
  data_extract/         ← per-victim records from confirmed IDOR
  solver.json           ← only with --solve
  nuclei/               ← generated templates + targets (when applicable)
```

---

## Test VM

```bash
cd vm && docker compose up -d
python3 vm/testsuite.py --save-auth vm/auth.json
```

Targets registered in `vm/docker-compose.yml`:

| URL | App | What it tests |
|---|---|---|
| `http://localhost:8080` | hxxpsin-target | Purpose-built — all 6 bug classes |
| `http://localhost:3000` | OWASP Juice Shop | Angular SPA + REST + GraphQL + WebSocket |
| `http://localhost:5050` | VAmPI | OWASP API Top 10 (Flask) — port 5050 because :5000 clashes with macOS AirPlay |
| `http://localhost:9090` | WebGoat | Guided OWASP Top 10 (Java) |
| `http://localhost:4280` | DVWA | SQLi, XSS, CSRF, file upload (PHP/MySQL) |
| `http://localhost:5013` | DVGA | GraphQL-specific attacks |
| `http://localhost:9191` | DVNA | OWASP Node.js vulnerable app |
| `http://localhost:7080` | WrongSecrets | 65 secrets-exposure challenges |
| `http://localhost:8000` | vAPI | OWASP API Top 10 (PHP/Laravel) |
| `http://localhost:8180` | Mutillidae | SQLi, XSS, LFI, LDAP, XPATH, CMDi |

crAPI lives in its own compose: `bash vm/crapi/setup.sh`.

Ground-truth specs live in `vm/expected/*.json` for: `crapi`, `dvga`,
`dvwa`, `hxxpsin-target`, `juice-shop`, `vampi`, `webgoat`. The test
suite (`vm/testsuite.py`) runs the full pipeline against each registered
app, scores findings against the spec, and produces a per-category
detection-rate report.

---

## Operator config

Layered TOML controls mail backends, captcha mode, the public tunnel,
the payload server, and per-target overrides. Loaded in order — later
sources win:

1. `~/.config/hxxpsin/config.toml` — personal (`chmod 600`)
2. `./hxxpsin.toml` — per-project, in scan CWD (gitignored)
3. `--auth-config PATH` — explicit override

Per-target settings auto-match by longest hostname suffix against
`[targets.<host>]` keys. Any `*_pass` / `*_secret` / `*_token` field
can be left blank and supplied via env var
(e.g. `HXXPSIN_MAIL_DEFAULT_IMAP_PASS=...`).

See [`hxxpsin.toml.example`](../hxxpsin.toml.example) for the full schema.

---

## Guardrails

- Crawler never auto-clicks: delete / remove / destroy / purchase / pay /
  submit payment / send invite.
- `PUT`, `PATCH`, `DELETE` auto-clicks require `--allow-writes`.
- The desync / CRLF / CT-confusion probes send only read-only requests
  with harmless canary header values.
- `--port-scan` refuses RFC1918, link-local, and shared-CDN ranges.
- `--analyze-block` refuses CIDR prefixes wider than `--analyze-block-max`
  (default /20).
- The solver is host-pinned: every `http_request` and `browser_eval` URL
  must be on the scanned target's host. Off-host URLs (SSRF metadata IPs
  etc.) belong inside body/query parameters of an on-target request.
- `--llm` uses local Ollama only — no data leaves the operator's machine.
  `--solve --solve-provider claude|openai` ships classifier findings and
  target responses to the chosen API.
