# hxxpsin — Architecture

## Purpose

Speed-run the recon/mapping phase of a web app pentest or CTF challenge.
Output a prioritized attack surface report so the tester spends a 3-hour window
on high-value manual testing, not crawling.

---

## The Unifying Model

Every web vulnerability fits one of six classes. The tool's modules map directly to them:

| Vulnerability class | hxxpsin module |
|---|---|
| **Identity confusion** — IDOR, BOLA, BFLA, mass assignment | `classifier.py` (IDOR/BOLA, MASS_ASSIGN, BFLA checks) |
| **State transition abuse** — race conditions, workflow bypass | `classifier.py` (RACE check) |
| **Parser differentials** — H2↓H1 desync, request smuggling | `desync_probe.py` (protocol probe) |
| **Trust boundary violations** — SSRF, file upload, webhooks | `classifier.py` (SSRF, UPLOAD checks) |
| **Data exposure via caching/sharing** — cache poisoning, cookie leakage | `desync_probe.py` (cacheability, cookie_key, unkeyed_hdr probes) |
| **Injection into an interpreter** — SQLi, XSS, template injection | `classifier.py` (INJECTION check) + nuclei templates |

---

## Full Pipeline

```
python3 main.py scan https://target.com --auth auth.json

[1] stackprint     ← HTTP probes only, ~10s
      ↓ StackProfile (detected tech, interesting paths, recommended tests)

[2] crawler        ← Playwright browser, ~60-120s
      ↓ Collector (requests, responses, WebSocket frames, JS bundle content)

[3] classifier     ← pure Python, instant
      ↓ ClassifierResult (scored findings, by_category, ws_findings, js_routes)

[4] desync_probe   ← async HTTP, ~30s
      ↓ DesyncResult (protocol/cache/unkeyed-header findings)

[5] open_redirect  ← async HTTP (+ optional Playwright), ~10-30s
      ↓ OpenRedirectResult (49 bypass classes × N redirect surfaces)

[6] nuclei_gen     ← pure Python, instant
      ↓ GenResult (targeted YAML templates, targets.txt, idor_targets.txt)

[7] reporter       ← pure Python, instant
      ↓ report.md + report.json
```

### Quick mode (no browser, ~60s total)

```
python3 main.py quick https://target.com

[1] stackprint → [3] classifier (from probe hits) → [4] desync_probe → [5] nuclei_gen → [6] reporter
```

Use quick mode at minute 0 while you manually log in and explore the app.
Switch to full scan once you have `auth.json`.

---

## Source modules

| File | Role |
|---|---|
| `stackprint.py` | Async HTTP fingerprinter — 33 tech definitions, 28 path probes, JS bundle analysis |
| `playbooks.py` | Stack-specific test recommendations — 200+ concrete steps across 33 tech keys |
| `crawler.py` | Playwright browser driver — BFS navigation, network intercept, WebSocket capture, JS harvest |
| `collector.py` | Deduplicating data store — requests, responses, WebSockets, JS routes, constants |
| `classifier.py` | Risk scorer — 13 independent checks, 12 bug categories, per-finding evidence |
| `desync_probe.py` | Protocol/cache/desync detector — 5 safe read-only probes |
| `open_redirect.py` | Open-redirect probe — 49 generic bypass classes across query / body / path / 14 request-header surfaces, with optional Playwright SPA verification |
| `nuclei_gen.py` | Dynamic nuclei template generator — SSRF, mass-assign, GraphQL, IDOR target expansion |
| `reporter.py` | Markdown + JSON report writer |
| `main.py` | Single CLI entry point — `scan` and `quick` commands |

---

## CLI reference

```bash
# Full pipeline (requires playwright install chromium)
python3 src/main.py scan https://target.com --auth auth.json --out ./output

# Two-account IDOR mode
python3 src/main.py scan https://target.com \
  --auth-a attacker.json \
  --auth-b victim.json

# No browser — use first in a challenge while logging in manually
python3 src/main.py quick https://target.com

# Individual modules
python3 src/stackprint.py https://target.com
python3 src/desync_probe.py https://target.com/api/users https://target.com/dashboard
python3 src/nuclei_gen.py --help
```

---

## Output structure

```
output/
  report.md          ← read this first
  report.json        ← machine-readable, feed to other tools
  stackprint.json    ← raw stack fingerprint
  collector.json     ← raw crawl data
  nuclei/
    targets.txt      ← high-score endpoint URLs
    idor_targets.txt ← IDOR candidates with ID variants (+1, +2, +10, +100)
    run-nuclei.sh    ← 3-phase nuclei execution script
    generated/
      ssrf-01-*.yaml
      mass-01-*.yaml
      graphql-introspect.yaml
```

---

## Test VM

```bash
cd vm && bash run.sh          # start all three targets
bash verify.sh                # 13-check regression suite
```

Targets:
- `http://localhost:8080` — hxxpsin-target (purpose-built, covers all 6 vulnerability classes)
- `http://localhost:3000` — OWASP Juice Shop (Angular + REST + GraphQL + WebSocket)
- `http://localhost:5050` — VAmPI (Flask REST, OWASP API Top 10) — port 5050 because :5000 clashes with macOS AirPlay Receiver
- `http://localhost:5013` — DVGA (GraphQL-specific attacks)
- `http://localhost:9090` — WebGoat (Java)
- `http://localhost:4280` — DVWA (PHP)
- `http://localhost:7080` — WrongSecrets
- `http://localhost:8000` — vAPI (PHP/Laravel)
- `http://localhost:8180` — Mutillidae
- `http://localhost:9191` — DVNA (Node.js)

---

## Guardrails

The crawler never auto-clicks:
- delete / remove / destroy / purchase / pay / submit payment / send invite

`PUT`, `PATCH`, `DELETE` auto-clicks require `--allow-writes`.
The desync probe sends only GET requests with harmless canary header values.
The nuclei generator targets SSRF probes at `http://127.0.0.1/` only.
