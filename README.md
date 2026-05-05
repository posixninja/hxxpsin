# hxxpsin

Speed-run the recon and attack-surface mapping phase of a web app pentest or
CTF challenge. Output a prioritized report so you spend the 3-hour window on
high-value manual testing, not crawling.

## How it works

Every web vulnerability fits one of six classes. The pipeline maps directly to them:

| Vulnerability class | Module |
|---|---|
| Identity confusion — IDOR, BOLA, BFLA, mass assignment | `classifier.py` |
| State transition abuse — race conditions, workflow bypass | `classifier.py` |
| Parser differentials — H2↓H1 desync, request smuggling | `desync_probe.py` |
| Trust boundary violations — SSRF, file upload, webhooks | `classifier.py` |
| Data exposure via caching — cache poisoning, unkeyed headers | `desync_probe.py` |
| Injection into interpreter — SQLi, XSS, template injection | `classifier.py` + nuclei |

### Full pipeline

```
python3 src/main.py scan https://target.com --auth auth.json

[1] stackprint     HTTP probes only, ~10s
      ↓ StackProfile (tech stack, interesting paths, recommended tests)

[2] crawler        Playwright browser, ~60-120s
      ↓ Collector (requests, responses, WebSocket frames, JS bundles)

[3] classifier     pure Python, instant
      ↓ ClassifierResult (scored findings, by_category, ws_findings)

[4] desync_probe   async HTTP, ~30s
      ↓ DesyncResult (protocol/cache/desync findings)

[5] nuclei_gen     pure Python, instant
      ↓ targeted YAML templates, targets.txt, idor_targets.txt

[6] reporter       pure Python, instant
      ↓ report.md + report.json
```

### Quick mode (no browser, ~60s)

```
python3 src/main.py quick https://target.com
```

Use this at minute 0 while you manually log in and explore the app. Switch to
full scan once you have `auth.json`.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

## Usage

```bash
# Full scan
python3 src/main.py scan https://target.com --auth auth.json --out ./output

# Two-account IDOR mode (cross-account access testing)
python3 src/main.py scan https://target.com \
  --auth-a attacker.json \
  --auth-b victim.json

# No browser — fingerprint only
python3 src/main.py quick https://target.com

# Individual modules
python3 src/stackprint.py https://target.com
python3 src/desync_probe.py https://target.com/api/users https://target.com/dashboard
python3 src/nuclei_gen.py --help
```

## Output

```
output/
  report.md             read this first
  report.json           machine-readable, feed to other tools
  stackprint.json       raw stack fingerprint
  collector.json        raw crawl data
  js_analysis.json      JS bundle routes and constants
  verify.json           per-check verification state
  nuclei/
    targets.txt         high-score endpoint URLs
    idor_targets.txt    IDOR candidates (+1, +2, +10, +100 ID variants)
    run-nuclei.sh       3-phase nuclei execution script
    generated/
      ssrf-01-*.yaml
      mass-01-*.yaml
      graphql-introspect.yaml
```

## Source modules

| File | Role |
|---|---|
| `stackprint.py` | Async HTTP fingerprinter — 33 tech definitions, 28 path probes, JS bundle analysis |
| `playbooks.py` | Stack-specific test playbooks — 200+ concrete steps across 33 tech keys |
| `crawler.py` | Playwright browser driver — BFS navigation, network intercept, WebSocket capture |
| `collector.py` | Deduplicating request/response store |
| `classifier.py` | Risk scorer — 13 checks, 12 bug categories, per-finding evidence |
| `desync_probe.py` | Protocol/cache/desync detector — 5 safe read-only probes |
| `js_deep_analyzer.py` | Deep JS bundle analysis — route extraction, secret constants, API surface |
| `nuclei_gen.py` | Dynamic nuclei template generator — SSRF, mass-assign, GraphQL, IDOR expansion |
| `reporter.py` | Markdown + JSON report writer |
| `verifier.py` | Finding verification layer |
| `main.py` | CLI entry point — `scan` and `quick` commands |

## Test VM

A local stack of intentionally vulnerable apps for regression testing and
detection-rate benchmarking.

### Start (main stack)

```bash
cd vm && docker compose up -d
```

Services started by `docker compose`:

| Service | URL | What it tests |
|---|---|---|
| hxxpsin-target | http://localhost:8080 | Purpose-built target — all 6 bug classes |
| juice-shop | http://localhost:3000 | Angular SPA + REST + GraphQL + WebSocket |
| vampi | http://localhost:5000 | OWASP API Top 10 (Flask REST) |
| webgoat | http://localhost:9090 | Guided OWASP Top 10 lessons (Java) |
| dvwa | http://localhost:4280 | SQLi, XSS, CSRF, file upload (PHP/MySQL) |
| dvga | http://localhost:5013 | GraphQL-specific attacks |
| wrongsecrets | http://localhost:7080 | 65 secrets-exposure challenges (hardcoded creds, env vars, Docker layers) |
| vAPI | http://localhost:8000 | OWASP API Top 10 in PHP/Laravel |
| dvws-node | http://localhost:8777 | XXE, NoSQL, SOAP, JWT, CORS, GraphQL batching |
| dvna | http://localhost:9191 | OWASP Node.js vulnerable app |
| mutillidae | http://localhost:8180 | SQLi, XSS, CSRF, LFI, LDAP injection, XPATH, command injection |

### Start (multi-container apps — separate docker-compose)

```bash
bash vm/crapi/setup.sh        # OWASP crAPI — 7 microservices, real bug-bounty feel
```

| Service | URL | What it tests |
|---|---|---|
| crAPI | http://localhost:8888 | OWASP API Top 10 — microservices, business logic, SSRF |
| vAPI | http://localhost:8000 | OWASP API Top 10 in PHP — BOLA, mass assignment, injection |
| dvws-node | http://localhost:8777 | XXE, NoSQL, SOAP, CSRF, JWT brute force, GraphQL batching, deserialization |
| mutillidae | http://localhost:8180 | SQLi, XSS, CSRF, LFI, LDAP injection, XPATH, command injection |

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

The test suite runs the full hxxpsin pipeline against each registered app, scores
findings against the expected vulnerability specs in `vm/expected/`, and produces
a cross-app detection-rate report by category.

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
| `dvna.json` | DVNA |
| `wrongsecrets.json` | WrongSecrets |
| `vapi.json` | vAPI |
| `dvws-node.json` | dvws-node |
| `mutillidae.json` | Mutillidae |

### Auth configuration

`vm/auth-config.json` configures automated auth capture for each app. Supported
types: `bearer_json`, `cookie_form`, `static`, `basic`.

Captured sessions are saved to `vm/sessions/<app>.json` and can be passed to any
command with `--auth`.

### Nuclei templates

`external/templates/` contains hxxpsin-specific nuclei templates that supplement
the generated ones:

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

## Docs

- [Architecture](docs/architecture.md) — pipeline design, module reference, CLI
- [Methodology](docs/methodology.md) — 6-class model, priority order, step-by-step
- [Challenge simulation](docs/challenge_simulation.md) — timed CTF/interview playbook
- [Expected findings](docs/expected_findings.md) — ground-truth format reference
