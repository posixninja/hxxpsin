# Expected Findings — Vulnerability Reference

Ground truth for each test app. Use this to evaluate how well hxxpsin performs.
Machine-readable specs live in `vm/expected/*.json`.

---

## How to use this

1. Run a scan: `python3 src/main.py scan http://localhost:<port> --out ./output`
2. Read `output/report.md`
3. Compare found categories against the tables below
4. Use `vm/compare.py` for automated scoring

---

## hxxpsin-target — `http://localhost:8080`

Purpose-built Flask app. Every bug is deliberate and known exactly.

| ID | Type | Endpoint | Requires Auth | hxxpsin Category | Detectable Without Auth |
|---|---|---|---|---|---|
| idor-users | IDOR/BOLA | `GET /api/users/{id}` | No | IDOR/BOLA | Yes |
| idor-invoices | IDOR/BOLA | `GET /api/invoices/{id}` | Yes | IDOR/BOLA | Partial (endpoint visible) |
| mass-assign | Mass Assignment | `PATCH /api/users/{id}` | No | Mass Assignment | Yes |
| bfla-promote | BFLA | `POST /api/users/{id}/promote` | No | BFLA | Yes |
| ssrf-fetch | SSRF | `POST /api/fetch` | No | SSRF Surface | Yes |
| upload | File Upload | `POST /api/upload` | No | File Upload | Yes |
| race-coupon | Race Condition | `POST /api/coupon/apply` | No | Race Condition | Yes |
| admin-exposure | Admin Exposure | `GET /admin` | No | Admin/Internal Exposure | Yes |
| graphql-introspect | GraphQL | `POST /graphql` | No | GraphQL | Yes |
| graphql-bola | GraphQL BOLA | `POST /graphql {user(id:N)}` | No | GraphQL | Yes |
| schema-disclosure | Info Disclosure | `GET /openapi.json` | No | Admin/Internal Exposure | Yes |
| reflection | Reflection | `GET /search?q=` | No | Injection | Yes |

**Expected hxxpsin score:** 10+ categories triggered, top finding ≥ 15.

---

## OWASP Juice Shop — `http://localhost:3000`

Angular SPA + Node.js REST + GraphQL. Challenge system tracks progress.

| ID | Type | Endpoint | Requires Auth | hxxpsin Category |
|---|---|---|---|---|
| idor-reviews | IDOR/BOLA | `GET /rest/products/{id}/reviews` | No | IDOR/BOLA |
| idor-baskets | IDOR/BOLA | `GET /rest/basket/{id}` | Yes | IDOR/BOLA |
| sqli-login | SQL Injection | `POST /rest/user/login` email field | No | Injection |
| admin-page | Admin Exposure | `GET /#/administration` | Yes (no role check) | Admin/Internal Exposure |
| admin-api | Admin Exposure | `GET /rest/admin/application-version` | No | Admin/Internal Exposure |
| jwt-secret | JWT | Weak secret on login JWT | No | Auth/Session |
| graphql | GraphQL | `POST /graphql` introspection | No | GraphQL |
| file-upload | File Upload | `POST /api/Complaints` | Yes | File Upload |
| xss-search | XSS | `GET /#/search?q=` | No | Injection |
| coupon-race | Race Condition | `POST /api/Orders` coupon field | Yes | Race Condition |
| user-list | Info Disclosure | `GET /api/Users` | Yes (no admin check) | IDOR/BOLA |

**Notes:** Most high-value bugs need auth. Run the scan with `--auth auth.json` after:
```bash
# Save login session
python3 -c "
import asyncio
from playwright.async_api import async_playwright

async def save():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        ctx = await browser.new_context()
        page = await ctx.new_page()
        await page.goto('http://localhost:3000')
        input('Register + log in, then press Enter...')
        await ctx.storage_state(path='juice-auth.json')
        await browser.close()

asyncio.run(save())
"
python3 src/main.py scan http://localhost:3000 --auth juice-auth.json --out ./juice-output
```

---

## VAmPI — `http://localhost:5000`

Flask REST API. Covers OWASP API Security Top 10 (2019).

| ID | OWASP API | Type | Endpoint | Requires Auth |
|---|---|---|---|---|
| bola-books | API1 | IDOR/BOLA | `GET /books/v1/{title}` | Yes |
| broken-auth | API2 | Auth | `POST /users/v1/login` (no rate limit) | No |
| excessive-data | API3 | Info Disclosure | `GET /users/v1` (returns passwords) | No |
| resource-authz | API5 | BFLA | `DELETE /books/v1/{title}` | Yes |
| mass-assign | API6 | Mass Assignment | `POST /users/v1/register` (admin field) | No |
| security-misconfig | API7 | Misconfig | CORS wildcard + debug mode | No |
| sqli | API8 | Injection | `POST /users/v1/login` username field | No |
| swagger-exposed | API9 | Info Disclosure | `GET /openapi3` | No |

**Quick test:** `python3 src/main.py scan http://localhost:5000 --out ./vampi-output`
VAmPI has an OpenAPI spec at `/openapi3` — hxxpsin will seed from it automatically.

---

## DVGA — Damn Vulnerable GraphQL Application — `http://localhost:5013`

Dedicated GraphQL attack surface. Good for practicing the full GraphQL kill chain.

| ID | Type | Endpoint | Requires Auth |
|---|---|---|---|
| introspection | GraphQL | `POST /graphql {__schema}` | No |
| sqli | Injection | `POST /graphql {pastes(filter:)}` | No |
| idor-nodes | IDOR/BOLA | `POST /graphql {paste(id:N)}` | No |
| batch-abuse | GraphQL | Alias brute force | No |
| deep-query | GraphQL DoS | Nested 10+ level query | No |
| field-suggestion | Info Disclosure | Typo in field name → Did you mean? | No |
| stored-xss | XSS | `mutation createPaste` | No |

**hxxpsin quick test:**
```bash
python3 src/main.py scan http://localhost:5013 --out ./dvga-output
```
GraphQL introspection template will be auto-generated.

---

## DVWA — `http://localhost:4280`

PHP + MySQL. Classic fundamentals. Login: `admin` / `password`.
Set Security Level to Low via `/DVWA/security.php`.

| ID | Type | Endpoint | Difficulty |
|---|---|---|---|
| sqli-get | SQLi | `GET /vulnerabilities/sqli/?id=` | Low |
| sqli-blind | Blind SQLi | `GET /vulnerabilities/sqli_blind/?id=` | Medium |
| cmd-injection | Command Injection | `POST /vulnerabilities/exec/` | Low |
| xss-reflected | XSS | `GET /vulnerabilities/xss_r/?name=` | Low |
| xss-stored | Stored XSS | `POST /vulnerabilities/xss_s/` | Low |
| csrf | CSRF | `POST /vulnerabilities/csrf/` | Low |
| file-upload | File Upload | `POST /vulnerabilities/upload/` | Low |
| lfi | Path Traversal | `GET /vulnerabilities/fi/?page=` | Low |
| brute-force | Auth | `GET /vulnerabilities/brute/` | Low |

**Note:** DVWA requires manual auth save since it uses PHP sessions.

---

## WebGoat — `http://localhost:9090`

Java, guided exploitation lessons. Register at `/WebGoat/registration`.

| ID | Type | Endpoint | Notes |
|---|---|---|---|
| sqli | SQL Injection | `/WebGoat/SqlInjection/attack5a` | UNION-based |
| jwt-none | JWT alg=none | `PUT /WebGoat/JWT/votings` | Strip signature |
| jwt-secret | JWT weak secret | `POST /WebGoat/JWT/secret` | Crack HS256 |
| xxe | XXE | `POST /WebGoat/XXE/simple` | Read /etc/passwd |
| ssrf | SSRF | `POST /WebGoat/SSRF/task` | Internal probe |
| idor | IDOR | `GET /WebGoat/IDOR/profile/{id}` | Numeric ID swap |
| path-traversal | Path Traversal | `POST /WebGoat/PathTraversal/` | Filename param |
| csrf | CSRF | `/WebGoat/csrf/` | No token |
| auth-bypass | Auth Bypass | `/WebGoat/auth-bypass/` | Param tampering |

---

## crAPI — `http://localhost:8888`

Separate setup: `bash vm/crapi/setup.sh`

| ID | Type | Area | Notes |
|---|---|---|---|
| bola-vehicles | IDOR/BOLA | `GET /identity/api/v2/vehicle/{id}/location` | UUID-based IDOR |
| bola-videos | IDOR/BOLA | `GET /community/api/v2/videos/{id}` | Profile video access |
| mass-assign | Mass Assignment | `PUT /identity/api/v2/user/videos/{id}` | conversion_params field |
| ssrf-video | SSRF | `POST /community/api/v2/videos/convert_video` | videoURL parameter |
| jwt-claim | JWT | Auth token | User role in JWT — tamperable |
| broken-auth | Auth | OTP endpoint | 3-digit OTP — brute forceable |
| email-verify-bypass | Auth | Account activation | Endpoint accessible without valid token |
| excess-data | Info Disclosure | `GET /community/api/v2/posts/{id}` | author.vehicleid leaks UUID |

---

## Detection rate tracking

Run after each tool update to measure regression/improvement:

```bash
# Score hxxpsin-target (should be near 100%)
python3 vm/compare.py http://localhost:8080 vm/expected/hxxpsin-target.json

# Score Juice Shop (unauthenticated — expect ~30%, needs auth for full coverage)
python3 vm/compare.py http://localhost:3000 vm/expected/juice-shop.json

# Score VAmPI
python3 vm/compare.py http://localhost:5000 vm/expected/vampi.json
```
