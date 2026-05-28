# Web App Bug Hunting Methodology

Reference methodology for timed challenges (3-hour CTF / interview format).

---

## Unifying Model — the 6 classes

Every web bug fits one of these. If your tool surfaces signals for all six,
you've covered the full space:

| Class | What it covers | hxxpsin modules |
|---|---|---|
| **Identity confusion** | IDOR, BOLA, BFLA, mass assignment, role tampering | `classifier`, `idor_probe` (two-account), `data_extractor` (post-confirm pull) |
| **State transition abuse** | Race conditions, workflow bypass, coupon reuse | `classifier` → RACE, `active_scanner`, `auth_bypass` |
| **Parser differentials** | H2↓H1 desync, request smuggling, header normalization, CT confusion, CRLF | `desync_probe`, `ct_probe`, `crlf_probe` |
| **Trust boundary violations** | SSRF, file upload, webhooks, URL fetchers | `classifier` → SSRF, `upload_probe`, `active_scanner` (SSRF), `payload_server` (OOB) |
| **Data exposure via caching/sharing** | Cache poisoning, cookie leakage, unkeyed headers, source maps | `desync_probe`, `js_deep_analyzer`, `file_grabber` |
| **Injection into interpreter** | SQLi, XSS, template injection, command injection, NoSQL, LDAP, XXE | `classifier` → INJECTION, `active_scanner`, `dom_xss_probe`, `nosql_probe`, `sql_dump` (post-confirm), `ldap_dump` (post-confirm) |

The key insight: these map directly to exploit-dev primitives.
"Identity confusion" = confused deputy. "Parser differentials" = protocol fuzzing.
"Trust boundary" = kernel/userland boundary. Same thinking, different surface.

---

## Mental model

> Map every trust boundary: browser → CDN → gateway → app → worker → storage, and every protocol translation between them.

## Priority order

1. BOLA / IDOR (highest yield in modern APIs)
2. Function-level authorization (BFLA)
3. WebSocket per-message authorization
4. GraphQL resolver authorization
5. JWT / OAuth mistakes
6. Mass assignment
7. SSRF via URL-fetching features
8. File upload / path traversal
9. Request smuggling / desync (if proxy/CDN complexity exists)
10. Race conditions / business logic
11. CORS / cache / host-header issues
12. Classic SQLi / XSS / template injection

## Step-by-step

### 1. Map the app
Open DevTools → Network tab. Click every feature. Record:
- Endpoints, HTTP methods, request bodies
- Cookies, auth headers
- Object IDs, role fields
- Error messages

### 2. Create two accounts
```
attacker@example.com
victim@example.com
```
Swap object IDs to test cross-account access.

### 3. Tamper with everything
Any field the server should not trust:
```
user_id  account_id  role  is_admin  price  quantity
status   owner_id    redirect_url    file_path   url
```

### 4. Inject lightly (safe probes first)
```
'
"
<svg/onload=alert(1)>
../../../../etc/passwd
http://127.0.0.1/
{{7*7}}
```

### 5. Auth/session checks
- Old token after logout
- Victim object ID with attacker token
- Remove Authorization header
- JWT: alg=none, kid/jku/x5u header abuse, decode for role/user_id (covered by `jwt_attack`)
- Direct /admin access
- Method/header override auth bypass — `X-Original-URL`, `X-Forwarded-For: 127.0.0.1`,
  trailing-slash / case / extension tricks (covered by `auth_bypass` + `access_replay`)

### 6. Finding write-up format
```
Title
Severity
Affected endpoint
Steps to reproduce
Expected behavior
Actual behavior
Impact
Suggested fix
```

## Attack surface taxonomy

### Auth / Session
JWT alg confusion, alg=none, kid/jku abuse, OAuth misconfig, OIDC state/nonce,
session fixation, no invalidation on logout, MFA bypass, password reset poisoning,
magic-link leakage, account enumeration, email change takeover.

### Authorization
IDOR, BOLA, BFLA, tenant isolation bypass, horizontal/vertical privesc,
role tampering, client-controlled owner_id, admin endpoint exposure,
feature-flag bypass, org invite abuse.

### REST / JSON API
Mass assignment, excessive data exposure, improper pagination access,
unsafe PATCH/PUT, method override, hidden HTTP methods, batch endpoint abuse,
JSON parser differentials, versioned/deprecated/mobile endpoint exposure.

### GraphQL
Introspection exposure, auth missing in resolvers, BOLA through node IDs,
batch query abuse, query depth/complexity DoS, alias brute force, fragment recursion,
field suggestion leakage, error message leakage, CSRF over GraphQL.

### WebSocket
Missing auth on upgrade, auth only at handshake, no per-message authz,
cross-site WebSocket hijacking, origin trust mistakes, token in WS URL,
message injection, JSON tampering, room/channel IDOR, replay, no rate limiting.

### HTTP/2 & Request Smuggling
H2 downgrade to H1 confusion, CL.TE / TE.CL / TE.TE, pseudo-header abuse,
duplicate header ambiguity, header normalization, rapid reset DoS,
request splitting, response queue poisoning, cache poisoning via header confusion.

### SSRF
Classic / blind SSRF, cloud metadata, DNS rebinding, IPv6/decimal/octal IP bypass,
redirect-based SSRF, gopher/file/dict protocol, webhook SSRF, PDF/image fetch,
open redirect → SSRF chain, parser differential (validator vs fetcher).
Common entry points: webhooks, URL previews, import-from-URL, PDF gen, image resize,
SSO metadata fetchers, Git importers.

### Open Redirect
Five discovery surfaces — query, body (form + JSON), path-segment, request-header
reflection (Host, X-Forwarded-Host, Forwarded, Referer, etc.), SPA hash routes.
Bypass classes worth exhausting before declaring "no vuln":

- **Authority confusion**: `https://target.com@evil.com/`, `https://target.com.evil.com/`,
  `https://evil.com/?target.com=1`, encoded-`@` (`%40`) variants
- **Scheme tricks**: `javascript:`, `data:`, mixed-case (`JaVaScRiPt:`),
  tab/newline injection in scheme (`java%09script:`), no-slashes (`https:evil/`)
- **Encoding evasion**: `/%2f%2f`, double-encoded `/%252f%252f`, backslash + encoded backslash
- **Whitespace**: tab/LF/NBSP prefix
- **Truncation**: null-byte (`%00`) before allowlist suffix
- **Unicode/IDN**: fullwidth solidus `／／`, ideographic period `。`
- **Fragment confusion**: `http://evil#@target/`, `http://target#evil/`
- **CRLF response splitting**: `%0d%0a` injecting Set-Cookie / Refresh /
  X-Forwarded-Host / CSP-strip / X-Frame-Options-strip / body-injection.
  Encoding variants: LF-only, CR-only, double-encoded, U+0085 NEL,
  U+2028 LINE SEP, U+2029 PARA SEP

Headers that often build redirect URLs server-side: `Host`, `X-Forwarded-Host`,
`X-Forwarded-Server`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL`,
`X-Host`, `X-HTTP-Host-Override`, `Referer`, `Forwarded` (RFC 7239).

Always baseline-check the endpoint first (404/410 = dead, 401/403 unauthed = needs-auth)
before claiming any "no vuln" verdict.

### Cache / CDN
Cache poisoning, cache deception, host/X-Forwarded-Host poisoning,
unkeyed params/headers, static/dynamic route confusion, CDN origin bypass,
private response cached publicly.

### File / Media Processing
MIME confusion, extension bypass, polyglot files, SVG script injection,
SVG SSRF/XXE, zip slip, archive bombs, metadata leakage, public bucket exposure,
signed URL abuse.

### Race Conditions
Double spend, coupon reuse, inventory race, limit bypass, password reset race,
TOCTOU authorization, concurrent transfer, idempotency-key abuse, one-time action replay.

### Frontend / Browser
DOM clobbering, prototype pollution, postMessage origin validation,
CORS misconfiguration, service worker takeover, sourcemap exposure,
client-side secret exposure, LocalStorage token theft, clickjacking, XS-Leaks, CSP bypass.

## Useful endpoints to probe
```
/actuator  /metrics  /debug  /health
/admin     /internal /swagger /openapi.json
/graphql   /graphiql /api/v1  /api/v2
```

## Module map (which module owns which step)

| Step | Module(s) |
|---|---|
| Pre-scope: subdomain/ASN/vhost (opt-in) | `surface_mapper`, `dns_recon` |
| Pre-scope + enrichment seed from Metasploit workspace (opt-in) | `msf_ingest` — pulls hosts/services into `scope.json`, folds creds/loot/notes/vulns into enrichment; optional push-back of confirmed findings as MSF vulns |
| Stack fingerprint + path probes | `stackprint`, `playbooks` |
| Browser crawl / HAR import | `crawler`, `collector`, `har_import`, `spa_router` |
| Auto register + log in | `auto_auth`, `mailbox`, `captcha`, `tunnel`, `auth_config` |
| JS bundle deep dive (routes, secrets, source maps, DOM-XSS) | `js_deep_analyzer`, `browser_verifier`, `dom_xss_probe` |
| Classify findings by category and risk | `classifier` |
| JWT attack analysis | `jwt_attack` |
| Hidden parameter discovery | `param_miner` |
| "Likely" verification + CORS + JS verify (+ local LLM) | `verifier`, `llm_verifier` |
| Open redirect (49 bypass classes × 14 surfaces) | `open_redirect` |
| Active injection (SQLi/CMDi/LDAPi/XXE/PT/SSTI) | `active_scanner`, `nosql_probe`, `auth_bypass` |
| Desync / cache / CT confusion / CRLF / WebSocket | `desync_probe`, `ct_probe`, `crlf_probe`, `ws_probe` |
| Upload bypass + replay of 401/403 with discovered tokens | `upload_probe`, `access_replay` |
| Post-confirm data extraction | `data_extractor`, `sql_dump`, `ldap_dump`, `file_grabber` |
| Response-body enrichment (users, hosts, secrets, images) | `enricher`, `secrets`, `image_analyzer` |
| Agentic confirmation (Claude / OpenAI / Ollama) | `challenge_solver`, `claude_client`, `openai_client`, `ollama_agent` |
| Report + briefing | `reporter`, `briefing_generator` |
| Encoding helpers everywhere | `codec` (URL/Base64/Unicode/HTML/JS escape) |
