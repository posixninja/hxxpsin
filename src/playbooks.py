"""
Stack-specific test playbooks for hxxpsin.

Each key maps to an ordered list of concrete test actions.
build_recommendations() merges them into a deduplicated priority list.
"""

# Always included regardless of stack — highest-yield universal tests
_BASE = [
    "Map all API endpoints; test every object ID for BOLA/IDOR (swap IDs between two accounts)",
    "Test all state-changing endpoints (POST/PUT/PATCH/DELETE) with no auth header",
    "Test horizontal privesc: access any /user/{id} or /account/{id} endpoint with a different account's token",
    "Test vertical privesc: send role/is_admin/plan fields in any POST/PUT/PATCH body",
    "Check all file upload endpoints: SVG (script injection), polyglot, zip slip, path traversal in filename",
    "Check all URL/webhook/redirect parameters for SSRF (internal IPs, cloud metadata, gopher://)",
    "Test race conditions on one-time actions: coupon, transfer, invite, verify — concurrent requests",
]

# Ordered by priority within each playbook — more impactful tests first
PLAYBOOKS: dict[str, list[str]] = {

    # ── CDN / Edge ──────────────────────────────────────────────────────────

    "cloudflare": [
        "Test HTTP request smuggling/desync: CL.TE and TE.CL probes at CDN→origin boundary",
        "Test cache poisoning via Host header and X-Forwarded-Host manipulation",
        "Test cache deception: append /.css or /.js to authenticated API paths",
        "Check for WAF bypass via header case variation, chunked encoding, or Unicode normalization",
        "Test origin IP bypass: resolve origin directly to skip Cloudflare WAF",
    ],
    "vercel": [
        "Extract API routes from /_next/static/chunks — Vercel deploys Next.js API routes under /api/*",
        "Test edge function behavior: check Vercel-specific headers for routing hints",
        "Check /_next/data/{buildId}/*.json for server-side rendered data leakage",
        "Test cache poisoning via query parameter injection on static asset paths",
    ],
    "cloudfront": [
        "Test cache poisoning via unkeyed headers (X-Forwarded-Host, X-Original-URL)",
        "Test signed URL abuse: enumerate S3 object keys from CloudFront distribution paths",
        "Check for H2/H1 desync at CloudFront→origin translation boundary",
        "Probe origin directly if IP is discoverable to bypass CloudFront WAF",
    ],
    "fastly": [
        "Test Surrogate-Key cache poisoning",
        "Test cache deception via path confusion between static/dynamic routing",
        "Test Vary header manipulation for cache segmentation bypass",
    ],
    "akamai": [
        "Test Akamai WAF bypass via header injection and encoding tricks",
        "Test cache poisoning via Host header",
        "Test origin bypass if origin IP exposed in certificate transparency logs",
    ],
    "netlify": [
        "Check _redirects and netlify.toml for open redirects or routing logic leaks",
        "Test Netlify Edge Functions for authorization gaps",
        "Check /.netlify/functions/* for exposed serverless functions",
    ],

    # ── Frontend Frameworks ──────────────────────────────────────────────────

    "nextjs": [
        "Download and grep all /_next/static/chunks/*.js for hidden API routes, secrets, feature flags",
        "Check for source maps: /_next/static/chunks/*.js.map — reconstruct full source if present",
        "Enumerate /_next/data/{buildId}/*.json — may expose getServerSideProps data without auth check",
        "Fuzz /api/* routes found in JS bundles; test each for IDOR and missing auth",
        "Test Next.js middleware bypass: path prefix tricks that route past middleware but hit handler",
        "Test next-auth: /api/auth/callback redirect abuse, /api/auth/session token inspection",
        "Test /api/auth/csrf token reuse across sessions",
    ],
    "react": [
        "Inspect window.__STATE__ or similar hydration globals for sensitive data",
        "Check JS bundles for hardcoded API keys, tokens, or internal endpoint strings",
        "Check for prototype pollution via JSON merge or deep clone utilities in bundle",
    ],
    "vue": [
        "Inspect window.__INITIAL_STATE__ for sensitive server-injected data",
        "Check for prototype pollution via Vue.set or reactive utilities",
        "Grep JS chunks for API endpoint strings and router definitions",
    ],
    "nuxt": [
        "Check window.__NUXT__.data for server-side data leaked to client",
        "Enumerate /_nuxt/ static chunks for hidden route definitions",
        "Test /api/* Nuxt server routes for IDOR and missing auth",
    ],
    "angular": [
        "Grep main.js bundle for environment.ts constants (API URLs, keys, flags)",
        "Check for AngularJS template injection if legacy ng-app is present",
        "Inspect router definitions in bundle for admin/internal route guards",
    ],
    "sveltekit": [
        "Check /_app/immutable/ chunks for hidden endpoints and secrets",
        "Test SvelteKit form actions for CSRF and missing auth",
        "Inspect __data.json endpoints generated by SvelteKit load functions",
    ],

    # ── Backend Frameworks ───────────────────────────────────────────────────

    "express": [
        "Test for prototype pollution via JSON body with __proto__ or constructor.prototype",
        "Check for NoSQL injection if MongoDB is implied (filter params, $where, $regex)",
        "Test JWT middleware: alg=none, RS256→HS256 confusion, expired token acceptance",
        "Check connect.sid session fixation and post-logout invalidation",
        "Fuzz route parameters for IDOR; Express apps often use :id directly from req.params",
    ],
    "rails": [
        "Test mass assignment: send extra fields in any POST/PUT/PATCH body (role, admin, plan)",
        "Test CSRF: remove or replay X-CSRF-Token across sessions",
        "Test ActiveStorage signed blob URL: enumerate blob IDs or test signed URL forgery",
        "Check /rails/info/properties (common in dev mode) for environment data leakage",
        "Test IDOR in any numeric ID route — Rails apps commonly expose /resources/:id without authz",
        "Check for debug routes: /rails/mailers, /letter_opener",
    ],
    "django": [
        "Check /admin/ — Django admin is often left enabled with weak credentials",
        "Test DRF (Django REST Framework) endpoints for IDOR and missing object-level permissions",
        "Test CORS+CSRF mismatch: if CORS allows credentials, CSRF may be bypassable",
        "Check for Django debug mode: trigger a 500 with invalid input and inspect traceback",
        "Test csrftoken reuse: verify token is invalidated after logout",
    ],
    "laravel": [
        "Probe /.env — Laravel apps in misconfigured deploys expose APP_KEY and DB credentials",
        "Check /storage/logs/laravel.log for stack traces and credential leakage",
        "Test mass assignment via Laravel Eloquent: send fillable fields not expected by form",
        "Test signed route abuse: Laravel signed URLs can be reused beyond intended scope",
        "Test XSRF-TOKEN cookie: check if it's validated server-side or only client-side",
    ],
    "spring": [
        "Probe /actuator — Spring Boot actuator exposes /env, /mappings, /beans, /heapdump",
        "Check /actuator/env for secrets in environment variables",
        "Check /actuator/mappings for full route map including internal handlers",
        "Test SpEL injection in any expression-evaluating endpoint",
        "Test SSRF via Spring's RestTemplate/WebClient if URL parameters are accepted",
    ],
    "aspnet": [
        "Test ViewState tampering if __VIEWSTATE is present in forms",
        "Check /.git or /web.config exposure for source/config leakage",
        "Test ASP.NET request validation bypass via Unicode or double-encoding",
        "Check for ELMAH error log: /elmah.axd",
    ],
    "phoenix": [
        "Test Phoenix Channels (WebSocket) for room/topic authorization — join with arbitrary topic IDs",
        "Test LiveView for state manipulation via phx-click or live_patch",
        "Check for exposed Phoenix debug pages (/dashboard, /dev/mailbox)",
        "Test IDOR on Ecto-backed resources — Phoenix apps often lack object-level authz",
    ],

    # ── API Layer ────────────────────────────────────────────────────────────

    "graphql": [
        "Run introspection: POST /graphql with {__schema{types{name,fields{name}}}}",
        "If introspection blocked, use field suggestion errors to enumerate schema",
        "Test authorization in every resolver — GraphQL often has auth at transport layer only",
        "Test BOLA via global node IDs: query node(id: \"<base64-encoded-other-user-id>\")",
        "Test batch query abuse: alias the same mutation 100x in one request",
        "Test query depth DoS: deeply nested query (10+ levels) without cost limiting",
        "Test mutation authorization: try admin mutations as regular user",
        "Check /graphiql — playground exposed in production is common",
        "Test CSRF over GraphQL: application/json POST without CSRF token",
    ],
    "trpc": [
        "Enumerate tRPC procedures via type introspection in JS bundles",
        "Test each procedure for missing auth (procedures default to public in some setups)",
        "Test IDOR: tRPC procedures that accept an ID param may lack object-level authz",
        "Check for procedure names that suggest admin operations (admin.*, internal.*)",
    ],
    "websocket": [
        "Test WebSocket upgrade without valid auth token — check if server validates Authorization",
        "Test cross-site WebSocket hijacking: connect from different origin without CORS check",
        "After auth, test per-message authorization: send events targeting other users' rooms/channels",
        "Fuzz channel_id/room_id/topic in subscribe/join events for IDOR",
        "Replay old WebSocket frames with modified payload to test for replay vulnerability",
        "Test message schema: inject extra fields (role, user_id) in JSON messages",
    ],

    # ── Auth Providers ───────────────────────────────────────────────────────

    "jwt": [
        "Decode JWT (base64url): inspect header for alg, kid — inspect payload for role/user_id",
        "Test alg=none: strip signature and change alg to none",
        "Test RS256→HS256 confusion: if public key is accessible, sign HS256 token with it",
        "Test kid header injection: path traversal or SQL in kid field if backend uses it for key lookup",
        "Test jku/x5u header: point to attacker-controlled JWKS endpoint",
        "Test expired token acceptance — check if exp claim is validated",
        "Test token reuse after logout — check if tokens are blacklisted server-side",
    ],
    "nextauth": [
        "Test /api/auth/callback with manipulated redirect_uri parameter",
        "Inspect next-auth.session-token cookie: decode JWT payload for user ID and role",
        "Test /api/auth/session for IDOR: does it leak other sessions?",
        "Test CSRF on /api/auth/signout and /api/auth/signin",
        "Check if next-auth is configured with a weak secret (check .env exposure)",
    ],
    "auth0": [
        "Test Auth0 tenant isolation: check if tokens from one app work on another app's API",
        "Test Auth0 callback URL: enumerate allowed callback URLs for open redirect",
        "Inspect JWT claims: look for org_id, roles, permissions — test modification",
        "Test Auth0 Management API exposure: /api/v2/* endpoints sometimes misconfigured",
    ],
    "cognito": [
        "Decode Cognito JWT: check cognito:groups claim for group-based privilege escalation",
        "Test Cognito user pool: check if user registration is open (self-signup enabled)",
        "Test Cognito identity pool: unauthenticated role permissions may be over-permissive",
        "Check for Cognito hosted UI open redirect in logout endpoint",
    ],
    "firebase": [
        "Inspect Firebase config in JS bundle: look for apiKey, projectId, databaseURL",
        "Test Firestore/RTDB security rules: try reading /users/{other_uid} without auth",
        "Test Firebase Storage rules: try accessing gs:// URLs for other users' files",
        "Check if Firebase Functions are deployed and their endpoint paths",
    ],
    "clerk": [
        "Test Clerk session token: inspect JWT for org_id, role, membership claims",
        "Test organization-level BOLA: swap org_id in API calls between orgs",
        "Check /api/clerk/* webhooks for signature verification bypass",
    ],

    # ── Infra ────────────────────────────────────────────────────────────────

    "nginx": [
        "Test HTTP request smuggling via H2/H1 downgrade at nginx reverse proxy",
        "Test alias path traversal: if alias directive is misconfigured, /static../etc/passwd works",
        "Check nginx off-by-slash: location /files { alias /data/; } → /files../secret",
        "Test X-Accel-Redirect header injection if nginx is used as file server gateway",
    ],
    "apache": [
        "Probe /.htaccess — may be readable in misconfigured deployments",
        "Probe /server-status and /server-info if mod_status is enabled",
        "Test mod_rewrite rule bypass via double encoding or path normalization",
    ],
    "envoy": [
        "Probe Envoy admin API on port 9901: /clusters, /config_dump, /stats",
        "Test header injection via Envoy x-envoy-* header trust",
        "Test gRPC-web transcoding for injection if REST→gRPC proxy is in use",
    ],
}


def build_recommendations(detected_keys: set[str]) -> list[str]:
    """
    Merge base tests + stack-specific playbooks into a deduplicated priority list.

    Priority: base tests first, then playbooks in category order
    (cdn → frontend → backend → api → auth → infra).
    """
    category_order = ["cdn", "frontend", "backend", "api", "auth", "infra"]

    # Map each detected key to its category (defined in stackprint._TECHS)
    # We import lazily here to avoid a circular dependency on module load.
    from stackprint import _TECHS

    by_category: dict[str, list[str]] = {c: [] for c in category_order}
    for key in detected_keys:
        tech = _TECHS.get(key, {})
        cat = tech.get("category", "infra")
        if cat in by_category and key in PLAYBOOKS:
            by_category[cat].append(key)

    seen: set[str] = set()
    result: list[str] = []

    for test in _BASE:
        if test not in seen:
            result.append(test)
            seen.add(test)

    for cat in category_order:
        for key in by_category[cat]:
            for test in PLAYBOOKS.get(key, []):
                if test not in seen:
                    result.append(test)
                    seen.add(test)

    return result
