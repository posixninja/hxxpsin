"""
spa_router.py — SPA route extraction without clicking.

Most modern SPAs (React/Vue/Angular/Next/Nuxt) ship their full route table inside
the JS bundle or expose it via a well-known global. The Playwright crawler's
default anchor-tag BFS misses all of it.

Two extractors:

  extract_routes_from_text(js_text) -> list[str]
      Static regex scan over a JS bundle (used by stackprint and the crawler
      both). Cheap, no browser needed.

  extract_routes_from_page(page) -> list[str]
      Runtime DOM scan via page.evaluate() on a live Playwright Page. Reads
      framework-specific globals: __NEXT_DATA__, __NUXT__, __INITIAL_STATE__,
      and walks any object on window matching /router|state|store/.

Returned paths always begin with "/" and are deduplicated.
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Static bundle patterns
# ---------------------------------------------------------------------------

# React Router v6: <Route path="/foo" element={...}/>
# (also matches the JSX-compiled object form: { path: "/foo", element: ... })
_REACT_ROUTE_RE = re.compile(
    r"""(?:<Route\s+[^>]*?path\s*=\s*["']|path\s*:\s*["'])(/[A-Za-z0-9_\-/:.]{1,80})["']""",
)

# Generic key/value form used by Vue Router, React Router config-style, Angular
# Router. Requires a sibling key like component/element/load/name within ~120
# chars to filter out non-route "path" strings.
_GENERIC_ROUTE_RE = re.compile(
    r"""path\s*:\s*["'](/[A-Za-z0-9_\-/:.\$]{0,80})["'][^{}]{0,140}?(?:component|element|load|loadChildren|name|redirect|children)\s*:""",
    re.DOTALL,
)

# Angular RouterModule.forRoot([{ path: 'login', ... }]) — note the leading slash is omitted in Angular
_ANGULAR_ROUTE_RE = re.compile(
    r"""RouterModule\.for(?:Root|Child)\(\s*\[\s*([^\]]{1,4000})\]""",
)
_ANGULAR_PATH_RE = re.compile(r"""path\s*:\s*["']([A-Za-z0-9_\-/:.\$]{0,80})["']""")

# Next.js chunk filenames hint at pages: /_next/static/chunks/pages/admin-abc123.js
# Capture the full basename; strip the trailing -[hash] in code (the hash is always
# 8-16 hex chars, but page names can also contain hyphens, so we strip in post).
_NEXT_CHUNK_RE = re.compile(
    r"""_next/static/chunks/pages/([A-Za-z0-9_\-/\[\]]+)\.js""",
)
_NEXT_HASH_SUFFIX_RE = re.compile(r"-[a-f0-9]{8,16}$")

# String-literal API-ish paths anywhere in the bundle: "/api/users", "/v1/...".
# Loose net for "looks like an endpoint we should hit".
_LOOSE_ENDPOINT_RE = re.compile(
    r"""["'](/(?:api|rest|v\d+|graphql|admin|auth)/[A-Za-z0-9_\-/:.{}]{0,120})["']""",
)

# Junk paths to strip — things that look like routes but are CSS/asset references.
_JUNK_SUFFIXES = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                  ".ico", ".woff", ".woff2", ".ttf", ".map", ".json")

# Reasonable upper bound on route count from a single bundle — prevents a
# pathological regex match from flooding the BFS queue.
_MAX_ROUTES_PER_BUNDLE = 250


def extract_routes_from_text(js_text: str) -> list[str]:
    """Regex-scan a JS bundle (or HTML) for SPA routes. Returns deduplicated
    paths starting with '/'."""
    if not js_text:
        return []

    out: list[str] = []
    seen: set[str] = set()

    def add(p: Optional[str]) -> None:
        if not p:
            return
        if not p.startswith("/"):
            p = "/" + p
        # Strip dynamic segment markers but keep the structure so the crawler
        # can fill them via param mining: /:id → /1, /[slug] → /1
        normalized = re.sub(r":[A-Za-z_]\w*", "1", p)
        normalized = re.sub(r"\[[^\]]+\]", "1", normalized)
        if any(normalized.lower().endswith(s) for s in _JUNK_SUFFIXES):
            return
        if len(normalized) > 200:
            return
        if normalized in seen:
            return
        seen.add(normalized)
        out.append(normalized)

    # 1. React Router <Route path=> + plain "path:" strings
    for m in _REACT_ROUTE_RE.finditer(js_text):
        add(m.group(1))

    # 2. Generic config-style routes (Vue Router, React Router config)
    for m in _GENERIC_ROUTE_RE.finditer(js_text):
        add(m.group(1))

    # 3. Angular RouterModule arrays — extract inner block then sub-grep paths
    for outer in _ANGULAR_ROUTE_RE.finditer(js_text):
        inner = outer.group(1)
        for m in _ANGULAR_PATH_RE.finditer(inner):
            add(m.group(1))

    # 4. Next.js page chunks — strip the build-hash suffix
    for m in _NEXT_CHUNK_RE.finditer(js_text):
        page = _NEXT_HASH_SUFFIX_RE.sub("", m.group(1))
        # Convert "_app", "_error", "_document" → skip; "index" → "/"
        if page.startswith("_"):
            continue
        if page == "index":
            add("/")
        else:
            add("/" + page)

    # 5. Loose API/REST/v1 string literals — caught net for endpoints not
    #    declared via a router but still hit by fetch()/axios in the bundle.
    for m in _LOOSE_ENDPOINT_RE.finditer(js_text):
        add(m.group(1))

        if len(out) >= _MAX_ROUTES_PER_BUNDLE:
            break

    return out[:_MAX_ROUTES_PER_BUNDLE]


# ---------------------------------------------------------------------------
# Runtime DOM extraction (used by Playwright crawler)
# ---------------------------------------------------------------------------

# JS injected into the page context. Returns a list of route-like strings
# pulled from common SPA framework globals. Defensive — every property access
# is wrapped in try/catch so a missing global doesn't crash the whole probe.
_ROUTE_DUMP_JS = r"""
() => {
  const out = new Set();
  const add = (v) => {
    if (typeof v !== 'string') return;
    if (v.length < 1 || v.length > 200) return;
    if (!v.startsWith('/')) return;
    out.add(v);
  };
  const walk = (obj, depth) => {
    if (depth > 5 || obj == null) return;
    if (typeof obj !== 'object') return;
    try {
      for (const k of Object.keys(obj)) {
        const v = obj[k];
        if ((k === 'path' || k === 'route' || k === 'url' || k === 'href') && typeof v === 'string') {
          add(v);
        } else if (k === 'routes' && Array.isArray(v)) {
          for (const r of v) walk(r, depth + 1);
        } else if (typeof v === 'object') {
          walk(v, depth + 1);
        }
      }
    } catch (e) {}
  };

  // Next.js
  try { walk(window.__NEXT_DATA__, 0); } catch (e) {}
  // Nuxt
  try { walk(window.__NUXT__, 0); } catch (e) {}
  // Generic Vuex/Redux/MobX/Pinia
  try { walk(window.__INITIAL_STATE__, 0); } catch (e) {}
  try { walk(window.__PRELOADED_STATE__, 0); } catch (e) {}
  // Apollo cache (may contain routes in fields)
  try { walk(window.__APOLLO_STATE__, 0); } catch (e) {}
  // Redux DevTools-exposed store
  try {
    const ext = window.__REDUX_DEVTOOLS_EXTENSION__;
    if (ext && ext.connect) {
      // We can't trigger devtools, but the state may also be on window.__REDUX_STORE__
    }
  } catch (e) {}
  // Any window.* matching router/state/store
  try {
    for (const k of Object.keys(window)) {
      if (/^(_{0,2}(router|state|store|routes)_{0,2})$/i.test(k)) {
        walk(window[k], 0);
      }
    }
  } catch (e) {}
  // Vue Router instance often hangs on app.$router
  try {
    const vueApp = document.querySelector('#app, #root, [data-v-app]');
    if (vueApp && vueApp.__vue_app__) {
      const router = vueApp.__vue_app__.config?.globalProperties?.$router;
      if (router && router.options && Array.isArray(router.options.routes)) {
        for (const r of router.options.routes) walk(r, 0);
      }
    }
  } catch (e) {}
  // Anchors in the DOM that reference hash routes (often invisible to the
  // crawler's _harvest because their href is "#/something")
  try {
    document.querySelectorAll('a[href]').forEach(a => {
      const href = a.getAttribute('href') || '';
      if (href.startsWith('#/')) add(href.substring(1));
      else if (href.startsWith('/#/')) add(href.substring(2));
    });
  } catch (e) {}
  return Array.from(out);
}
"""


async def extract_routes_from_page(page) -> list[str]:
    """Evaluate JS inside a live Playwright Page and return discovered routes.
    Uses framework-specific globals + DOM scan for hash anchors."""
    try:
        result = await page.evaluate(_ROUTE_DUMP_JS)
    except Exception:
        return []
    if not isinstance(result, list):
        return []
    # Final dedup + normalize
    out: list[str] = []
    seen: set[str] = set()
    for v in result:
        if not isinstance(v, str):
            continue
        if not v.startswith("/"):
            v = "/" + v
        if v not in seen and len(v) < 200:
            seen.add(v)
            out.append(v)
    return out


def is_hash_routing(html_or_js: str) -> bool:
    """Detect if the SPA uses fragment routing (e.g. /#/login).
    Sniffed from common patterns in either the initial HTML or JS bundles."""
    if not html_or_js:
        return False
    # Anchors using hash routes (post-render or SSR'd templates)
    if re.search(r"""href\s*=\s*["']#/[\w]""", html_or_js):
        return True
    # Vue Router 4
    if re.search(r"createWebHashHistory", html_or_js):
        return True
    # React Router
    if re.search(r"<HashRouter|new\s+HashRouter\b|HashRouter\s*\(", html_or_js):
        return True
    # Angular — useHash: true in RouterModule.forRoot config (minified or not).
    # Common minified shapes: `useHash:!0`, `useHash:true`, `useHash?X():Y()`
    # (the last is the strategy-selection ternary that Angular bundles only
    # when hash routing is available — strong signal in practice).
    if re.search(r"useHash\s*:\s*!0|useHash\s*:\s*true|useHash\s*\?", html_or_js):
        return True
    # HashLocationStrategy explicit binding (Angular) or withHashLocation (>= v16)
    if re.search(r"HashLocationStrategy|withHashLocation\s*\(", html_or_js):
        return True
    return False
