"""
intruder.py — Payload-position fuzzer (Burp Intruder equivalent).

Mark injection points with §...§ in URL, headers, or body. The original
value between the markers is the default/baseline; Intruder replaces it.

Attack modes:
  sniper        One payload at a time, one position; others keep their default (default)
  battering_ram Same payload applied to all positions simultaneously
  pitchfork     Multiple payload lists, one per position, iterated in lockstep
  cluster_bomb  Cartesian product of all payload lists across all positions

Built-in payload sets (pass as --payloads <name>):
  xss, sqli, lfi, bypass, ids, usernames, passwords, methods, extensions

Usage:
  python3 main.py fuzz --url "https://target.com/api/user/§1§" --payloads ids
  python3 main.py fuzz --url "https://t.com/login" --method POST \\
      --body '{"username":"§admin§","password":"§pass§"}' \\
      --payloads usernames --payloads passwords --mode pitchfork
  python3 main.py fuzz --request req.txt --payloads /path/to/list.txt \\
      --mode cluster_bomb --grep "admin" --filter-status 200
"""

import asyncio
import itertools
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

import httpx

import payloads as _payloads

_MARKER_RE = re.compile(r"§([^§\n]*)§")


# ---------------------------------------------------------------------------
# Built-in payload sets — loaded from PayloadsAllTheThings at runtime
# Large sets (>50 entries) are lazy-loaded; small sets stay inline.
# ---------------------------------------------------------------------------

def _build_builtin_payloads() -> dict[str, list[str]]:
    return {
        # XSS: quick 38-payload set from PAT; use 'xss_full' for 666-payload set
        "xss":          _payloads.xss_quick(),
        "xss_full":     _payloads.xss_full(),
        "xss_poly":     _payloads.xss_polyglots(),

        # SQL: PAT auth-bypass list (195 combined)
        "sqli":         _payloads.sql_auth_bypass()[:80],
        "sqli_error":   _payloads.sql_error()[:60],
        "sqli_time":    _payloads.sql_time()[:30],

        # LFI: 100 from JHADDIX + 30 Windows
        "lfi":          _payloads.lfi_unix()[:100] + _payloads.lfi_windows()[:30],
        "lfi_deep":     _payloads.lfi_dotdotpwn()[:500],

        # CMDi
        "cmdi":         _payloads.cmdi_exec()[:60],

        # SSTI: 66-payload fuzz file (includes RCE payloads)
        "ssti":         _payloads.ssti_fuzz(),

        # XXE
        "xxe":          _payloads.xxe_payloads()[:30],

        # NoSQL: 45 combined MongoDB + generic
        "nosql":        _payloads.nosql_mongodb() + _payloads.nosql_general(),

        # LDAP: 46 fuzzing payloads
        "ldap":         _payloads.ldap_fuzz(),

        # CRLF: 17 payloads
        "crlf":         _payloads.crlf_payloads(),

        # Open redirect: 60 payloads
        "redirect":     _payloads.open_redirect()[:60],

        # SSI/ESI: 91 payloads
        "ssi":          _payloads.ssi_payloads(),

        # SpringBoot actuator: 51 paths
        "springboot":   _payloads.springboot_actuator(),

        # Web cache header names for param-miner style testing
        "cache_headers": _payloads.cache_headers()[:200],

        # --- Small inline sets ---
        "bypass": [
            "admin", "administrator", "root", "superuser", "guest",
            "", "null", "undefined", "true", "false",
            "{}", "[]", "0", "-1", "0x1", "%00", "%0a",
            "' OR '1'='1", "1 OR 1=1", "../../../etc/passwd",
        ],
        "ids": [str(i) for i in range(0, 101)] + ["", "null", "undefined", "-1", "0x1", "99999"],
        "usernames": [
            "admin", "administrator", "root", "user", "guest", "test",
            "operator", "manager", "superuser", "webmaster", "info",
            "support", "api", "service", "system", "dev", "devops",
            "staff", "internal", "backup", "demo", "anonymous",
        ],
        "passwords": [
            "password", "password123", "Password1", "admin", "admin123",
            "123456", "12345678", "letmein", "qwerty", "abc123",
            "password1", "welcome", "dragon", "master", "monkey",
            "shadow", "sunshine", "princess", "", "pass", "test",
            "root", "toor", "changeme", "secret", "P@ssw0rd",
        ],
        "methods":    ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"],
        "extensions": [
            ".php", ".asp", ".aspx", ".jsp", ".bak", ".bak.php", ".old",
            ".txt", ".xml", ".json", ".config", ".log", ".gz", ".tar.gz",
            ".zip", ".sql", ".swp", ".env", ".DS_Store", "",
        ],
    }

BUILTIN_PAYLOADS: dict[str, list[str]] = _build_builtin_payloads()


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class IntruderRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: Optional[str]


@dataclass
class AttackResult:
    num: int
    payloads: list[str]
    status: int
    length: int
    elapsed: float
    grep_match: bool
    body_snippet: str
    error: Optional[str] = None

    def to_row(self, use_color: bool = True) -> str:
        if self.error:
            s = "ERR"
        elif use_color:
            if self.status < 300:
                s = f"\033[32m{self.status}\033[0m"
            elif self.status < 400:
                s = f"\033[33m{self.status}\033[0m"
            elif self.status < 500:
                s = f"\033[31m{self.status}\033[0m"
            else:
                s = f"\033[35m{self.status}\033[0m"
        else:
            s = str(self.status)

        payload_s = " | ".join(repr(p[:40]) for p in self.payloads)
        grep_s = "  \033[33m[MATCH]\033[0m" if self.grep_match and use_color else ("  [MATCH]" if self.grep_match else "")
        err_s = f"  {self.error}" if self.error else ""
        return f"  #{self.num:<4}  {s}  {self.length:>7}B  {self.elapsed*1000:>6.0f}ms  {payload_s}{grep_s}{err_s}"


@dataclass
class IntruderResult:
    attack_mode: str
    total_sent: int
    results: list[AttackResult] = field(default_factory=list)

    @property
    def grep_hits(self) -> list[AttackResult]:
        return [r for r in self.results if r.grep_match]

    def summary(self) -> str:
        statuses: dict[int, int] = {}
        for r in self.results:
            statuses[r.status] = statuses.get(r.status, 0) + 1
        breakdown = ", ".join(f"{k}:{v}" for k, v in sorted(statuses.items()))
        return (
            f"mode={self.attack_mode}  sent={self.total_sent}  "
            f"statuses=[{breakdown}]  grep_hits={len(self.grep_hits)}"
        )

    def to_dict(self) -> dict:
        return {
            "attack_mode": self.attack_mode,
            "total_sent": self.total_sent,
            "results": [
                {
                    "num": r.num,
                    "payloads": r.payloads,
                    "status": r.status,
                    "length": r.length,
                    "elapsed_ms": round(r.elapsed * 1000),
                    "grep_match": r.grep_match,
                    "body_snippet": r.body_snippet[:300],
                    "error": r.error,
                }
                for r in self.results
            ],
        }


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------

class Intruder:
    def __init__(
        self,
        verify_tls: bool = False,
        follow_redirects: bool = True,
        timeout: float = 10.0,
        rate: float = 0.0,
        proxy: Optional[str] = None,
        concurrency: int = 1,
    ):
        self.verify_tls = verify_tls
        self.follow_redirects = follow_redirects
        self.timeout = timeout
        self.rate = rate
        self.proxy = proxy
        self.concurrency = concurrency

    async def run(
        self,
        req: IntruderRequest,
        payload_lists: list[list[str]],
        mode: str = "sniper",
        grep: Optional[str] = None,
        filter_status: Optional[set[int]] = None,
        hide_status: Optional[set[int]] = None,
        verbose: bool = True,
        save_to: Optional[str] = None,
    ) -> IntruderResult:
        n_positions = _count_positions(req)
        if n_positions == 0:
            print("[intruder] No §markers§ found in URL, headers, or body.", file=sys.stderr)
            return IntruderResult(attack_mode=mode, total_sent=0)

        if mode == "sniper":
            combos = list(_sniper_combos(req, payload_lists[0] if payload_lists else [], n_positions))
        elif mode == "battering_ram":
            combos = list(_battering_ram_combos(req, payload_lists[0] if payload_lists else [], n_positions))
        elif mode == "pitchfork":
            combos = list(_pitchfork_combos(req, payload_lists, n_positions))
        elif mode == "cluster_bomb":
            combos = list(_cluster_bomb_combos(req, payload_lists, n_positions))
        else:
            raise ValueError(f"Unknown mode: {mode!r}")

        result = IntruderResult(attack_mode=mode, total_sent=len(combos))
        use_color = sys.stdout.isatty()
        delay = 1.0 / self.rate if self.rate > 0 else 0.0

        if verbose:
            grep_note = f"  grep={grep!r}" if grep else ""
            print(f"\n[intruder] mode={mode}  positions={n_positions}  attacks={len(combos)}{grep_note}", file=sys.stderr)
            print("─" * 70)
            print(f"  #      status    length     time   payload(s)")
            print("─" * 70)

        kwargs: dict = dict(verify=self.verify_tls, follow_redirects=self.follow_redirects, timeout=self.timeout)
        if self.proxy:
            kwargs["proxy"] = self.proxy

        sem = asyncio.Semaphore(self.concurrency)

        async def attack_one(i: int, combo: tuple) -> AttackResult:
            method, url, headers, body, payloads = combo
            async with sem:
                ar = await _do_attack(client, i, method, url, headers, body, payloads, grep)
                if delay > 0:
                    await asyncio.sleep(delay)
            return ar

        async with httpx.AsyncClient(**kwargs) as client:
            # gather preserves submission order, semaphore bounds concurrency
            all_ars: list[AttackResult] = await asyncio.gather(
                *[attack_one(i, combo) for i, combo in enumerate(combos, 1)]
            )

        for ar in all_ars:
            if filter_status and ar.status not in filter_status:
                result.total_sent -= 1
                continue
            if hide_status and ar.status in hide_status:
                continue
            result.results.append(ar)
            if verbose:
                print(ar.to_row(use_color))

        if verbose:
            print("─" * 70)
            print(f"\n{result.summary()}")

        if save_to:
            Path(save_to).write_text(json.dumps(result.to_dict(), indent=2))
            print(f"[saved → {save_to}]")

        return result


# ---------------------------------------------------------------------------
# Position helpers
# ---------------------------------------------------------------------------

def _count_positions(req: IntruderRequest) -> int:
    count = 0
    for s in _all_strings(req):
        count += len(_MARKER_RE.findall(s))
    return count


def _all_strings(req: IntruderRequest) -> list[str]:
    return [req.url] + list(req.headers.values()) + ([req.body] if req.body else [])


def _get_defaults(req: IntruderRequest) -> list[str]:
    defaults: list[str] = []
    for s in _all_strings(req):
        for m in _MARKER_RE.finditer(s):
            defaults.append(m.group(1))
    return defaults


def _substitute(req: IntruderRequest, payload_map: dict[int, str]) -> tuple[str, dict[str, str], Optional[str]]:
    idx = [0]

    def sub(s: str) -> str:
        def replacer(m: re.Match) -> str:
            v = payload_map.get(idx[0], m.group(1))
            idx[0] += 1
            return v
        return _MARKER_RE.sub(replacer, s)

    url = sub(req.url)
    headers = {k: sub(v) for k, v in req.headers.items()}
    body = sub(req.body) if req.body else None
    return url, headers, body


# ---------------------------------------------------------------------------
# Attack mode combo generators
# ---------------------------------------------------------------------------

def _sniper_combos(req: IntruderRequest, payloads: list[str], n: int) -> Iterator[tuple]:
    defaults = _get_defaults(req)
    for pos in range(n):
        for p in payloads:
            pmap = {i: defaults[i] for i in range(n)}
            pmap[pos] = p
            url, headers, body = _substitute(req, pmap)
            yield req.method, url, headers, body, [p]


def _battering_ram_combos(req: IntruderRequest, payloads: list[str], n: int) -> Iterator[tuple]:
    for p in payloads:
        pmap = {i: p for i in range(n)}
        url, headers, body = _substitute(req, pmap)
        yield req.method, url, headers, body, [p]


def _pitchfork_combos(req: IntruderRequest, lists: list[list[str]], n: int) -> Iterator[tuple]:
    defaults = _get_defaults(req)
    padded = lists[:n] + [[defaults[i]] * 1 for i in range(len(lists), n)]
    for row in zip(*padded):
        pmap = {i: row[i] if i < len(row) else defaults[i] for i in range(n)}
        url, headers, body = _substitute(req, pmap)
        yield req.method, url, headers, body, list(row)


def _cluster_bomb_combos(req: IntruderRequest, lists: list[list[str]], n: int) -> Iterator[tuple]:
    defaults = _get_defaults(req)
    padded = lists[:n] + [[defaults[i]] for i in range(len(lists), n)]
    for combo in itertools.product(*padded):
        pmap = {i: combo[i] for i in range(n)}
        url, headers, body = _substitute(req, pmap)
        yield req.method, url, headers, body, list(combo)


# ---------------------------------------------------------------------------
# HTTP attack
# ---------------------------------------------------------------------------

async def _do_attack(
    client: httpx.AsyncClient,
    num: int,
    method: str,
    url: str,
    headers: dict[str, str],
    body: Optional[str],
    payloads: list[str],
    grep: Optional[str],
) -> AttackResult:
    t0 = time.monotonic()
    try:
        resp = await client.request(
            method, url,
            headers=headers,
            content=body.encode() if body else None,
        )
        text = resp.text
        return AttackResult(
            num=num,
            payloads=payloads,
            status=resp.status_code,
            length=len(resp.content),
            elapsed=time.monotonic() - t0,
            grep_match=bool(grep and re.search(grep, text, re.IGNORECASE)),
            body_snippet=text[:500],
        )
    except Exception as e:
        return AttackResult(
            num=num,
            payloads=payloads,
            status=0,
            length=0,
            elapsed=time.monotonic() - t0,
            grep_match=False,
            body_snippet="",
            error=str(e),
        )


# ---------------------------------------------------------------------------
# Payload loader
# ---------------------------------------------------------------------------

def load_payloads(spec: str) -> list[str]:
    """
    Load payloads from a built-in name, file path, or comma-separated inline list.

    Priority:
      1. Built-in name (e.g. 'xss', 'sqli', 'ids')
      2. File path (one payload per line)
      3. Comma-separated inline values
    """
    if spec in BUILTIN_PAYLOADS:
        return BUILTIN_PAYLOADS[spec]

    p = Path(spec)
    if p.exists():
        return [line for line in p.read_text().splitlines() if line]

    # Inline comma-separated
    return [v.strip() for v in spec.split(",") if v.strip()]
