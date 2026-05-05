"""
repeater.py — Manual HTTP request replay (Burp Repeater equivalent).

Usage:
  python3 main.py repeat --url https://target.com/api/user/1
  python3 main.py repeat --url https://target.com/api/user/1 --method POST --body '{"x":1}'
  python3 main.py repeat --request burp_req.txt
  python3 main.py repeat --request burp_req.txt --replace "user_id=1" "user_id=2"
  python3 main.py repeat --url https://target.com/api --times 3 --diff

Supported --request file formats:
  Raw HTTP (Burp copy-as-curl / paste-request):
      POST /api/user HTTP/1.1
      Host: target.com
      Authorization: Bearer eyJ...

      {"key": "value"}

  JSON:
      {"method": "POST", "url": "https://target.com/api", "headers": {}, "body": "..."}
"""

import asyncio
import difflib
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx


@dataclass
class ReplayRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: Optional[str]

    @classmethod
    def from_raw_http(cls, raw: str, scheme: str = "https") -> "ReplayRequest":
        lines = raw.replace("\r\n", "\n").split("\n")
        req_line = lines[0].strip()
        parts = req_line.split(" ")
        method = parts[0].upper()
        path = parts[1] if len(parts) > 1 else "/"

        headers: dict[str, str] = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                k, _, v = lines[i].partition(":")
                headers[k.strip()] = v.strip()
            i += 1

        body_parts = lines[i + 1:] if i + 1 < len(lines) else []
        body = "\n".join(body_parts).strip() or None

        host = headers.pop("Host", headers.pop("host", "localhost"))
        url = f"{scheme}://{host}{path}"
        return cls(method=method, url=url, headers=headers, body=body)

    @classmethod
    def from_file(cls, path: str, scheme: str = "https") -> "ReplayRequest":
        content = Path(path).read_text()
        if content.strip().startswith("{"):
            data = json.loads(content)
            return cls(
                method=data.get("method", "GET").upper(),
                url=data["url"],
                headers=data.get("headers", {}),
                body=data.get("body"),
            )
        return cls.from_raw_http(content, scheme=scheme)


@dataclass
class ReplayResult:
    status: int
    headers: dict[str, str]
    body: str
    elapsed: float
    attempt: int
    error: Optional[str] = None


class Repeater:
    def __init__(
        self,
        verify_tls: bool = False,
        follow_redirects: bool = True,
        timeout: float = 10.0,
        proxy: Optional[str] = None,
    ):
        self.verify_tls = verify_tls
        self.follow_redirects = follow_redirects
        self.timeout = timeout
        self.proxy = proxy

    async def run(
        self,
        req: ReplayRequest,
        times: int = 1,
        replacements: Optional[list[tuple[str, str]]] = None,
        verbose: bool = True,
        save_to: Optional[str] = None,
    ) -> list[ReplayResult]:
        if replacements:
            req = _apply_replacements(req, replacements)

        kwargs: dict = dict(
            verify=self.verify_tls,
            follow_redirects=self.follow_redirects,
            timeout=self.timeout,
        )
        if self.proxy:
            kwargs["proxy"] = self.proxy

        results: list[ReplayResult] = []
        async with httpx.AsyncClient(**kwargs) as client:
            for i in range(1, times + 1):
                r = await _send(client, req, i)
                results.append(r)
                if verbose:
                    _print_result(req, r, show_request=(i == 1))

        if verbose and len(results) >= 2:
            _print_diff(results[0], results[-1])

        if save_to:
            _save(req, results, save_to)

        return results


async def _send(client: httpx.AsyncClient, req: ReplayRequest, attempt: int) -> ReplayResult:
    t0 = time.monotonic()
    try:
        resp = await client.request(
            req.method,
            req.url,
            headers=req.headers,
            content=req.body.encode() if req.body else None,
        )
        return ReplayResult(
            status=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            elapsed=time.monotonic() - t0,
            attempt=attempt,
        )
    except Exception as e:
        return ReplayResult(
            status=0, headers={}, body="",
            elapsed=time.monotonic() - t0,
            attempt=attempt,
            error=str(e),
        )


def _apply_replacements(req: ReplayRequest, reps: list[tuple[str, str]]) -> ReplayRequest:
    url, body = req.url, req.body or ""
    headers = dict(req.headers)
    for old, new in reps:
        url = url.replace(old, new)
        body = body.replace(old, new)
        headers = {k: v.replace(old, new) for k, v in headers.items()}
    return ReplayRequest(req.method, url, headers, body or None)


def _status_color(status: int, use_color: bool) -> str:
    if not use_color:
        return str(status)
    if status < 300:
        return f"\033[32m{status}\033[0m"
    if status < 400:
        return f"\033[33m{status}\033[0m"
    if status < 500:
        return f"\033[31m{status}\033[0m"
    return f"\033[35m{status}\033[0m"


def _print_result(req: ReplayRequest, r: ReplayResult, show_request: bool) -> None:
    use_color = sys.stdout.isatty()
    sep = "─" * 60

    if show_request:
        print(f"\n{sep}")
        print(f"→ {req.method} {req.url}")
        for k, v in req.headers.items():
            print(f"  {k}: {v}")
        if req.body:
            print(f"\n{req.body[:1000]}")
            if len(req.body) > 1000:
                print(f"  ... ({len(req.body)} bytes total)")

    print(f"\n{sep}")
    if r.error:
        print(f"← ERROR: {r.error}")
        return

    size = len(r.body.encode("utf-8", errors="replace"))
    print(f"← {_status_color(r.status, use_color)}  {size}B  {r.elapsed * 1000:.0f}ms  (attempt {r.attempt})")
    for k, v in list(r.headers.items())[:15]:
        print(f"  {k}: {v}")
    if r.body:
        print(f"\n{r.body[:4000]}")
        if len(r.body) > 4000:
            print(f"  ... ({len(r.body)} total bytes)")


def _print_diff(r1: ReplayResult, r2: ReplayResult) -> None:
    sep = "─" * 60
    print(f"\n{sep}")
    print(f"Diff (attempt 1 vs {r2.attempt}):")
    if r1.status != r2.status:
        print(f"  Status:  {r1.status} → {r2.status}")
    s1 = len(r1.body.encode("utf-8", errors="replace"))
    s2 = len(r2.body.encode("utf-8", errors="replace"))
    if s1 != s2:
        print(f"  Length:  {s1}B → {s2}B  (Δ{s2 - s1:+d}B)")
    diff = list(difflib.unified_diff(r1.body.splitlines(), r2.body.splitlines(), lineterm="", n=2))
    if diff:
        print("\n".join(diff[:60]))
    else:
        print("  (identical response bodies)")


def _save(req: ReplayRequest, results: list[ReplayResult], path: str) -> None:
    data = {
        "request": {"method": req.method, "url": req.url, "headers": req.headers, "body": req.body},
        "results": [
            {
                "attempt": r.attempt,
                "status": r.status,
                "elapsed_ms": round(r.elapsed * 1000),
                "length": len(r.body.encode("utf-8", errors="replace")),
                "headers": r.headers,
                "body": r.body[:8000],
                "error": r.error,
            }
            for r in results
        ],
    }
    Path(path).write_text(json.dumps(data, indent=2))
    print(f"\n[saved → {path}]")
