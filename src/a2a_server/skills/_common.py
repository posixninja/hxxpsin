"""Shared helpers used by multiple skill modules.

Extracted from ``probe.py`` so recon / payload / verify / intel skills
don't have to either duplicate the logic or back-import from a peer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_auth_headers(path: str | None) -> dict[str, str] | None:
    """Read hxxpsin's standard auth.json shape and return HTTP headers.

    Two flavors accepted (matches what AutoAuth writes):
      - ``{"headers": {"Authorization": "Bearer ..."}}``
      - ``{"cookies": [{"name": "...", "value": "..."}, ...]}``
        → emitted as a single ``Cookie: name=value; name2=value2`` header.

    Returns None on missing file / unreadable / empty.
    """
    if not path:
        return None
    p = Path(path).expanduser()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
    except Exception:
        return None
    headers: dict[str, str] = {}
    h = data.get("headers")
    if isinstance(h, dict):
        for k, v in h.items():
            if isinstance(k, str) and isinstance(v, str):
                headers[k] = v
    cookies = data.get("cookies")
    if isinstance(cookies, list):
        parts = []
        for c in cookies:
            if isinstance(c, dict) and isinstance(c.get("name"), str) and isinstance(c.get("value"), str):
                parts.append(f"{c['name']}={c['value']}")
        if parts:
            headers.setdefault("Cookie", "; ".join(parts))
    return headers or None


def normalize_result(result: Any) -> dict[str, Any]:
    """Coerce any handler return value into a JSON-serializable dict."""
    if hasattr(result, "to_dict"):
        return result.to_dict()
    if isinstance(result, list):
        return {"result": result}
    if isinstance(result, dict):
        return result
    if hasattr(result, "__dict__"):
        return result.__dict__
    return {"raw": str(result)}
