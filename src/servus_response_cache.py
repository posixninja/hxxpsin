"""Disk cache + JSON-extraction helpers shared by the provider shims.

Used by [claude_client](claude_client.py), [openai_client](openai_client.py),
and [llm_client](llm_client.py). Same cache key scheme keeps the three
caches non-colliding (different providers hash to different files).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional


def cache_key(provider: str, model: str, system: str, prompt: str) -> str:
    h = hashlib.sha256()
    for part in (provider, model, system or "", prompt or ""):
        h.update(part.encode())
        h.update(b"\x00")
    return h.hexdigest()[:24]


def read_cache(cache_dir: Optional[Path], key: str) -> Optional[str]:
    if cache_dir is None:
        return None
    path = cache_dir / f"{key}.txt"
    if not path.exists():
        return None
    try:
        return path.read_text()
    except Exception:
        return None


def write_cache(cache_dir: Optional[Path], key: str, text: str) -> None:
    if cache_dir is None:
        return
    try:
        (cache_dir / f"{key}.txt").write_text(text)
    except Exception:
        pass


def maybe_parse_json(text: str) -> Optional[dict]:
    """Pluck the first top-level JSON object out of `text`. Tolerant of
    fenced ``` ```json ... ``` ``` blocks and inline-prose wrappers."""
    text = (text or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        text = text.strip("`").lstrip("json").strip()
    if not text.startswith("{"):
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            text = text[start : end + 1]
    try:
        return json.loads(text)
    except Exception:
        return None
