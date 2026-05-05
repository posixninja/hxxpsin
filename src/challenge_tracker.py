"""
challenge_tracker.py — Ground-truth bug detection via vulnerable-app scoreboards.

Many intentionally-vulnerable apps (Juice Shop, VAmPI, WebGoat) expose an
endpoint listing every bug class and whether it has been triggered. This
module polls that endpoint before and after a scan and reports the diff —
giving us authoritative ground truth on which bugs hxxpsin actually caused
to fire (vs missed).

Supported targets:
  Juice Shop    /api/Challenges            (111 challenges, "solved" boolean)
  VAmPI         (no scoreboard — skipped)
  WebGoat       /WebGoat/service/lessonprogress.mvc  (per-lesson "solved")
  crAPI         (no scoreboard — skipped)

Pipeline position: snapshot at start of scan, snapshot at end, report the
newly-solved set as confirmed findings.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional

import httpx


@dataclass
class TriggeredChallenge:
    name: str
    category: str
    difficulty: int
    description: str = ""
    target_app: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "difficulty": self.difficulty,
            "description": self.description[:300],
            "target_app": self.target_app,
        }


@dataclass
class ChallengeSnapshot:
    target_app: str
    solved_ids: set[str] = field(default_factory=set)
    all_challenges: dict[str, dict] = field(default_factory=dict)  # id → metadata

    def is_empty(self) -> bool:
        return not self.all_challenges


@dataclass
class ChallengeTrackerResult:
    target_app: str = "unknown"
    pre_solved: int = 0
    post_solved: int = 0
    triggered: list[TriggeredChallenge] = field(default_factory=list)

    @property
    def newly_triggered(self) -> int:
        return len(self.triggered)

    def to_dict(self) -> dict:
        return {
            "target_app": self.target_app,
            "pre_solved": self.pre_solved,
            "post_solved": self.post_solved,
            "newly_triggered": self.newly_triggered,
            "triggered": [c.to_dict() for c in self.triggered],
        }


class ChallengeTracker:
    """Poll vulnerable-app scoreboards for ground-truth bug verification."""

    def __init__(self, target: str, timeout: float = 8.0):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self._app: Optional[str] = None  # "juice-shop" | "webgoat" | None

    async def detect(self) -> Optional[str]:
        """Identify the target app by probing well-known fingerprint URLs."""
        if self._app is not None:
            return self._app
        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            # Juice Shop: /api/Challenges returns JSON with "data" array
            try:
                r = await client.get(f"{self.target}/api/Challenges")
                if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
                    d = r.json()
                    if isinstance(d, dict) and "data" in d and isinstance(d["data"], list):
                        if d["data"] and any("solved" in c for c in d["data"][:3]):
                            self._app = "juice-shop"
                            return self._app
            except (httpx.HTTPError, json.JSONDecodeError, ValueError):
                pass
            # WebGoat: /WebGoat/service/lessonprogress.mvc returns JSON list
            try:
                r = await client.get(f"{self.target}/WebGoat/service/lessonprogress.mvc")
                if r.status_code == 200 and r.headers.get("content-type", "").startswith("application/json"):
                    self._app = "webgoat"
                    return self._app
            except httpx.HTTPError:
                pass
        return None

    async def snapshot(self) -> ChallengeSnapshot:
        """Capture current solved state. Empty snapshot if app isn't supported."""
        app = await self.detect()
        if not app:
            return ChallengeSnapshot(target_app="unknown")
        if app == "juice-shop":
            return await self._snapshot_juice_shop()
        if app == "webgoat":
            return await self._snapshot_webgoat()
        return ChallengeSnapshot(target_app=app)

    async def _snapshot_juice_shop(self) -> ChallengeSnapshot:
        snap = ChallengeSnapshot(target_app="juice-shop")
        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            try:
                r = await client.get(f"{self.target}/api/Challenges")
                d = r.json()
                for c in d.get("data", []):
                    cid = str(c.get("id"))
                    snap.all_challenges[cid] = c
                    if c.get("solved"):
                        snap.solved_ids.add(cid)
            except (httpx.HTTPError, json.JSONDecodeError, ValueError):
                pass
        return snap

    async def _snapshot_webgoat(self) -> ChallengeSnapshot:
        snap = ChallengeSnapshot(target_app="webgoat")
        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            try:
                r = await client.get(f"{self.target}/WebGoat/service/lessonprogress.mvc")
                items = r.json() if r.status_code == 200 else []
                for it in items:
                    cid = str(it.get("lessonName") or it.get("name") or "")
                    if not cid:
                        continue
                    snap.all_challenges[cid] = it
                    if it.get("solved"):
                        snap.solved_ids.add(cid)
            except (httpx.HTTPError, json.JSONDecodeError, ValueError):
                pass
        return snap

    @staticmethod
    def diff(pre: ChallengeSnapshot, post: ChallengeSnapshot) -> ChallengeTrackerResult:
        """Compute newly-solved challenges between two snapshots."""
        result = ChallengeTrackerResult(
            target_app=post.target_app,
            pre_solved=len(pre.solved_ids),
            post_solved=len(post.solved_ids),
        )
        new_ids = post.solved_ids - pre.solved_ids
        for cid in new_ids:
            meta = post.all_challenges.get(cid, {})
            result.triggered.append(TriggeredChallenge(
                name=meta.get("name") or meta.get("lessonName") or cid,
                category=meta.get("category") or "unknown",
                difficulty=int(meta.get("difficulty", 0) or 0),
                description=_clean_html(meta.get("description", "")),
                target_app=post.target_app,
            ))
        # Sort by difficulty descending (harder bugs are more notable)
        result.triggered.sort(key=lambda c: -c.difficulty)
        return result


_TAG_RE = re.compile(r"<[^>]+>")


def _clean_html(s: str) -> str:
    """Strip HTML tags from challenge descriptions."""
    if not isinstance(s, str):
        return ""
    return _TAG_RE.sub("", s).strip()
