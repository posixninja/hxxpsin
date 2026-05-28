"""verify/verify_challenge_tracker — vulnerable-app scoreboard polling.

Wraps ``challenge_tracker.ChallengeTracker`` for ground-truth bug
confirmation against vulnerable apps that expose a scoreboard
(Juice Shop, WebGoat).

Supports two actions:
  snapshot  → current solved state (used as pre/post baselines)
  diff      → compute newly-triggered challenges between two snapshots"""

from __future__ import annotations

from typing import Any

from . import REGISTRY


# snapshot_id → ChallengeSnapshot
_SNAPSHOTS: dict[str, Any] = {}


async def _handler(
    *,
    target: str | None = None,
    action: str = "snapshot",
    snapshot_id: str | None = None,
    pre_snapshot_id: str | None = None,
    post_snapshot_id: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    from challenge_tracker import ChallengeSnapshot, ChallengeTracker  # type: ignore[import-not-found]

    import uuid

    act = (action or "snapshot").lower()
    if act == "snapshot":
        if not target:
            return {"error": "action=snapshot requires target"}
        tracker = ChallengeTracker(target, timeout=timeout)
        snap: ChallengeSnapshot = await tracker.snapshot()
        sid = snapshot_id or uuid.uuid4().hex[:12]
        _SNAPSHOTS[sid] = snap
        return {
            "snapshot_id": sid,
            "target_app": snap.target_app,
            "solved_count": len(snap.solved_ids),
            "total_challenges": len(snap.all_challenges),
        }

    if act == "diff":
        if not pre_snapshot_id or not post_snapshot_id:
            return {"error": "action=diff requires pre_snapshot_id and post_snapshot_id"}
        pre = _SNAPSHOTS.get(pre_snapshot_id)
        post = _SNAPSHOTS.get(post_snapshot_id)
        if pre is None or post is None:
            missing = [
                sid for sid in (pre_snapshot_id, post_snapshot_id)
                if sid not in _SNAPSHOTS
            ]
            return {"error": f"unknown snapshot_id(s): {missing}"}
        result = ChallengeTracker.diff(pre, post)
        return result.to_dict()

    return {"error": f"unknown action {action!r}; expected snapshot|diff"}


REGISTRY.add(
    agent_id="verify",
    skill_id="verify_challenge_tracker",
    description=(
        "Poll a vulnerable-app scoreboard (Juice Shop, WebGoat) for ground-truth "
        "bug confirmation. action=snapshot captures solved-state; action=diff "
        "compares two snapshots to report newly-triggered challenges."
    ),
    input_schema={
        "type": "object",
        "required": ["action"],
        "properties": {
            "action": {"type": "string", "enum": ["snapshot", "diff"]},
            "target": {"type": "string", "description": "Target base URL (required for snapshot)"},
            "snapshot_id": {"type": "string", "description": "Optional caller-supplied snapshot ID"},
            "pre_snapshot_id": {"type": "string", "description": "Required for diff"},
            "post_snapshot_id": {"type": "string", "description": "Required for diff"},
            "timeout": {"type": "number", "description": "Per-request timeout in seconds (default 8.0)"},
        },
    },
    handler=_handler,
)
