"""Read SecurisNexus workload identity at startup.

When hxxpsin runs as an SN-registered workload, ``register.sh`` writes
a state file the workload reads at boot to learn:

- ``identity_id`` — opaque SN identity (e.g. ``id-1d39...``)
- ``spiffe_id`` — SPIFFE URI used as the actor identifier in cognitiond
- ``company_id`` — tenant slug
- ``bootstrap_token`` — one-shot token used by certd to mint the SVID

The state file lives at ``${STATE_DIR}/hxxpsin.json`` where ``STATE_DIR``
defaults to ``servus/securisnexus/state/``. The same file is consumed
by the supervisor launcher to materialize mTLS certs into env-var-named
paths (``HXXPSIN_COGNITION_CLIENT_CERT`` etc.).

If no state file is present we return ``Identity.unmanaged()`` — local
dev mode. In that mode every consumer falls back to environment
variables and/or insecure defaults, just like servus's local-dev path.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


_STATE_BASENAME = "hxxpsin.json"


def _default_state_dir() -> Path:
    explicit = os.environ.get("SECURISNEXUS_STATE_DIR")
    if explicit:
        return Path(explicit)
    # Mirror servus's default: <servus_repo>/securisnexus/state/
    return Path.home() / "Desktop" / "Projects" / "servus" / "securisnexus" / "state"


@dataclass(frozen=True)
class Identity:
    identity_id: Optional[str]
    spiffe_id: Optional[str]
    company_id: Optional[str]
    bootstrap_token: Optional[str]
    endpoint: Optional[str]
    managed: bool

    @property
    def actor_id(self) -> str:
        """SPIFFE URI when available, else a stable local fallback."""
        if self.spiffe_id:
            return self.spiffe_id
        if self.identity_id:
            return self.identity_id
        return "local:hxxpsin"

    @classmethod
    def unmanaged(cls) -> "Identity":
        return cls(
            identity_id=os.environ.get("HXXPSIN_IDENTITY_ID") or None,
            spiffe_id=os.environ.get("HXXPSIN_SPIFFE_ID") or None,
            company_id=os.environ.get("HXXPSIN_COMPANY_ID")
            or os.environ.get("HXXPSIN_TENANT")
            or None,
            bootstrap_token=None,
            endpoint=os.environ.get("HXXPSIN_ENDPOINT") or None,
            managed=False,
        )


def load(state_path: Path | str | None = None) -> Identity:
    """Best-effort load. Never raises — missing/malformed state → unmanaged."""
    path = Path(state_path) if state_path else _default_state_dir() / _STATE_BASENAME
    if not path.exists():
        log.info("identity: no state file at %s; running unmanaged", path)
        return Identity.unmanaged()
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        log.warning("identity: failed to parse %s: %s; running unmanaged", path, e)
        return Identity.unmanaged()
    return Identity(
        identity_id=data.get("identity_id"),
        spiffe_id=data.get("spiffe_id"),
        company_id=data.get("company_id"),
        bootstrap_token=data.get("bootstrap_token"),
        endpoint=data.get("endpoint"),
        managed=True,
    )
