"""
auth_config.py — Operator config loader.

Loads layered TOML config files for mail/tunnel/per-target settings:
  1. ~/.config/hxxpsin/config.toml   (personal/global)
  2. ./hxxpsin.toml                   (per-project, in scan CWD)
  3. --auth-config PATH               (explicit)

Later sources override earlier ones (deep merge per top-level section). Any
sensitive field can also be overridden by an environment variable named
`HXXPSIN_<UPPER_SNAKE_PATH>` — e.g. `[mail.default].imap_pass` →
`HXXPSIN_MAIL_DEFAULT_IMAP_PASS`. Env vars take precedence over file values.

Per-target settings are resolved by longest hostname-suffix match against
`[targets.<key>]` entries.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Typed profile dataclasses
# ---------------------------------------------------------------------------


@dataclass
class MailProfile:
    """One [mail.<name>] block — defines how to fetch incoming mail."""
    name: str
    backend: str  # "imap" | "mailhog" | "mailtm"
    imap_host: Optional[str] = None
    imap_port: int = 993
    imap_user: Optional[str] = None
    imap_pass: Optional[str] = None
    imap_folder: str = "INBOX"
    imap_ssl: bool = True
    # mailhog/mailpit-specific
    mailhog_url: Optional[str] = None
    # mail.tm-specific (no static fields — backend creates a fresh account per scan)


@dataclass
class TunnelProfile:
    """[tunnel] block — exposes a local payload server to the public internet."""
    backend: str = "cloudflared"  # "cloudflared" | "ngrok" | "static"
    binary: str = "cloudflared"
    auth_token: Optional[str] = None
    public_url: Optional[str] = None  # required when backend == "static"
    region: Optional[str] = None  # ngrok region hint


@dataclass
class PayloadServerProfile:
    """[payload_server] block — local HTTP server exposed via the tunnel."""
    host: str = "127.0.0.1"
    port: int = 0  # 0 = pick a free port at start
    payload_dir: Optional[str] = None


@dataclass
class CaptchaProfile:
    """[captcha] block — how to handle detected captchas during auto-auth.
    'human' opens a headed browser for the operator to solve. 'service' is
    a stub for future paid-API integration. 'none' = detect-and-bail."""
    mode: str = "human"  # "human" | "service" | "none"
    provider: Optional[str] = None  # for mode="service": 2captcha|anticaptcha|capmonster
    api_key: Optional[str] = None
    timeout: int = 600  # seconds the human is allowed to take
    snapshot_path: Optional[str] = None  # override default output/manual-auth.json


@dataclass
class MSFProfile:
    """[msf] block — Metasploit Framework workspace integration.

    Two backends are tried in order: msfrpcd (msgpack-RPC) first, then a
    direct PostgreSQL read of the msf database. Both runtime deps are
    optional; the module degrades gracefully when they're missing.

    Push is opt-in (push_findings = false by default) because writing to
    a shared engagement workspace is a side effect operators may not want."""
    enabled: bool = False
    # RPC
    rpc_host: str = "127.0.0.1"
    rpc_port: int = 55553
    rpc_user: str = "msf"
    rpc_pass: Optional[str] = None        # HXXPSIN_MSF_RPC_PASS
    rpc_ssl: bool = True
    # Direct-PG fallback
    db_host: str = "127.0.0.1"
    db_port: int = 5432
    db_name: str = "msf"
    db_user: str = "msf"
    db_pass: Optional[str] = None         # HXXPSIN_MSF_DB_PASS
    # Workspace + selective pull
    workspace: str = "default"
    pull_hosts: bool = True
    pull_creds: bool = True
    pull_loot: bool = True
    pull_notes: bool = True
    pull_sessions: bool = True            # PR1/B — read-only `session.list`
    suggest_modules: bool = True          # PR1/B — emit per-finding module hints
    # Push-back
    push_findings: bool = False
    push_min_score: int = 50


@dataclass
class ServusProfile:
    """[servus] block — outbound LLM gateway.

    All hxxpsin LLM traffic is routed through servus's chat-complete
    endpoint. ANTHROPIC_API_KEY / OPENAI_API_KEY are NOT read by
    hxxpsin anymore — servus holds them.
    """

    url: str = "http://127.0.0.1:9847"
    agent_token: Optional[str] = None  # populated from env var named by agent_token_env
    agent_token_env: str = "SERVUS_AGENT_TOKEN"
    initiator_subject: Optional[str] = None
    default_provider: str = "claude"  # claude | openai | ollama


@dataclass
class SecurisNexusProfile:
    """[securisnexus] block — workload identity + inbound cognitiond gate.

    Outbound probe HTTP is NOT gated; only inbound MCP / A2A calls are.
    """

    state_dir: Optional[str] = None  # ${SECURISNEXUS_STATE_DIR} default if None
    scope_prefix: str = "assistant:tool:hxxpsin"
    cognitiond_url: Optional[str] = None  # COGNITIOND_URL default if None
    client_cert: Optional[str] = None  # HXXPSIN_COGNITION_CLIENT_CERT
    client_key: Optional[str] = None  # HXXPSIN_COGNITION_CLIENT_KEY
    ca_path: Optional[str] = None
    insecure: bool = False  # HXXPSIN_COGNITION_INSECURE=1 in dev


@dataclass
class A2AProfile:
    """[a2a] block — local A2A HTTP server bind."""

    host: str = "127.0.0.1"
    port: int = 9851


@dataclass
class HttpGovernorProfile:
    """[http] block — shared cache, rate limit, scope guard for outbound probes."""

    max_concurrent: int = 12
    requests_per_second: float = 20.0
    allow_hosts: list[str] = field(default_factory=list)
    deny_paths: list[str] = field(default_factory=list)


@dataclass
class TargetProfile:
    """Resolved per-target settings after hostname-suffix matching + mail-ref deref."""
    matched_key: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    totp_secret: Optional[str] = None
    mail: Optional[MailProfile] = None


@dataclass
class Config:
    """Top-level loaded config. Contains all profiles + raw [targets.*] entries."""
    mail_profiles: dict[str, MailProfile] = field(default_factory=dict)
    tunnel: TunnelProfile = field(default_factory=TunnelProfile)
    payload_server: PayloadServerProfile = field(default_factory=PayloadServerProfile)
    captcha: CaptchaProfile = field(default_factory=CaptchaProfile)
    msf: MSFProfile = field(default_factory=MSFProfile)
    servus: ServusProfile = field(default_factory=ServusProfile)
    securisnexus: SecurisNexusProfile = field(default_factory=SecurisNexusProfile)
    a2a: A2AProfile = field(default_factory=A2AProfile)
    http: HttpGovernorProfile = field(default_factory=HttpGovernorProfile)
    _targets: dict[str, dict] = field(default_factory=dict)
    sources: list[Path] = field(default_factory=list)

    def resolve_for(self, target_url: str) -> TargetProfile:
        """Pick the [targets.<host>] entry whose key is the longest suffix of the
        URL's hostname. Returns an empty TargetProfile if nothing matches."""
        host = (urlparse(target_url).hostname or "").lower().strip()
        if not host:
            return TargetProfile()

        best_key: Optional[str] = None
        for key in self._targets:
            k = key.lower().strip()
            if host == k or host.endswith("." + k):
                if best_key is None or len(k) > len(best_key):
                    best_key = key

        if best_key is None:
            return TargetProfile()

        entry = self._targets[best_key]
        mail_ref = entry.get("mail")
        mail = self.mail_profiles.get(mail_ref) if isinstance(mail_ref, str) else None

        return TargetProfile(
            matched_key=best_key,
            email=entry.get("email"),
            username=entry.get("username"),
            password=entry.get("password"),
            totp_secret=entry.get("totp_secret"),
            mail=mail,
        )


# ---------------------------------------------------------------------------
# Loading + merging
# ---------------------------------------------------------------------------


_DEFAULT_HOME_PATH = Path.home() / ".config" / "hxxpsin" / "config.toml"
_DEFAULT_REPO_NAME = "hxxpsin.toml"


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"failed to read {path}: {exc}") from exc


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursive dict merge — override wins on scalar/list conflicts, dicts merge."""
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _env_override(env_path: str, current: Optional[str]) -> Optional[str]:
    """Return env-var value if set, else `current`. env_path is dotted, e.g.
    'mail.default.imap_pass' → looks up HXXPSIN_MAIL_DEFAULT_IMAP_PASS."""
    var = "HXXPSIN_" + env_path.upper().replace(".", "_")
    val = os.environ.get(var)
    return val if val is not None else current


class ConfigError(Exception):
    """Raised when a TOML file is malformed or referenced profile is missing."""


def default_paths(cwd: Optional[Path] = None) -> list[Path]:
    """The default lookup chain (home, then repo). Each may or may not exist."""
    cwd = cwd or Path.cwd()
    return [_DEFAULT_HOME_PATH, cwd / _DEFAULT_REPO_NAME]


def load(
    extra_path: Optional[str | Path] = None,
    cwd: Optional[Path] = None,
) -> Config:
    """Load + merge config files. Later sources override earlier ones.

    Lookup order:
      1. ~/.config/hxxpsin/config.toml
      2. <cwd>/hxxpsin.toml
      3. extra_path (if provided)

    Missing files are silently skipped. Returns a fully-populated Config with
    defaults filled in for any unspecified section.
    """
    paths = default_paths(cwd)
    if extra_path:
        paths.append(Path(extra_path).expanduser())

    merged: dict[str, Any] = {}
    sources: list[Path] = []
    for p in paths:
        p = p.expanduser()
        if not p.exists():
            continue
        merged = _deep_merge(merged, _read_toml(p))
        sources.append(p)

    # ── [mail.*] blocks ─────────────────────────────────────────────────
    mail_profiles: dict[str, MailProfile] = {}
    mail_section = merged.get("mail", {})
    if not isinstance(mail_section, dict):
        raise ConfigError("[mail] must be a table of named sub-tables")
    for name, raw in mail_section.items():
        if not isinstance(raw, dict):
            raise ConfigError(f"[mail.{name}] must be a table")
        backend = (raw.get("backend") or "imap").lower()
        if backend not in ("imap", "mailhog", "mailtm"):
            raise ConfigError(f"[mail.{name}].backend must be imap|mailhog|mailtm")
        mail_profiles[name] = MailProfile(
            name=name,
            backend=backend,
            imap_host=raw.get("imap_host"),
            imap_port=int(raw.get("imap_port", 993)),
            imap_user=raw.get("imap_user"),
            imap_pass=_env_override(f"mail.{name}.imap_pass", raw.get("imap_pass")),
            imap_folder=raw.get("imap_folder", "INBOX"),
            imap_ssl=bool(raw.get("imap_ssl", True)),
            mailhog_url=raw.get("mailhog_url"),
        )

    # ── [tunnel] block ──────────────────────────────────────────────────
    tunnel_raw = merged.get("tunnel", {})
    if not isinstance(tunnel_raw, dict):
        raise ConfigError("[tunnel] must be a table")
    tunnel = TunnelProfile(
        backend=(_env_override("tunnel.backend", tunnel_raw.get("backend"))
                 or "cloudflared").lower(),
        binary=tunnel_raw.get("binary", "cloudflared"),
        auth_token=_env_override("tunnel.auth_token", tunnel_raw.get("auth_token")),
        public_url=tunnel_raw.get("public_url"),
        region=tunnel_raw.get("region"),
    )
    if tunnel.backend not in ("cloudflared", "ngrok", "static", "none"):
        raise ConfigError("[tunnel].backend must be cloudflared|ngrok|static|none")
    if tunnel.backend == "static" and not tunnel.public_url:
        raise ConfigError("[tunnel].backend = 'static' requires public_url")

    # ── [payload_server] block ──────────────────────────────────────────
    ps_raw = merged.get("payload_server", {})
    if not isinstance(ps_raw, dict):
        raise ConfigError("[payload_server] must be a table")
    payload_server = PayloadServerProfile(
        host=ps_raw.get("host", "127.0.0.1"),
        port=int(ps_raw.get("port", 0)),
        payload_dir=ps_raw.get("payload_dir"),
    )

    # ── [captcha] block ─────────────────────────────────────────────────
    cap_raw = merged.get("captcha", {})
    if not isinstance(cap_raw, dict):
        raise ConfigError("[captcha] must be a table")
    captcha = CaptchaProfile(
        mode=(cap_raw.get("mode") or "human").lower(),
        provider=cap_raw.get("provider"),
        api_key=_env_override("captcha.api_key", cap_raw.get("api_key")),
        timeout=int(cap_raw.get("timeout", 600)),
        snapshot_path=cap_raw.get("snapshot_path"),
    )
    if captcha.mode not in ("human", "service", "none"):
        raise ConfigError("[captcha].mode must be human|service|none")
    if captcha.mode == "service" and not captcha.provider:
        raise ConfigError("[captcha].mode = 'service' requires provider = '2captcha'|'anticaptcha'|'capmonster'")

    # ── [msf] block — Metasploit workspace integration (opt-in) ─────────
    msf_raw = merged.get("msf", {})
    if not isinstance(msf_raw, dict):
        raise ConfigError("[msf] must be a table")
    msf = MSFProfile(
        enabled=bool(msf_raw.get("enabled", False)),
        rpc_host=msf_raw.get("rpc_host", "127.0.0.1"),
        rpc_port=int(msf_raw.get("rpc_port", 55553)),
        rpc_user=msf_raw.get("rpc_user", "msf"),
        rpc_pass=_env_override("msf.rpc_pass", msf_raw.get("rpc_pass")),
        rpc_ssl=bool(msf_raw.get("rpc_ssl", True)),
        db_host=msf_raw.get("db_host", "127.0.0.1"),
        db_port=int(msf_raw.get("db_port", 5432)),
        db_name=msf_raw.get("db_name", "msf"),
        db_user=msf_raw.get("db_user", "msf"),
        db_pass=_env_override("msf.db_pass", msf_raw.get("db_pass")),
        workspace=msf_raw.get("workspace", "default"),
        pull_hosts=bool(msf_raw.get("pull_hosts", True)),
        pull_creds=bool(msf_raw.get("pull_creds", True)),
        pull_loot=bool(msf_raw.get("pull_loot", True)),
        pull_notes=bool(msf_raw.get("pull_notes", True)),
        pull_sessions=bool(msf_raw.get("pull_sessions", True)),
        suggest_modules=bool(msf_raw.get("suggest_modules", True)),
        push_findings=bool(msf_raw.get("push_findings", False)),
        push_min_score=int(msf_raw.get("push_min_score", 50)),
    )
    if msf.enabled and not (msf.rpc_pass or msf.db_pass):
        raise ConfigError(
            "[msf] enabled = true but neither rpc_pass nor db_pass is set "
            "(use HXXPSIN_MSF_RPC_PASS / HXXPSIN_MSF_DB_PASS env vars)"
        )

    # ── [servus] block ──────────────────────────────────────────────────
    servus_raw = merged.get("servus", {})
    if not isinstance(servus_raw, dict):
        raise ConfigError("[servus] must be a table")
    servus_token_env = str(servus_raw.get("agent_token_env") or "SERVUS_AGENT_TOKEN")
    servus = ServusProfile(
        url=(
            os.environ.get("SERVUS_ASSISTANT_URL")
            or str(servus_raw.get("url") or "http://127.0.0.1:9847")
        ).rstrip("/"),
        agent_token=os.environ.get(servus_token_env)
        or _env_override("servus.agent_token", servus_raw.get("agent_token")),
        agent_token_env=servus_token_env,
        initiator_subject=os.environ.get("HXXPSIN_INITIATOR_SUBJECT")
        or _env_override("servus.initiator_subject", servus_raw.get("initiator_subject")),
        default_provider=str(
            os.environ.get("HXXPSIN_DEFAULT_LLM_PROVIDER")
            or servus_raw.get("default_provider")
            or "claude"
        ).lower(),
    )
    if servus.default_provider not in ("claude", "openai", "ollama"):
        raise ConfigError(
            f"[servus].default_provider must be claude|openai|ollama, got {servus.default_provider!r}"
        )

    # ── [securisnexus] block ────────────────────────────────────────────
    sn_raw = merged.get("securisnexus", {})
    if not isinstance(sn_raw, dict):
        raise ConfigError("[securisnexus] must be a table")
    insecure_env = (os.environ.get("HXXPSIN_COGNITION_INSECURE", "") or "").lower()
    securisnexus = SecurisNexusProfile(
        state_dir=os.environ.get("SECURISNEXUS_STATE_DIR")
        or _expand_path(sn_raw.get("state_dir")),
        scope_prefix=str(sn_raw.get("scope_prefix") or "assistant:tool:hxxpsin"),
        cognitiond_url=os.environ.get("COGNITIOND_URL") or sn_raw.get("cognitiond_url"),
        client_cert=os.environ.get("HXXPSIN_COGNITION_CLIENT_CERT")
        or _expand_path(sn_raw.get("client_cert")),
        client_key=os.environ.get("HXXPSIN_COGNITION_CLIENT_KEY")
        or _expand_path(sn_raw.get("client_key")),
        ca_path=os.environ.get("HXXPSIN_COGNITION_CA_PATH")
        or _expand_path(sn_raw.get("ca_path")),
        insecure=(insecure_env in ("1", "true", "yes")) or bool(sn_raw.get("insecure")),
    )

    # ── [a2a] block ─────────────────────────────────────────────────────
    a2a_raw = merged.get("a2a", {})
    if not isinstance(a2a_raw, dict):
        raise ConfigError("[a2a] must be a table")
    a2a = A2AProfile(
        host=str(os.environ.get("HXXPSIN_A2A_HOST") or a2a_raw.get("host") or "127.0.0.1"),
        port=int(os.environ.get("HXXPSIN_A2A_PORT") or a2a_raw.get("port") or 9851),
    )

    http_raw = merged.get("http", {})
    if not isinstance(http_raw, dict):
        raise ConfigError("[http] must be a table")
    http = HttpGovernorProfile(
        max_concurrent=int(http_raw.get("max_concurrent", 12)),
        requests_per_second=float(http_raw.get("requests_per_second", 20.0)),
        allow_hosts=list(http_raw.get("allow_hosts") or []),
        deny_paths=list(http_raw.get("deny_paths") or []),
    )

    # ── [targets.*] blocks — kept raw, resolved per-call ────────────────
    targets_raw = merged.get("targets", {})
    if not isinstance(targets_raw, dict):
        raise ConfigError("[targets] must be a table of named sub-tables")
    targets: dict[str, dict] = {}
    for key, entry in targets_raw.items():
        if not isinstance(entry, dict):
            raise ConfigError(f"[targets.\"{key}\"] must be a table")
        # Env-var override for totp_secret per target
        env_key = f"targets.{key}.totp_secret"
        secret = _env_override(env_key, entry.get("totp_secret"))
        # password too
        pw = _env_override(f"targets.{key}.password", entry.get("password"))
        targets[key] = {**entry, "totp_secret": secret, "password": pw}

    # Validate mail-refs in targets
    for key, entry in targets.items():
        ref = entry.get("mail")
        if ref is not None and ref not in mail_profiles:
            raise ConfigError(
                f"[targets.\"{key}\"].mail = \"{ref}\" but no [mail.{ref}] block defined"
            )

    return Config(
        mail_profiles=mail_profiles,
        tunnel=tunnel,
        payload_server=payload_server,
        captcha=captcha,
        msf=msf,
        servus=servus,
        securisnexus=securisnexus,
        a2a=a2a,
        http=http,
        _targets=targets,
        sources=sources,
    )


def _expand_path(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None
    return str(Path(value).expanduser())


# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------


def summary_for_target(cfg: Config, target_url: str) -> str:
    """One-line human summary of which profile resolved for a target. Used by
    main.py at scan start so the operator sees what's loaded."""
    parts: list[str] = []
    if cfg.sources:
        parts.append("sources=" + ",".join(str(p) for p in cfg.sources))
    else:
        parts.append("sources=none")
    tp = cfg.resolve_for(target_url)
    if tp.matched_key:
        m = f"target=\"{tp.matched_key}\""
        if tp.mail:
            m += f" mail={tp.mail.name}({tp.mail.backend})"
        if tp.totp_secret:
            m += " totp=set"
        if tp.email:
            m += f" email={tp.email}"
        parts.append(m)
    else:
        parts.append("target=<no match>")
    parts.append(f"tunnel={cfg.tunnel.backend}")
    if cfg.msf.enabled:
        parts.append(f"msf={cfg.msf.workspace}"
                     + (" push" if cfg.msf.push_findings else ""))
    return "  ".join(parts)
