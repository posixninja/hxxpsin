"""
surface_mapper.py — Stage 0 attack-surface expansion.

Takes a single seed (URL, hostname, IP, or CIDR) and produces a Scope object
listing every host:port the downstream pipeline could iterate over. Runs
BEFORE stackprint when any of --auto-scope, --port-scan, or --analyze-block
is set; skipped entirely otherwise so existing single-URL scans pay no cost.

Passes (each pass is opt-in via the flags driving it):

  dns          A/AAAA via getaddrinfo for the seed host (always when host).
  rdap         rdap.org HTTPS lookup for the seed domain — registrar,
               registrant org, creation/expiry, nameservers. Enabled with
               --auto-scope.
  asn          Team Cymru DNS TXT (origin.asn.cymru.com) → ASN, prefix,
               country, registry. Enabled with --auto-scope or
               --analyze-block.
  subdomains   Passive only: crt.sh JSON (CT logs) + Wayback CDX. Enabled
               with --auto-scope.
  netblock     Reverse-DNS sweep across the ASN-owned prefix(es).
               Enabled with --analyze-block. Refuses prefixes wider than
               /20 unless --analyze-block-max is raised.
  ports        Curated TCP web ports per resolved IP. Disabled by default;
               --port-scan {web,full} required. Uses asyncio.open_connection
               so no root / no raw sockets.
  vhost        For each IP with open web ports, rotate Host: header across
               the discovered hostname list and diff response status / body
               hash vs an IP-literal baseline. Enabled with --port-scan
               (free piggyback — we already have the open ports).

Hard safety bounds:

  - All active passes default OFF. Caller opts in via flags.
  - Built-in deny list of network ranges that are never port-scanned or
    sweep-targeted: RFC1918, link-local, loopback, cloud metadata IP
    (169.254.169.254), and the major shared-CDN /13s (Cloudflare, Fastly,
    Akamai partials). Scanning those is loud, useless, and gets you banned.
  - Per-host port-scan concurrency capped at 50 in-flight.
  - Every IP we touch is appended to <out>/recon/audit.jsonl so the
    operator can answer 'what did you hit?' if a program owner asks.
"""

import asyncio
import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

from dns_recon import DNSRecon, full_dns_recon


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------

@dataclass
class HostRecord:
    hostname: str
    addresses: list[str] = field(default_factory=list)
    source: str = "seed"                 # seed | crt.sh | wayback | reverse-dns | san
    open_ports: list[int] = field(default_factory=list)
    banners: dict[str, str] = field(default_factory=dict)    # "port" -> banner

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname, "addresses": self.addresses,
            "source": self.source, "open_ports": self.open_ports,
            "banners": self.banners,
        }


@dataclass
class WhoisInfo:
    domain: Optional[str] = None
    registrar: Optional[str] = None
    registrant_org: Optional[str] = None
    nameservers: list[str] = field(default_factory=list)
    created: Optional[str] = None
    expires: Optional[str] = None
    raw_handle: Optional[str] = None     # RDAP entity handle, for pivoting

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}


@dataclass
class ASNInfo:
    ip: str
    asn: Optional[int] = None
    prefix: Optional[str] = None
    country: Optional[str] = None
    registry: Optional[str] = None
    as_name: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class VhostHit:
    ip: str
    port: int
    hostname: str
    status: int
    body_sha256_prefix: str              # first 16 hex chars
    content_length: int
    distinct_from_baseline: bool

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Scope:
    seed: str
    root_domain: Optional[str] = None
    hosts: list[HostRecord] = field(default_factory=list)
    whois: Optional[WhoisInfo] = None
    dns: Optional[DNSRecon] = None
    asn: list[ASNInfo] = field(default_factory=list)
    netblock_prefixes: list[str] = field(default_factory=list)
    vhost_hits: list[VhostHit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    started_at: float = 0.0
    elapsed_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "root_domain": self.root_domain,
            "hosts": [h.to_dict() for h in self.hosts],
            "whois": self.whois.to_dict() if self.whois else None,
            "dns": self.dns.to_dict() if self.dns else None,
            "asn": [a.to_dict() for a in self.asn],
            "netblock_prefixes": self.netblock_prefixes,
            "vhost_hits": [v.to_dict() for v in self.vhost_hits],
            "notes": self.notes,
            "elapsed_s": round(self.elapsed_s, 2),
        }


# ---------------------------------------------------------------------------
# Curated port lists — web-app focused, not nmap top-1000
# ---------------------------------------------------------------------------

_WEB_PORTS = [
    80, 443, 81, 591, 2082, 2087, 2095, 2096,
    3000, 3001, 3030, 4000, 4040, 4200, 4443, 5000, 5001, 5601,
    6000, 7000, 7001, 7070, 7080, 7474, 7547,
    8000, 8001, 8008, 8009, 8010, 8042, 8069, 8080, 8081, 8082,
    8083, 8088, 8090, 8091, 8118, 8123, 8172, 8181, 8222, 8243,
    8280, 8281, 8333, 8443, 8500, 8530, 8531, 8642, 8765, 8800,
    8834, 8880, 8888, 8983,
    9000, 9001, 9043, 9060, 9080, 9090, 9091, 9200, 9300, 9443,
    9981, 9999,
    10000, 10001, 10250, 11211, 15672, 27017,
]

_FULL_PORTS = sorted(set(_WEB_PORTS + [
    21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 389, 445, 465,
    500, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 1723,
    1883, 2049, 2181, 2375, 2376, 2379, 2380, 3128, 3268, 3306,
    3389, 4369, 4500, 4567, 4789, 4848, 5061, 5222, 5432, 5672,
    5800, 5900, 5984, 5985, 5986, 6379, 6443, 6667, 7077, 8086,
    9092, 9418, 11214, 11215, 25565, 27018, 27019,
]))


# ---------------------------------------------------------------------------
# Safety: never scan these ranges
# ---------------------------------------------------------------------------

_DENY_NETS: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network(c) for c in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",
        "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
        # shared CDNs — scanning their /13s is useless and abusive
        "104.16.0.0/12",     # Cloudflare
        "172.64.0.0/13",     # Cloudflare
        "151.101.0.0/16",    # Fastly
        "23.32.0.0/11",      # Akamai (partial)
    )
]


def _is_safe_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_unspecified)
    return not any(addr in net for net in _DENY_NETS)


# ---------------------------------------------------------------------------
# Seed parsing
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def parse_seed(seed: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (hostname, ip, cidr) — exactly one of (hostname,ip) is set
    unless seed is a CIDR, in which case cidr is set."""
    s = seed.strip()
    if "/" in s and not s.startswith("http"):
        try:
            net = ipaddress.ip_network(s, strict=False)
            return None, None, str(net)
        except ValueError:
            pass
    if "://" in s:
        s = urlparse(s).hostname or s
    s = s.split(":")[0]
    if _IP_RE.match(s):
        return None, s, None
    return s, None, None


def _etld_plus_one(hostname: str) -> str:
    """Crude eTLD+1 — splits on dots and keeps the last 2 labels. Works
    for .com/.org/.net/.io. Operators on .co.uk-style suffixes should pass
    --scope-suffix explicitly."""
    parts = hostname.rsplit(".", 2)
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


# ---------------------------------------------------------------------------
# DNS (stdlib only — we don't pull in dnspython)
# ---------------------------------------------------------------------------

async def _resolve_a(host: str) -> list[str]:
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return []
    seen, out = set(), []
    for fam, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


async def _reverse_dns(ip: str) -> Optional[str]:
    loop = asyncio.get_event_loop()
    try:
        name, _ = await loop.getnameinfo((ip, 0), 0)
    except (socket.gaierror, OSError):
        return None
    return name if name and name != ip else None


# ---------------------------------------------------------------------------
# Team Cymru IP→ASN via DNS TXT
# ---------------------------------------------------------------------------

async def _cymru_asn(ip: str) -> Optional[ASNInfo]:
    # Cymru exposes IP→ASN over plain DNS TXT — no port 43, no API key.
    # Format:  <reversed-ip>.origin.asn.cymru.com  TXT
    #          "ASN | Prefix | CC | Registry | Allocated"
    try:
        rev = ".".join(reversed(ip.split(".")))
    except Exception:
        return None
    qname = f"{rev}.origin.asn.cymru.com"
    txt = await _dns_txt(qname)
    if not txt:
        return None
    parts = [p.strip() for p in txt.split("|")]
    if len(parts) < 4:
        return None
    info = ASNInfo(ip=ip)
    try:
        info.asn = int(parts[0].split()[0])
    except Exception:
        info.asn = None
    info.prefix = parts[1] or None
    info.country = parts[2] or None
    info.registry = parts[3] or None
    if info.asn:
        # Pivot: AS<n>.asn.cymru.com → "<asn> | CC | Registry | Allocated | <name>"
        as_txt = await _dns_txt(f"AS{info.asn}.asn.cymru.com")
        if as_txt:
            as_parts = [p.strip() for p in as_txt.split("|")]
            if as_parts:
                info.as_name = as_parts[-1] or None
    return info


async def _dns_txt(qname: str) -> Optional[str]:
    """Minimal TXT lookup via the system resolver. Falls back to subprocess
    `dig` when getaddrinfo isn't enough (TXT records aren't first-class in
    the stdlib resolver). Best-effort only."""
    proc = await asyncio.create_subprocess_exec(
        "dig", "+short", "+time=3", "+tries=1", "TXT", qname,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
    except (asyncio.TimeoutError, FileNotFoundError):
        try:
            proc.kill()
        except Exception:
            pass
        return None
    line = stdout.decode("utf-8", errors="replace").strip().splitlines()
    if not line:
        return None
    # dig returns TXT records quoted; strip outer quotes
    raw = line[0].strip()
    return raw.strip('"') if raw else None


# ---------------------------------------------------------------------------
# RDAP — registration whois, HTTPS, no API key
# ---------------------------------------------------------------------------

async def _rdap_lookup(domain: str, client: httpx.AsyncClient) -> Optional[WhoisInfo]:
    try:
        r = await client.get(f"https://rdap.org/domain/{domain}", timeout=8.0)
    except Exception:
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    info = WhoisInfo(domain=domain)
    info.raw_handle = data.get("handle")
    for ev in data.get("events", []) or []:
        action = (ev.get("eventAction") or "").lower()
        if action == "registration":
            info.created = ev.get("eventDate")
        elif action in ("expiration", "expiry"):
            info.expires = ev.get("eventDate")
    info.nameservers = [
        ns.get("ldhName", "").lower()
        for ns in data.get("nameservers", []) or []
        if ns.get("ldhName")
    ]
    for ent in data.get("entities", []) or []:
        roles = [r.lower() for r in ent.get("roles") or []]
        vcard = ent.get("vcardArray") or []
        if "registrar" in roles and not info.registrar:
            info.registrar = _vcard_field(vcard, "fn")
        if "registrant" in roles and not info.registrant_org:
            info.registrant_org = _vcard_field(vcard, "org") or _vcard_field(vcard, "fn")
    return info


def _vcard_field(vcard_array: list, field_name: str) -> Optional[str]:
    if not vcard_array or len(vcard_array) < 2:
        return None
    for entry in vcard_array[1]:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        if entry[0] == field_name:
            val = entry[3]
            if isinstance(val, list):
                return " ".join(str(x) for x in val if x)
            return str(val) if val else None
    return None


# ---------------------------------------------------------------------------
# Passive subdomain enumeration — crt.sh + Wayback CDX
# ---------------------------------------------------------------------------

async def _crtsh_subdomains(domain: str, client: httpx.AsyncClient) -> set[str]:
    try:
        r = await client.get("https://crt.sh/",
                             params={"q": f"%.{domain}", "output": "json"},
                             timeout=15.0)
    except Exception:
        return set()
    if r.status_code != 200:
        return set()
    try:
        rows = r.json()
    except Exception:
        return set()
    out: set[str] = set()
    for row in rows:
        for field_name in ("name_value", "common_name"):
            val = row.get(field_name) or ""
            for line in str(val).splitlines():
                line = line.strip().lower().lstrip("*.")
                if line and line.endswith(domain):
                    out.add(line)
    return out


async def _wayback_subdomains(domain: str, client: httpx.AsyncClient) -> set[str]:
    try:
        r = await client.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{domain}/*", "output": "json",
                    "fl": "original", "collapse": "urlkey", "limit": 5000},
            timeout=15.0,
        )
    except Exception:
        return set()
    if r.status_code != 200:
        return set()
    try:
        rows = r.json()
    except Exception:
        return set()
    out: set[str] = set()
    for row in rows[1:] if rows else []:
        if not row:
            continue
        host = urlparse(row[0]).hostname
        if host and host.endswith(domain):
            out.add(host.lower())
    return out


# ---------------------------------------------------------------------------
# Async TCP port probe — no raw sockets, no root needed
# ---------------------------------------------------------------------------

async def _probe_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def _port_scan_host(ip: str, ports: list[int], concurrency: int = 50,
                          timeout: float = 1.5) -> list[int]:
    if not _is_safe_ip(ip):
        return []
    sem = asyncio.Semaphore(concurrency)

    async def _one(p: int) -> Optional[int]:
        async with sem:
            return p if await _probe_port(ip, p, timeout=timeout) else None

    results = await asyncio.gather(*(_one(p) for p in ports))
    return sorted(p for p in results if p is not None)


async def _http_banner(client: httpx.AsyncClient, ip: str, port: int) -> str:
    scheme = "https" if port in (443, 8443, 4443, 9443, 8243) or port % 1000 == 443 else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        r = await client.get(url, timeout=4.0)
    except Exception as exc:
        return f"err:{type(exc).__name__}"
    server = r.headers.get("Server", "")
    powered = r.headers.get("X-Powered-By", "")
    title_match = re.search(r"<title[^>]*>([^<]{0,80})", r.text or "", re.I)
    title = title_match.group(1).strip() if title_match else ""
    bits = [f"status={r.status_code}"]
    if server:
        bits.append(f"server={server}")
    if powered:
        bits.append(f"powered={powered}")
    if title:
        bits.append(f"title={title}")
    return " | ".join(bits)


# ---------------------------------------------------------------------------
# Vhost differ — rotate Host: header, diff body hash
# ---------------------------------------------------------------------------

async def _vhost_probe(client: httpx.AsyncClient, ip: str, port: int,
                       hostnames: list[str]) -> list[VhostHit]:
    scheme = "https" if port in (443, 8443, 4443, 9443, 8243) else "http"
    base_url = f"{scheme}://{ip}:{port}/"
    try:
        baseline = await client.get(base_url, timeout=5.0,
                                    headers={"Host": ip})
    except Exception:
        return []
    base_hash = sha256((baseline.text or "").encode("utf-8",
                                                    errors="replace")).hexdigest()[:16]
    base_len = len(baseline.text or "")
    out: list[VhostHit] = []
    for host in hostnames:
        try:
            r = await client.get(base_url, timeout=5.0, headers={"Host": host})
        except Exception:
            continue
        h = sha256((r.text or "").encode("utf-8", errors="replace")).hexdigest()[:16]
        distinct = (h != base_hash) or (r.status_code != baseline.status_code) \
            or abs(len(r.text or "") - base_len) > 64
        out.append(VhostHit(
            ip=ip, port=port, hostname=host,
            status=r.status_code, body_sha256_prefix=h,
            content_length=len(r.text or ""),
            distinct_from_baseline=distinct,
        ))
    return out


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

@dataclass
class SurfaceMapperConfig:
    auto_scope: bool = False
    port_scan: str = "none"              # "none" | "web" | "full"
    analyze_block: bool = False
    analyze_block_max: int = 20          # refuse prefixes wider than /<this>
    max_subdomains: int = 200
    max_vhosts_per_ip: int = 50
    port_concurrency: int = 50
    port_timeout: float = 1.5
    scope_suffix: Optional[str] = None   # operator override for eTLD+1 quirks


async def map_surface(seed: str, cfg: SurfaceMapperConfig,
                      out_dir: Optional[Path] = None,
                      log=None) -> Scope:
    """Stage 0 entry point. Returns a Scope; also writes
    <out_dir>/recon/scope.json and <out_dir>/recon/audit.jsonl when
    out_dir is set."""
    if log is None:
        log = lambda *_: None

    scope = Scope(seed=seed, started_at=time.time())
    hostname, ip, cidr = parse_seed(seed)

    # Quick reject: nothing to do without any flag enabled
    if not (cfg.auto_scope or cfg.port_scan != "none" or cfg.analyze_block):
        scope.notes.append("surface_mapper skipped — no recon flag set")
        return scope

    seed_addresses: list[str] = []
    if hostname:
        scope.root_domain = cfg.scope_suffix or _etld_plus_one(hostname)
        seed_addresses = await _resolve_a(hostname)
        scope.hosts.append(HostRecord(hostname=hostname,
                                      addresses=seed_addresses, source="seed"))
    elif ip:
        seed_addresses = [ip]
    elif cidr:
        scope.netblock_prefixes.append(cidr)

    audit_path = (out_dir / "recon" / "audit.jsonl") if out_dir else None
    if audit_path:
        audit_path.parent.mkdir(parents=True, exist_ok=True)

    def _audit(event: str, **fields):
        rec = {"ts": time.time(), "event": event, **fields}
        log(event, fields)
        if audit_path:
            with audit_path.open("a") as fp:
                fp.write(json.dumps(rec) + "\n")

    _audit("seed", hostname=hostname, ip=ip, cidr=cidr,
           addresses=seed_addresses)

    async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                 http2=True,
                                 headers={"User-Agent": "hxxpsin/0 recon"}) as client:

        # ── auto-scope: RDAP + deep DNS + passive subdomain enumeration ─
        if cfg.auto_scope and scope.root_domain:
            scope.whois = await _rdap_lookup(scope.root_domain, client)
            _audit("rdap", domain=scope.root_domain,
                   ok=bool(scope.whois))

            # Deep DNS recon — all record types + AXFR + DKIM + SPF/DMARC
            scope.dns = await full_dns_recon(scope.root_domain)
            _audit("dns_recon",
                   types=len(scope.dns.records),
                   axfr_ok=bool(scope.dns.axfr),
                   wildcard=scope.dns.wildcard,
                   discovered=len(scope.dns.discovered_hostnames))

            crt_task = asyncio.create_task(
                _crtsh_subdomains(scope.root_domain, client))
            wb_task = asyncio.create_task(
                _wayback_subdomains(scope.root_domain, client))
            crt_hosts, wb_hosts = await asyncio.gather(crt_task, wb_task)
            dns_hosts: set[str] = set(scope.dns.discovered_hostnames)
            new_hosts = (crt_hosts | wb_hosts | dns_hosts) - {hostname}
            # If we detected wildcard DNS, the brute / passive results are
            # mostly garbage — keep them but flag it loudly.
            if scope.dns.wildcard:
                scope.notes.append(
                    f"wildcard DNS detected on *.{scope.root_domain} → "
                    f"{scope.dns.wildcard_address} — many 'discovered' "
                    "subdomains are likely false positives")
            new_hosts = sorted(new_hosts)[:cfg.max_subdomains]
            for h in new_hosts:
                if h in crt_hosts:
                    source = "crt.sh"
                elif h in dns_hosts:
                    source = "dns"
                else:
                    source = "wayback"
                addrs = await _resolve_a(h)
                if addrs:
                    scope.hosts.append(HostRecord(hostname=h, addresses=addrs,
                                                  source=source))
            _audit("passive_subdomains", count=len(new_hosts))

        # ── ASN lookup (auto-scope or analyze-block) ──────────────────
        if (cfg.auto_scope or cfg.analyze_block) and seed_addresses:
            seen_asns: set[int] = set()
            for addr in seed_addresses:
                if not _is_safe_ip(addr):
                    continue
                info = await _cymru_asn(addr)
                if info and info.asn and info.asn not in seen_asns:
                    seen_asns.add(info.asn)
                    scope.asn.append(info)
                    if info.prefix and info.prefix not in scope.netblock_prefixes:
                        scope.netblock_prefixes.append(info.prefix)
            _audit("asn", asns=sorted(seen_asns))

        # ── analyze-block: reverse-DNS sweep across the netblock ──────
        if cfg.analyze_block and scope.netblock_prefixes:
            for cidr_str in list(scope.netblock_prefixes):
                try:
                    net = ipaddress.ip_network(cidr_str, strict=False)
                except ValueError:
                    continue
                if net.prefixlen < cfg.analyze_block_max:
                    scope.notes.append(
                        f"refused netblock sweep of {cidr_str} — wider than "
                        f"/{cfg.analyze_block_max}; raise --analyze-block-max")
                    continue
                _audit("netblock_sweep_begin", cidr=cidr_str,
                       hosts=net.num_addresses)
                sem = asyncio.Semaphore(100)

                async def _rev(addr_str: str):
                    async with sem:
                        return addr_str, await _reverse_dns(addr_str)

                tasks = [_rev(str(a)) for a in net.hosts()
                         if _is_safe_ip(str(a))]
                results = await asyncio.gather(*tasks)
                added = 0
                known = {h.hostname for h in scope.hosts}
                for addr_str, name in results:
                    if not name or name in known:
                        continue
                    scope.hosts.append(HostRecord(
                        hostname=name, addresses=[addr_str],
                        source="reverse-dns"))
                    known.add(name)
                    added += 1
                _audit("netblock_sweep_end", cidr=cidr_str, new_hosts=added)

        # ── port scan (per-host, opt-in only) ─────────────────────────
        if cfg.port_scan != "none":
            ports = _WEB_PORTS if cfg.port_scan == "web" else _FULL_PORTS
            ip_to_hosts: dict[str, list[str]] = {}
            for h in scope.hosts:
                for a in h.addresses:
                    if _is_safe_ip(a):
                        ip_to_hosts.setdefault(a, []).append(h.hostname)
            _audit("port_scan_begin", mode=cfg.port_scan,
                   ips=len(ip_to_hosts), ports=len(ports))
            for addr, _ in ip_to_hosts.items():
                open_ports = await _port_scan_host(
                    addr, ports,
                    concurrency=cfg.port_concurrency,
                    timeout=cfg.port_timeout,
                )
                if not open_ports:
                    continue
                # Attach the open ports to every host pointing at this IP
                for h in scope.hosts:
                    if addr in h.addresses:
                        h.open_ports = sorted(set(h.open_ports + open_ports))
                # Banner-grab each open port
                for p in open_ports:
                    banner = await _http_banner(client, addr, p)
                    for h in scope.hosts:
                        if addr in h.addresses:
                            h.banners[str(p)] = banner
                _audit("port_scan_host", ip=addr, open_ports=open_ports)

                # ── vhost probe (free piggyback on port scan) ─────────
                hostnames_for_ip = sorted({
                    h.hostname for h in scope.hosts if addr in h.addresses
                })[: cfg.max_vhosts_per_ip]
                if len(hostnames_for_ip) >= 2:
                    for p in open_ports:
                        hits = await _vhost_probe(client, addr, p,
                                                  hostnames_for_ip)
                        scope.vhost_hits.extend(
                            h for h in hits if h.distinct_from_baseline)
            _audit("port_scan_end")

    scope.elapsed_s = time.time() - scope.started_at

    if out_dir:
        recon_dir = out_dir / "recon"
        recon_dir.mkdir(parents=True, exist_ok=True)
        (recon_dir / "scope.json").write_text(
            json.dumps(scope.to_dict(), indent=2))

    return scope


# ---------------------------------------------------------------------------
# CLI for standalone testing — `python3 src/surface_mapper.py example.com ...`
# ---------------------------------------------------------------------------

def _summary(scope: Scope) -> str:
    n_hosts = len(scope.hosts)
    n_ports = sum(len(h.open_ports) for h in scope.hosts)
    n_vhosts = sum(1 for v in scope.vhost_hits if v.distinct_from_baseline)
    n_asn = len(scope.asn)
    return (f"hosts={n_hosts} open_ports={n_ports} asns={n_asn} "
            f"vhost_hits={n_vhosts} elapsed={scope.elapsed_s:.1f}s")


if __name__ == "__main__":
    import argparse, sys
    p = argparse.ArgumentParser(prog="surface_mapper",
                                description="Stage 0 attack-surface mapper")
    p.add_argument("seed", help="URL, hostname, IP, or CIDR")
    p.add_argument("--auto-scope", action="store_true")
    p.add_argument("--port-scan", choices=("none", "web", "full"), default="none")
    p.add_argument("--analyze-block", action="store_true")
    p.add_argument("--analyze-block-max", type=int, default=20)
    p.add_argument("--scope-suffix", default=None)
    p.add_argument("--out", default=None, help="Output dir for scope.json + audit.jsonl")
    args = p.parse_args()

    cfg = SurfaceMapperConfig(
        auto_scope=args.auto_scope,
        port_scan=args.port_scan,
        analyze_block=args.analyze_block,
        analyze_block_max=args.analyze_block_max,
        scope_suffix=args.scope_suffix,
    )
    out_dir = Path(args.out) if args.out else None

    def _log(event, fields):
        print(f"[recon] {event} {fields}", file=sys.stderr)

    scope = asyncio.run(map_surface(args.seed, cfg, out_dir=out_dir, log=_log))
    print(json.dumps(scope.to_dict(), indent=2))
    print(_summary(scope), file=sys.stderr)
