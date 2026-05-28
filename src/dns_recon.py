"""
dns_recon.py — comprehensive DNS recon for the Stage 0 surface mapper.

Pulls every common record type plus the protocol-specific lookups a security
operator wants on a target:

  Basic types        A, AAAA, CNAME, MX, NS, SOA, TXT, CAA, SRV, NAPTR,
                     SSHFP, TLSA, DS, DNSKEY, HTTPS, SVCB
  Mail policy        SPF (with include-chain expansion), DMARC (parsed
                     tags + rua/ruf addresses), DKIM (brute common
                     selectors)
  Zone enumeration   ANY query sent DIRECTLY to the authoritative NS so
                     RFC 8482 minimization at the public resolver doesn't
                     hide records; AXFR attempt against every NS
  Misconfig          Wildcard-resolution detection so subdomain brute
                     downstream doesn't drown in false positives

Implementation note: this module shells out to `dig`. That's deliberate —
it avoids adding dnspython as a dep, and dig is universally present on
macOS/Linux dev machines. When dig is unavailable every function returns
empty / None gracefully so the rest of the pipeline continues.
"""

import asyncio
import os
import random
import re
import string
import time
from dataclasses import dataclass, field
from typing import Optional


# Bundled subdomain wordlist (SecLists subdomains-top1million-5000). Resolved
# at import time so the path is stable whether dns_recon is imported as a
# module or run as `python3 src/dns_recon.py`.
DEFAULT_SUBDOMAIN_WORDLIST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "wordlists", "subdomains-top5000.txt",
)


# Record types worth pulling on every recon pass. ANY is queried separately
# against the authoritative server (see dns_any).
BASIC_TYPES: list[str] = [
    "A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA",
    "SRV", "NAPTR", "SSHFP", "TLSA", "DS", "DNSKEY", "HTTPS", "SVCB",
]


# Common DKIM selectors in the wild. The list is biased toward big providers
# whose presence reveals what mail infra the target uses.
DKIM_SELECTORS: list[str] = [
    "default", "selector", "selector1", "selector2", "selector3",
    "google", "google1", "google2", "20161025", "20210112",
    "mail", "smtp", "dkim", "domainkey", "k1", "k2", "k3",
    "s1", "s2", "s3", "scph0922", "scph1019",
    "amazonses", "amazon", "ses",
    "mandrill", "mandrill1", "mandrill2",
    "fm1", "fm2", "fm3", "fastmail",
    "mailjet", "sendgrid", "zoho", "zendesk", "zendesk1", "zendesk2",
    "pm", "postmark",
    "mxvault", "everlytic", "everlytickey1", "everlytickey2",
    "sl", "sl1", "sl2",
    "hubspot", "hubspot1", "hubspot2",
    "salesforce", "marketing", "campaign", "newsletter",
    "intercom",
]


# DMARC tag names per RFC 7489 §6.3
DMARC_TAGS = ("v", "p", "sp", "rua", "ruf", "adkim", "aspf",
              "pct", "fo", "rf", "ri")


# ---------------------------------------------------------------------------
# Data shape
# ---------------------------------------------------------------------------

@dataclass
class SOARecord:
    primary_ns: str
    admin_email: str                     # decoded from DNS form (first . → @)
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int
    raw: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class DNSRecon:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    soa: Optional[SOARecord] = None
    spf: list[str] = field(default_factory=list)
    spf_includes: list[str] = field(default_factory=list)
    dmarc: Optional[str] = None
    dmarc_parsed: dict[str, str] = field(default_factory=dict)
    dkim: dict[str, str] = field(default_factory=dict)
    any_records: list[str] = field(default_factory=list)
    axfr: dict[str, list[str]] = field(default_factory=dict)
    wildcard: bool = False
    wildcard_address: Optional[str] = None
    authoritative_ns: list[str] = field(default_factory=list)
    discovered_hostnames: list[str] = field(default_factory=list)  # from MX/CNAME/SRV/AXFR
    brute_hits: dict[str, list[str]] = field(default_factory=dict)  # fqdn → [A records]
    brute_wordlist_size: int = 0
    elapsed_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "records": self.records,
            "soa": self.soa.to_dict() if self.soa else None,
            "spf": self.spf,
            "spf_includes": self.spf_includes,
            "dmarc": self.dmarc,
            "dmarc_parsed": self.dmarc_parsed,
            "dkim": self.dkim,
            "any_records": self.any_records,
            "axfr": self.axfr,
            "wildcard": self.wildcard,
            "wildcard_address": self.wildcard_address,
            "authoritative_ns": self.authoritative_ns,
            "discovered_hostnames": self.discovered_hostnames,
            "brute_hits": self.brute_hits,
            "brute_wordlist_size": self.brute_wordlist_size,
            "elapsed_s": round(self.elapsed_s, 2),
        }


# ---------------------------------------------------------------------------
# dig wrapper — single source of truth for shell-outs
# ---------------------------------------------------------------------------

async def _run_dig(args: list[str], timeout: float) -> str:
    """Run `dig` with the given args, return stdout or '' on error."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError):
        return ""
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return ""
    return stdout.decode("utf-8", errors="replace")


async def _dig(qtype: str, qname: str, server: Optional[str] = None,
               timeout: float = 4.0) -> list[str]:
    """Short-format dig: one record per line, no comments. Returns the
    raw text of each answer (TXT records still come back quoted)."""
    args = [f"+time={int(timeout)}", "+tries=1", "+short"]
    if server:
        args.append(f"@{server}")
    args.extend([qtype, qname])
    out = await _run_dig(args, timeout)
    return [line.strip() for line in out.splitlines() if line.strip()]


async def _dig_full(qtype: str, qname: str, server: Optional[str] = None,
                    timeout: float = 6.0) -> list[str]:
    """Full-answer dig: keeps the `NAME TTL CLASS TYPE RDATA` format. Used
    for ANY and AXFR where the record type is part of what we're after."""
    args = [f"+time={int(timeout)}", "+tries=1",
            "+noall", "+answer", "+nocomments", "+nocmd"]
    if server:
        args.append(f"@{server}")
    args.extend([qtype, qname])
    out = await _run_dig(args, timeout)
    return [line.strip() for line in out.splitlines()
            if line.strip() and not line.startswith(";")]


# ---------------------------------------------------------------------------
# TXT helpers — strip quoting, collapse multi-string TXTs
# ---------------------------------------------------------------------------

_TXT_QUOTE_PAIR_RE = re.compile(r'"\s+"')


def _unquote_txt(raw: str) -> str:
    """dig formats multi-string TXT records as `"part1" "part2"`. Strip the
    outer quotes and the inner glue so the result is one logical string."""
    s = raw.strip()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return _TXT_QUOTE_PAIR_RE.sub("", s)


# ---------------------------------------------------------------------------
# Per-type wrappers
# ---------------------------------------------------------------------------

async def dns_records(domain: str, types: list[str] = BASIC_TYPES,
                      timeout: float = 4.0) -> dict[str, list[str]]:
    """Fetch every type in `types` in parallel. Returns a dict of
    type → [record, …]; types with no answers are omitted."""
    results = await asyncio.gather(*(_dig(t, domain, timeout=timeout)
                                     for t in types))
    out: dict[str, list[str]] = {}
    for t, vals in zip(types, results):
        if not vals:
            continue
        if t == "TXT":
            out[t] = [_unquote_txt(v) for v in vals]
        else:
            out[t] = vals
    return out


# ---------------------------------------------------------------------------
# SOA — parse the 7-tuple (primary NS, admin email, serial, refresh, retry,
#       expire, minimum). The admin-contact label has the first dot replaced
#       by `@` to produce a real email address.
# ---------------------------------------------------------------------------

def parse_soa(raw: str) -> Optional[SOARecord]:
    parts = raw.strip().rstrip(".").split()
    if len(parts) < 7:
        return None
    primary = parts[0].rstrip(".").lower()
    admin_dns = parts[1].rstrip(".")
    # Convert DNS-form admin contact ("hostmaster.example.com") to email
    # ("hostmaster@example.com"). The first unescaped dot is the @-sign.
    if "." in admin_dns:
        local, _, dom = admin_dns.partition(".")
        admin_email = f"{local}@{dom}"
    else:
        admin_email = admin_dns
    try:
        serial, refresh, retry, expire, minimum = (int(p) for p in parts[2:7])
    except ValueError:
        return None
    return SOARecord(primary_ns=primary, admin_email=admin_email,
                     serial=serial, refresh=refresh, retry=retry,
                     expire=expire, minimum=minimum, raw=raw.strip())


# ---------------------------------------------------------------------------
# SPF — fetch + recursive include/redirect expansion
# ---------------------------------------------------------------------------

async def dns_spf(domain: str, _depth: int = 0,
                  _seen: Optional[set[str]] = None,
                  ) -> tuple[list[str], list[str]]:
    """Return (spf_records_at_domain, all_includes_resolved_recursively).
    Caps recursion at 10 levels per RFC 7208 §4.6.4."""
    if _seen is None:
        _seen = set()
    if domain in _seen or _depth > 10:
        return [], []
    _seen.add(domain)

    raw = await _dig("TXT", domain)
    spf = [_unquote_txt(r) for r in raw
           if _unquote_txt(r).lower().startswith("v=spf1")]

    includes: list[str] = []
    for record in spf:
        for token in record.split():
            tok_low = token.lower()
            if tok_low.startswith("include:"):
                inc = token.split(":", 1)[1].rstrip(".").lower()
                includes.append(inc)
                _, sub = await dns_spf(inc, _depth + 1, _seen)
                includes.extend(sub)
            elif tok_low.startswith("redirect="):
                rd = token.split("=", 1)[1].rstrip(".").lower()
                includes.append(rd)
                _, sub = await dns_spf(rd, _depth + 1, _seen)
                includes.extend(sub)
    return spf, includes


# ---------------------------------------------------------------------------
# DMARC — fetch _dmarc.<domain> TXT, parse tags
# ---------------------------------------------------------------------------

async def dns_dmarc(domain: str) -> tuple[Optional[str], dict[str, str]]:
    raw = await _dig("TXT", f"_dmarc.{domain}")
    for r in raw:
        txt = _unquote_txt(r)
        if not txt.lower().startswith("v=dmarc1"):
            continue
        parsed: dict[str, str] = {}
        for part in txt.split(";"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            parsed[k.strip().lower()] = v.strip()
        return txt, parsed
    return None, {}


# ---------------------------------------------------------------------------
# DKIM — brute common selectors
# ---------------------------------------------------------------------------

async def dns_dkim(domain: str, selectors: Optional[list[str]] = None,
                   concurrency: int = 20) -> dict[str, str]:
    selectors = selectors or DKIM_SELECTORS
    sem = asyncio.Semaphore(concurrency)
    found: dict[str, str] = {}

    async def _probe(sel: str) -> None:
        async with sem:
            raw = await _dig("TXT", f"{sel}._domainkey.{domain}")
        for r in raw:
            txt = _unquote_txt(r)
            # DKIM keys have either v=DKIM1, a k= tag, or a p= public key
            if "v=DKIM1" in txt or "k=" in txt or "p=" in txt:
                found[sel] = txt
                return

    await asyncio.gather(*(_probe(s) for s in selectors))
    return found


# ---------------------------------------------------------------------------
# ANY — query the authoritative NS to bypass RFC 8482 minimization
# ---------------------------------------------------------------------------

async def dns_any(domain: str, authoritative_ns: Optional[str] = None
                  ) -> list[str]:
    if not authoritative_ns:
        ns_list = await _dig("NS", domain)
        if not ns_list:
            return []
        authoritative_ns = ns_list[0].rstrip(".")
    return await _dig_full("ANY", domain, server=authoritative_ns, timeout=6.0)


# ---------------------------------------------------------------------------
# AXFR — zone transfer attempt
# ---------------------------------------------------------------------------

_AXFR_FAIL_MARKERS = ("Transfer failed", "communications error",
                      "REFUSED", "connection refused",
                      "no servers could be reached")


async def dns_axfr(domain: str, ns: str, timeout: float = 8.0) -> list[str]:
    """Returns the zone records on success; empty list on refusal or error."""
    args = [f"+time={int(timeout)}", "+tries=1", "+noall", "+answer",
            f"@{ns}", "AXFR", domain]
    out = await _run_dig(args, timeout)
    if any(marker in out for marker in _AXFR_FAIL_MARKERS):
        return []
    lines = [l.strip() for l in out.splitlines()
             if l.strip() and not l.startswith(";")]
    # A successful AXFR returns at minimum 2 SOA records (start + end)
    if len(lines) < 2:
        return []
    return lines


# ---------------------------------------------------------------------------
# Subdomain brute force — resolve `<word>.<domain>` in parallel against a
# wordlist. Per the design note, no wildcard suppression: the caller decides
# what to do with the wildcard_address from dns_wildcard.
# ---------------------------------------------------------------------------

# Strict-ish DNS label: lowercase a-z/0-9/hyphen, no leading/trailing hyphen,
# up to 63 chars. Filters out comments and junk so a stray "#" in a wordlist
# doesn't get queried.
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$")


def load_subdomain_wordlist(path: str) -> list[str]:
    """Load a subdomain wordlist file. Strips comments, blank lines, and
    anything that isn't a valid single DNS label. Deduplicates."""
    seen: set[str] = set()
    out: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                w = line.strip().lower().rstrip(".")
                if not w or w.startswith("#"):
                    continue
                if not _LABEL_RE.match(w):
                    continue
                if w in seen:
                    continue
                seen.add(w)
                out.append(w)
    except OSError:
        return []
    return out


async def dns_brute(domain: str, wordlist: Optional[list[str]] = None,
                    wordlist_path: Optional[str] = None,
                    concurrency: int = 50,
                    timeout: float = 3.0) -> dict[str, list[str]]:
    """Resolve `<word>.<domain>` for every label in `wordlist` (or load from
    `wordlist_path`, defaulting to the bundled top-5000). Returns a dict
    fqdn → [A/AAAA records] for every label that resolved.

    Honors `concurrency` so a 5k pass against an aggressive resolver doesn't
    flood it. Returns {} on empty/missing wordlist."""
    if wordlist is None:
        words = load_subdomain_wordlist(wordlist_path or DEFAULT_SUBDOMAIN_WORDLIST)
    else:
        words = wordlist
    if not words:
        return {}

    sem = asyncio.Semaphore(max(1, concurrency))
    hits: dict[str, list[str]] = {}

    async def _probe(label: str) -> None:
        fqdn = f"{label}.{domain}"
        async with sem:
            a = await _dig("A", fqdn, timeout=timeout)
            aaaa = await _dig("AAAA", fqdn, timeout=timeout) if not a else []
        addrs = a + aaaa
        if addrs:
            hits[fqdn] = addrs

    await asyncio.gather(*(_probe(w) for w in words))
    return hits


# ---------------------------------------------------------------------------
# Wildcard detection — query a random label, see if it answers
# ---------------------------------------------------------------------------

async def dns_wildcard(domain: str) -> tuple[bool, Optional[str]]:
    nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
    addrs = await _dig("A", f"{nonce}.{domain}")
    if addrs:
        return True, addrs[0]
    return False, None


# ---------------------------------------------------------------------------
# Hostname extraction — pull hostnames out of MX/CNAME/SRV/NS/AXFR results
# ---------------------------------------------------------------------------

_AXFR_HOSTNAME_RE = re.compile(r"^([a-z0-9_][a-z0-9._\-]*?)\.?\s+\d+\s+IN\s+",
                                re.IGNORECASE)


def _hostnames_from_records(records: dict[str, list[str]],
                            domain: str) -> list[str]:
    out: set[str] = set()

    def _norm(h: str) -> str:
        return h.strip().rstrip(".").lower()

    for r in records.get("MX", []):
        # "10 mail.example.com."
        parts = r.split()
        if len(parts) >= 2:
            out.add(_norm(parts[-1]))
    for r in records.get("CNAME", []):
        out.add(_norm(r))
    for r in records.get("NS", []):
        out.add(_norm(r))
    for r in records.get("SRV", []):
        # "10 5 443 host.example.com."
        parts = r.split()
        if len(parts) >= 4:
            out.add(_norm(parts[-1]))
    for r in records.get("HTTPS", []) + records.get("SVCB", []):
        # "1 . alpn=h2,h3" or "1 alt.example.com. alpn=h2"
        parts = r.split()
        if len(parts) >= 2 and parts[1] not in (".", "@"):
            out.add(_norm(parts[1]))

    # Only keep ones in the same eTLD+1 family as the seed domain
    return sorted(h for h in out
                  if h and h != domain and h.endswith("." + domain))


def _hostnames_from_axfr(zone_lines: list[str], domain: str) -> list[str]:
    out: set[str] = set()
    for line in zone_lines:
        m = _AXFR_HOSTNAME_RE.match(line)
        if not m:
            continue
        label = m.group(1).strip(".").lower()
        # dig prints relative labels as `host` and absolute as `host.example.com.`
        if "." in label and label.endswith(domain):
            out.add(label)
        elif "." not in label and label not in ("@",):
            out.add(f"{label}.{domain}")
    return sorted(out)


# ---------------------------------------------------------------------------
# Master entrypoint
# ---------------------------------------------------------------------------

async def full_dns_recon(domain: str, *,
                         do_axfr: bool = False,
                         do_dkim: bool = True,
                         do_any: bool = True,
                         do_brute: bool = False,
                         dkim_selectors: Optional[list[str]] = None,
                         brute_wordlist: Optional[list[str]] = None,
                         brute_wordlist_path: Optional[str] = None,
                         brute_concurrency: int = 50,
                         ) -> DNSRecon:
    start = time.monotonic()
    rec = DNSRecon(domain=domain)

    # Phase 1: all basic record types in parallel
    rec.records = await dns_records(domain)
    rec.authoritative_ns = sorted({
        ns.rstrip(".").lower() for ns in rec.records.get("NS", [])
    })
    for soa_line in rec.records.get("SOA", []):
        parsed_soa = parse_soa(soa_line)
        if parsed_soa:
            rec.soa = parsed_soa
            break

    # Phase 2: mail-policy lookups + wildcard detection (also parallel)
    spf_task = asyncio.create_task(dns_spf(domain))
    dmarc_task = asyncio.create_task(dns_dmarc(domain))
    wildcard_task = asyncio.create_task(dns_wildcard(domain))
    dkim_task = (asyncio.create_task(dns_dkim(domain, dkim_selectors))
                 if do_dkim else None)

    (rec.spf, rec.spf_includes) = await spf_task
    (rec.dmarc, rec.dmarc_parsed) = await dmarc_task
    (rec.wildcard, rec.wildcard_address) = await wildcard_task
    if dkim_task:
        rec.dkim = await dkim_task

    # Phase 3: ANY against authoritative (bypasses RFC 8482 minimization)
    if do_any and rec.authoritative_ns:
        rec.any_records = await dns_any(domain, rec.authoritative_ns[0])

    # Phase 4: AXFR against every NS — sequential to avoid hammering a single
    # provider when all NSes share infrastructure
    if do_axfr and rec.authoritative_ns:
        for ns in rec.authoritative_ns:
            zone = await dns_axfr(domain, ns)
            if zone:
                rec.axfr[ns] = zone

    # Phase 5: subdomain brute force (opt-in via do_brute). Per design, we
    # don't suppress wildcard matches here — caller filters using
    # rec.wildcard_address if desired.
    if do_brute:
        if brute_wordlist is None:
            brute_words = load_subdomain_wordlist(
                brute_wordlist_path or DEFAULT_SUBDOMAIN_WORDLIST)
        else:
            brute_words = brute_wordlist
        rec.brute_wordlist_size = len(brute_words)
        rec.brute_hits = await dns_brute(
            domain, wordlist=brute_words, concurrency=brute_concurrency)

    # Collect every hostname we surfaced anywhere in the recon
    discovered: set[str] = set(_hostnames_from_records(rec.records, domain))
    for zone_lines in rec.axfr.values():
        discovered.update(_hostnames_from_axfr(zone_lines, domain))
    discovered.update(rec.brute_hits.keys())
    rec.discovered_hostnames = sorted(discovered)

    rec.elapsed_s = time.monotonic() - start
    return rec


# ---------------------------------------------------------------------------
# Standalone CLI for testing — `python3 src/dns_recon.py example.com`
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse, json, sys
    p = argparse.ArgumentParser(prog="dns_recon",
                                description="Comprehensive DNS recon (dig wrapper)")
    p.add_argument("domain", help="Target apex domain (e.g. example.com)")
    p.add_argument("--dns-xfer", action="store_true",
                   help="Attempt AXFR zone transfer against each NS "
                        "(off by default — active/intrusive probe)")
    p.add_argument("--no-dkim", action="store_true")
    p.add_argument("--no-any", action="store_true")
    p.add_argument("--brute", action="store_true",
                   help="Run subdomain brute force (off by default — noisy)")
    p.add_argument("--brute-wordlist", default=None,
                   help=f"Path to subdomain wordlist (default: {DEFAULT_SUBDOMAIN_WORDLIST})")
    p.add_argument("--brute-concurrency", type=int, default=50,
                   help="Parallel resolver queries during brute (default 50)")
    args = p.parse_args()

    rec = asyncio.run(full_dns_recon(
        args.domain,
        do_axfr=args.dns_xfer,
        do_dkim=not args.no_dkim,
        do_any=not args.no_any,
        do_brute=args.brute,
        brute_wordlist_path=args.brute_wordlist,
        brute_concurrency=args.brute_concurrency,
    ))
    print(json.dumps(rec.to_dict(), indent=2))
    n_types = len(rec.records)
    n_hosts = len(rec.discovered_hostnames)
    n_axfr = sum(len(v) for v in rec.axfr.values())
    n_dkim = len(rec.dkim)
    n_brute = len(rec.brute_hits)
    print(f"types={n_types} hosts={n_hosts} dkim_selectors={n_dkim} "
          f"axfr_lines={n_axfr} brute_hits={n_brute}/{rec.brute_wordlist_size} "
          f"wildcard={rec.wildcard} elapsed={rec.elapsed_s:.2f}s", file=sys.stderr)
