"""Recon tab — Surface mapper (Stage 0) + DNS + OOB tunnel hits."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static, TabbedContent, TabPane, TextArea

from ..state import AppState
from .msf import MSFPane


_HIT_COLS = ["received_at", "kind", "method", "path", "peer", "correlation_id"]
_HOST_COLS = ["hostname", "addresses", "source", "open_ports"]
_VHOST_COLS = ["ip", "port", "hostname", "status", "content_length", "distinct"]
_ASN_COLS = ["ip", "asn", "as_name", "country", "prefix"]


def _join(v) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v[:6])
    if v is None:
        return ""
    return str(v)


class SurfacePane(Vertical):
    DEFAULT_CSS = """
    SurfacePane { height: 1fr; }
    SurfacePane Static.section { background: $surface-darken-1; padding: 0 1; height: 1; color: $text-muted; }
    SurfacePane DataTable { height: 1fr; }
    SurfacePane #surface-summary { height: 5; padding: 0 1; }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state

    def compose(self) -> ComposeResult:
        yield Static("", id="surface-summary")
        yield Static("Hosts", classes="section")
        yield DataTable(id="surface-hosts", cursor_type="row", zebra_stripes=True)
        yield Static("Virtual-host hits", classes="section")
        yield DataTable(id="surface-vhosts", cursor_type="row", zebra_stripes=True)
        yield Static("ASN / netblocks", classes="section")
        yield DataTable(id="surface-asn", cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        self.query_one("#surface-hosts", DataTable).add_columns(*_HOST_COLS)
        self.query_one("#surface-vhosts", DataTable).add_columns(*_VHOST_COLS)
        self.query_one("#surface-asn", DataTable).add_columns(*_ASN_COLS)
        self.refresh_data()

    def refresh_data(self) -> None:
        scope = self._state.scope or {}
        seed = scope.get("seed", "")
        root = scope.get("root_domain", "")
        hosts = scope.get("hosts", []) or []
        vhosts = scope.get("vhost_hits", []) or []
        asn = scope.get("asn", []) or []
        prefixes = scope.get("netblock_prefixes", []) or []
        whois = scope.get("whois") or {}
        elapsed = scope.get("elapsed_s", 0)

        if not scope:
            summary = "Surface mapper has not run — pass --auto-scope/--port-scan/--analyze-block on the next scan."
        else:
            registrar = whois.get("registrar", "—") if isinstance(whois, dict) else "—"
            summary = (
                f"seed:   {seed}\n"
                f"root:   {root}\n"
                f"hosts:  {len(hosts)}    vhosts: {len(vhosts)}    asn:    {len(asn)}    "
                f"netblocks: {len(prefixes)}\n"
                f"whois:  {registrar}\n"
                f"elapsed: {elapsed}s"
            )
        self.query_one("#surface-summary", Static).update(summary)

        hosts_t = self.query_one("#surface-hosts", DataTable)
        hosts_t.clear()
        for h in hosts:
            if not isinstance(h, dict):
                continue
            hosts_t.add_row(
                _join(h.get("hostname")),
                _join(h.get("addresses")),
                _join(h.get("source")),
                _join(h.get("open_ports")),
            )

        vhosts_t = self.query_one("#surface-vhosts", DataTable)
        vhosts_t.clear()
        for v in vhosts:
            if not isinstance(v, dict):
                continue
            vhosts_t.add_row(
                _join(v.get("ip")),
                _join(v.get("port")),
                _join(v.get("hostname")),
                _join(v.get("status")),
                _join(v.get("content_length")),
                "yes" if v.get("distinct_from_baseline") else "no",
            )

        asn_t = self.query_one("#surface-asn", DataTable)
        asn_t.clear()
        for a in asn:
            if not isinstance(a, dict):
                continue
            asn_t.add_row(
                _join(a.get("ip")),
                _join(a.get("asn")),
                _join(a.get("as_name")),
                _join(a.get("country")),
                _join(a.get("prefix")),
            )


class DNSPane(Vertical):
    """DNS records pulled from scope.dns."""
    DEFAULT_CSS = """
    DNSPane { height: 1fr; }
    DNSPane TextArea { height: 1fr; border: none; }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state

    def compose(self) -> ComposeResult:
        yield TextArea("", id="dns-text", read_only=True)

    def on_mount(self) -> None:
        self.refresh_data()

    def refresh_data(self) -> None:
        scope = self._state.scope or {}
        dns = scope.get("dns") if isinstance(scope.get("dns"), dict) else {}
        if not dns:
            self.query_one("#dns-text", TextArea).load_text(
                "No DNS recon — run with --auto-scope to populate."
            )
            return
        lines: list[str] = [f"domain: {dns.get('domain', '')}", ""]
        records = dns.get("records") or {}
        if isinstance(records, dict):
            for rtype, vals in sorted(records.items()):
                lines.append(f"--- {rtype} ---")
                if isinstance(vals, list):
                    for v in vals[:40]:
                        lines.append(f"  {v}")
                else:
                    lines.append(f"  {vals}")
                lines.append("")
        soa = dns.get("soa")
        if isinstance(soa, dict):
            lines.append("--- SOA ---")
            for k, v in soa.items():
                lines.append(f"  {k}: {v}")
            lines.append("")
        axfr = dns.get("axfr") or []
        if axfr:
            lines.append(f"--- AXFR ({len(axfr)} lines) ---")
            for ln in axfr[:80]:
                lines.append(f"  {ln}")
        self.query_one("#dns-text", TextArea).load_text("\n".join(lines))


class TunnelPane(Vertical):
    """OOB tunnel hits — live-updated from `tunnel_hit` events."""
    DEFAULT_CSS = """
    TunnelPane { height: 1fr; }
    TunnelPane #tunnel-header { height: 3; padding: 0 1; background: $surface-darken-1; }
    TunnelPane DataTable { height: 1fr; }
    TunnelPane #tunnel-detail { height: 10; border-top: solid $primary; padding: 0 1; }
    """

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state

    def compose(self) -> ComposeResult:
        yield Static("", id="tunnel-header")
        yield DataTable(id="tunnel-table", cursor_type="row", zebra_stripes=True)
        yield TextArea("", id="tunnel-detail", read_only=True)

    def on_mount(self) -> None:
        self.query_one("#tunnel-table", DataTable).add_columns(*_HIT_COLS)
        self.refresh_data()

    def refresh_data(self) -> None:
        backend = self._state.tunnel_backend or "—"
        public = self._state.tunnel_public_url or "—"
        hits = self._state.tunnel_hits
        header = (
            f"backend: {backend}    public_url: {public}\n"
            f"hits:    {len(hits)}"
        )
        self.query_one("#tunnel-header", Static).update(header)

        table = self.query_one("#tunnel-table", DataTable)
        table.clear()
        for h in hits:
            if not isinstance(h, dict):
                continue
            table.add_row(
                str(h.get("received_at", ""))[:19],
                _join(h.get("kind")),
                _join(h.get("method")),
                _join(h.get("path"))[:60],
                _join(h.get("peer"))[:30],
                _join(h.get("correlation_id"))[:24],
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        hits = self._state.tunnel_hits
        if 0 <= idx < len(hits):
            h = hits[idx]
            lines = [f"{k}: {v}" for k, v in h.items() if k != "body"]
            body = h.get("body", "")
            if body:
                lines.append("")
                lines.append("--- body ---")
                lines.append(str(body)[:4000])
            self.query_one("#tunnel-detail", TextArea).load_text("\n".join(lines))


class ReconScreen(Vertical):
    """Recon tab: Surface + DNS + Tunnel + MSF sub-panes."""

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._surface: SurfacePane | None = None
        self._dns: DNSPane | None = None
        self._tunnel: TunnelPane | None = None
        self._msf: MSFPane | None = None

    def compose(self) -> ComposeResult:
        with TabbedContent():
            with TabPane("Surface", id="recon-surface"):
                self._surface = SurfacePane(self._state)
                yield self._surface
            with TabPane("DNS", id="recon-dns"):
                self._dns = DNSPane(self._state)
                yield self._dns
            with TabPane("Tunnel (OOB)", id="recon-tunnel"):
                self._tunnel = TunnelPane(self._state)
                yield self._tunnel
            with TabPane("MSF", id="recon-msf"):
                self._msf = MSFPane(self._state)
                yield self._msf

    def refresh_data(self) -> None:
        if self._surface is not None:
            self._surface.refresh_data()
        if self._dns is not None:
            self._dns.refresh_data()
        if self._tunnel is not None:
            self._tunnel.refresh_data()
        if self._msf is not None:
            self._msf.refresh_data()
