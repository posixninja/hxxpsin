"""Enrichment tab — entity browser: users, OAuth apps, hosts, secrets."""
from __future__ import annotations

import json
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.message import Message
from textual.widgets import (
    Button, DataTable, Label, ListItem, ListView, Select,
    Static, TabbedContent, TabPane, TextArea,
)

from ..state import AppState
from .requests import SendToRepeater


class LoadAuthIntoRepeater(Message):
    def __init__(self, headers: dict) -> None:
        super().__init__()
        self.headers = headers


class EnrichmentScreen(Horizontal):
    """Entity browser over output/enrichment/ directory."""

    BINDINGS = [
        Binding("r", "load_auth_repeater", "Auth → Repeater"),
        Binding("v", "reveal_secret", "Reveal"),
        Binding("c", "copy_to_clipboard", "Copy"),
    ]

    DEFAULT_CSS = """
    EnrichmentScreen {
        height: 1fr;
    }
    EnrichmentScreen #entity-sidebar {
        width: 20%;
        border-right: solid $primary;
    }
    EnrichmentScreen #entity-list-panel {
        width: 38%;
        border-right: solid $primary;
    }
    EnrichmentScreen #entity-detail-panel {
        width: 42%;
    }
    EnrichmentScreen DataTable {
        height: 1fr;
    }
    EnrichmentScreen ListView {
        height: 1fr;
    }
    EnrichmentScreen TextArea {
        height: 1fr;
        border: none;
    }
    EnrichmentScreen .sidebar-item {
        padding: 0 1;
    }
    """

    _ENTITY_TYPES = ["Users", "OAuth Apps", "Hosts", "Secrets", "JS Analysis", "LLM Verdicts"]

    def __init__(self, state: AppState, **kwargs):
        super().__init__(**kwargs)
        self._state = state
        self._current_type: str = "Users"
        self._users: list[dict] = []
        self._oauth_apps: list[dict] = []
        self._hosts: list[dict] = []
        self._secrets: list[dict] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="entity-sidebar"):
            yield Static("Entity Type", classes="sidebar-item")
            yield ListView(id="entity-type-list")

        with Vertical(id="entity-list-panel"):
            yield DataTable(id="entity-table", cursor_type="row", zebra_stripes=True)

        with Vertical(id="entity-detail-panel"):
            with TabbedContent(id="detail-tabs"):
                with TabPane("Profile", id="tab-profile"):
                    yield TextArea("", id="profile-text", read_only=True)
                with TabPane("Auth", id="tab-auth"):
                    yield TextArea("", id="auth-text", read_only=True)
                    yield Button("Load into Repeater", id="btn-auth-repeater", variant="primary")
                with TabPane("Secrets", id="tab-secrets"):
                    yield TextArea("", id="secrets-text", read_only=True)
                with TabPane("Provenance", id="tab-provenance"):
                    yield TextArea("", id="provenance-text", read_only=True)

    def on_mount(self) -> None:
        lv = self.query_one("#entity-type-list", ListView)
        for etype in self._ENTITY_TYPES:
            lv.append(ListItem(Label(etype)))
        self._load_enrichment_data()
        self._switch_entity_type("Users")

    def _load_enrichment_data(self) -> None:
        enrich_dir = self._state.enrichment_dir
        if not enrich_dir:
            return
        p = Path(enrich_dir)

        # Load users
        users_dir = p / "users"
        self._users = []
        if users_dir.is_dir():
            for user_dir in sorted(users_dir.iterdir()):
                record_file = user_dir / "record.json"
                auth_file = user_dir / "auth.json"
                if record_file.exists():
                    try:
                        rec = json.loads(record_file.read_text())
                        if auth_file.exists():
                            rec["_auth"] = json.loads(auth_file.read_text())
                        prov_file = user_dir / "provenance.json"
                        if prov_file.exists():
                            rec["_provenance"] = json.loads(prov_file.read_text())
                        self._users.append(rec)
                    except Exception:
                        pass

        # Load OAuth apps
        oauth_dir = p / "oauth_apps"
        self._oauth_apps = []
        if oauth_dir.is_dir():
            for app_dir in sorted(oauth_dir.iterdir()):
                record_file = app_dir / "record.json"
                if record_file.exists():
                    try:
                        self._oauth_apps.append(json.loads(record_file.read_text()))
                    except Exception:
                        pass

        # Load hosts
        hosts_dir = p / "hosts"
        self._hosts = []
        if hosts_dir.is_dir():
            for host_dir in sorted(hosts_dir.iterdir()):
                record_file = host_dir / "record.json"
                if record_file.exists():
                    try:
                        self._hosts.append(json.loads(record_file.read_text()))
                    except Exception:
                        pass

        # Load secrets
        secrets_dir = p / "secrets"
        self._secrets = []
        if secrets_dir.is_dir():
            for secret_dir in sorted(secrets_dir.iterdir()):
                meta_file = secret_dir / "metadata.json"
                if meta_file.exists():
                    try:
                        meta = json.loads(meta_file.read_text())
                        val_file = secret_dir / "value.txt"
                        if val_file.exists():
                            meta["_value"] = val_file.read_text().strip()
                        self._secrets.append(meta)
                    except Exception:
                        pass

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        lv = event.list_view
        if lv.id == "entity-type-list":
            idx = lv.index
            if idx is not None and 0 <= idx < len(self._ENTITY_TYPES):
                self._switch_entity_type(self._ENTITY_TYPES[idx])
        else:
            # entity detail list — handled by DataTable
            pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        self._show_entity_detail(idx)

    def _switch_entity_type(self, etype: str) -> None:
        self._current_type = etype
        table = self.query_one("#entity-table", DataTable)
        table.clear(columns=True)

        if etype == "Users":
            table.add_columns("ID", "Score", "Emails", "Has Creds")
            if not self._users:
                table.add_row("—", "No users found in enrichment output", "", "")
            else:
                for u in self._users:
                    emails = ", ".join(u.get("emails", [])[:2])
                    table.add_row(
                        str(u.get("canonical_id", ""))[:20],
                        str(u.get("score", "")),
                        emails[:40],
                        "✓" if u.get("has_credentials") else "",
                    )

        elif etype == "OAuth Apps":
            table.add_columns("Client ID", "Name", "Secret", "Redirect URIs")
            if not self._oauth_apps:
                table.add_row("—", "No OAuth apps found in enrichment output", "", "")
            else:
                for app in self._oauth_apps:
                    table.add_row(
                        str(app.get("client_id", ""))[:30],
                        str(app.get("name", "")),
                        "✓" if app.get("client_secret_present") else "",
                        str(len(app.get("redirect_uris", []))),
                    )

        elif etype == "Hosts":
            table.add_columns("Hostname", "IPs", "Paths")
            if not self._hosts:
                table.add_row("—", "No hosts found in enrichment output", "")
            else:
                for h in self._hosts:
                    ips = ", ".join(h.get("ips", [])[:3])
                    table.add_row(
                        str(h.get("hostname", "")),
                        ips[:30],
                        str(len(h.get("discovered_paths", []))),
                    )

        elif etype == "Secrets":
            table.add_columns("Type", "Entropy", "Preview", "Length")
            if not self._secrets:
                table.add_row("—", "No secrets found in enrichment output", "", "")
            else:
                for s in self._secrets:
                    table.add_row(
                        str(s.get("type_hint", "")),
                        str(s.get("entropy", "")),
                        str(s.get("value_preview", ""))[:30],
                        str(s.get("value_length", "")),
                    )

        elif etype == "JS Analysis":
            js_path = None
            if self._state.out_dir:
                js_path = Path(self._state.out_dir) / "js_analysis.json"
            table.add_columns("Type", "Value")
            loaded = False
            if js_path and js_path.exists():
                try:
                    js = json.loads(js_path.read_text())
                    for ep in js.get("endpoints", [])[:50]:
                        table.add_row("endpoint", str(ep.get("path", "")))
                        loaded = True
                    for sec in js.get("secrets", [])[:20]:
                        table.add_row("secret", str(sec.get("type", "")) + ": " + str(sec.get("value", ""))[:40])
                        loaded = True
                except Exception:
                    pass
            if not loaded:
                table.add_row("—", "No JS analysis data — run a scan first")

        elif etype == "LLM Verdicts":
            table.add_columns("Verdict", "Category", "URL", "Reason")
            llm_path = None
            if self._state.out_dir:
                llm_path = Path(self._state.out_dir) / "llm_verifier.json"
            loaded = False
            if llm_path and llm_path.exists():
                try:
                    data = json.loads(llm_path.read_text())
                    results = data if isinstance(data, list) else data.get("results", [])
                    for r in results:
                        table.add_row(
                            str(r.get("verdict", "")),
                            str(r.get("category", "")),
                            str(r.get("url", ""))[:40],
                            str(r.get("reason", ""))[:40],
                        )
                        loaded = True
                except Exception:
                    pass
            if not loaded:
                table.add_row("—", "No LLM verdicts — run with --llm flag", "", "")

    def _show_entity_detail(self, idx: int) -> None:
        etype = self._current_type
        entities = {
            "Users": self._users,
            "OAuth Apps": self._oauth_apps,
            "Hosts": self._hosts,
            "Secrets": self._secrets,
        }.get(etype, [])

        if not (0 <= idx < len(entities)):
            return
        entity = entities[idx]

        profile_lines = [f"{k}: {v}" for k, v in entity.items()
                         if not k.startswith("_") and not isinstance(v, (dict, list))]
        self.query_one("#profile-text", TextArea).load_text("\n".join(profile_lines))

        auth = entity.get("_auth", {})
        if auth:
            auth_lines = []
            meta = auth.get("_meta", {})
            for key in ("Authorization", "Cookie", "X-Auth-Token"):
                if key in auth:
                    auth_lines.append(f"{key}: {auth[key]}")
            if meta:
                for k, v in meta.items():
                    auth_lines.append(f"{k}: {v}")
            self.query_one("#auth-text", TextArea).load_text("\n".join(auth_lines))
        else:
            self.query_one("#auth-text", TextArea).load_text("(no auth headers)")

        prov = entity.get("_provenance", [])
        if prov:
            prov_lines = [f"{p.get('url', '')}  {p.get('json_path', '')}" for p in prov[:30]]
            self.query_one("#provenance-text", TextArea).load_text("\n".join(prov_lines))

        if "_value" in entity:
            self.query_one("#secrets-text", TextArea).load_text("(press v to reveal)")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-auth-repeater":
            auth_text = self.query_one("#auth-text", TextArea).text
            headers: dict = {}
            for line in auth_text.splitlines():
                if ": " in line:
                    k, _, v = line.partition(": ")
                    headers[k.strip()] = v.strip()
            if headers:
                self.post_message(LoadAuthIntoRepeater(headers))
                self.app.notify(f"Loaded {len(headers)} auth header(s) into Repeater")
            else:
                self.app.notify("No auth headers found for this entity", severity="warning")

    def action_load_auth_repeater(self) -> None:
        self.query_one("#btn-auth-repeater", Button).press()

    def action_reveal_secret(self) -> None:
        table = self.query_one("#entity-table", DataTable)
        idx = table.cursor_row
        if self._current_type == "Secrets" and 0 <= idx < len(self._secrets):
            value = self._secrets[idx].get("_value", "(unavailable)")
            self.query_one("#secrets-text", TextArea).load_text(value)

    def action_copy_to_clipboard(self) -> None:
        """Copy the most relevant visible text to the system clipboard."""
        import subprocess
        try:
            tabs = self.query_one("#detail-tabs", TabbedContent)
            active = tabs.active
        except Exception:
            active = ""

        text = ""
        try:
            if active == "tab-secrets" or self._current_type == "Secrets":
                text = self.query_one("#secrets-text", TextArea).text
            elif active == "tab-auth":
                text = self.query_one("#auth-text", TextArea).text
            elif active == "tab-profile":
                text = self.query_one("#profile-text", TextArea).text
            else:
                text = self.query_one("#auth-text", TextArea).text
        except Exception:
            pass

        if not text or text in ("(no auth headers)", "(press v to reveal)"):
            self.app.notify("Nothing to copy — reveal the secret first (v)", severity="warning")
            return

        try:
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
            preview = text[:40].replace("\n", " ")
            self.app.notify(f"Copied: {preview}…" if len(text) > 40 else f"Copied: {text}")
        except Exception as e:
            self.app.notify(f"Clipboard error: {e}", severity="error")

    def refresh_data(self) -> None:
        self._load_enrichment_data()
        self._switch_entity_type(self._current_type)
