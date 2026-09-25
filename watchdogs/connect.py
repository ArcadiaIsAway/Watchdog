"""Connect wizard: pick a role, then join with live nearby detection."""

from __future__ import annotations

import os
import socket
import threading

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from watchdogs.discover import (
    Peer,
    collect_peers,
    describe_endpoints,
    local_addresses,
    normalize_join_code,
)
from watchdogs.engine import Engine


def _privileged() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


class ConnectScreen(ModalScreen[str | None]):
    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(self, engine: Engine) -> None:
        super().__init__()
        self.engine = engine
        self._joining = False
        self._scan_stop = threading.Event()
        self._peers: dict[str, Peer] = {}
        self._view = "pick"

    def compose(self) -> ComposeResult:
        with Vertical(id="connect-box"):
            yield Label("CONNECT", id="connect-title")
            with Vertical(id="view-pick"):
                yield Static(
                    "Same program on both machines. Start here on your computer, "
                    "then do the same on the server with sudo.",
                    id="pick-lead",
                )
                yield Button("1   My computer  —  I will watch from here", id="as-dashboard", variant="primary")
                yield Button("2   This is the server  —  send logins and commands", id="as-server", variant="success")
                yield Button("Just monitor this machine", id="as-local")
            with Vertical(id="view-dashboard"):
                yield Label("ON THE SERVER — look for this", id="dash-server-label")
                yield Static("", id="dash-identity")
                yield Static("", id="connect-code")
                yield Static("", id="dash-steps")
                yield Static("", id="dash-addrs")
                yield Static("", id="dash-wait")
                with Horizontal(id="connect-after"):
                    yield Button("Copy code", id="copy-code")
                    yield Button("Copy best address", id="copy-addr")
                    yield Button("Show monitor", id="to-monitor", variant="primary")
                    yield Button("I am the server", id="switch-server")
            with Vertical(id="view-server"):
                yield Static("", id="server-steps")
                yield Label("Nearby dashboards  —  click one to join")
                yield OptionList(id="nearby")
                yield Label("Or type what the other screen shows")
                yield Input(placeholder="Join code   e.g. K7M2", id="in-code", max_length=8)
                yield Input(placeholder="Address if nothing appears   e.g. 100.x.x.x", id="in-host")
                with Horizontal(id="server-actions"):
                    yield Button("Connect", id="as-agent", variant="success")
                    yield Button("Back", id="back-pick")
            yield Static("", id="connect-status")

    def on_mount(self) -> None:
        self._show("pick")
        if self.engine.link_role == "dashboard" and self.engine.join_code:
            self._show_dashboard()
        elif self.engine.link_role == "agent":
            self._show("server")
            self._start_scan()

    def on_unmount(self) -> None:
        self._scan_stop.set()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "as-dashboard":
            self._open_dashboard()
        elif event.button.id == "as-server":
            self._show("server")
            self._start_scan()
        elif event.button.id == "as-local":
            self.action_skip()
        elif event.button.id == "back-pick":
            self._scan_stop.set()
            self._show("pick")
        elif event.button.id == "copy-code":
            code = self.engine.join_code
            if code:
                self.app.copy_to_clipboard(code)
                self._status(f"Copied join code {code}")
        elif event.button.id == "copy-addr":
            addrs = local_addresses()
            port = int((self.engine.cfg.get("link") or {}).get("port") or 8765)
            if self.engine.report_server and self.engine.report_server.actual_port:
                port = self.engine.report_server.actual_port
            if addrs:
                text = f"{addrs[0]}:{port}"
                self.app.copy_to_clipboard(text)
                self._status(f"Copied {text}")
        elif event.button.id == "to-monitor":
            self.dismiss(f"Dashboard open — join code {self.engine.join_code}")
        elif event.button.id == "switch-server":
            self._become_server()
        elif event.button.id == "as-agent":
            self._join()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id in {"in-code", "in-host"}:
            self._join()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id != "nearby":
            return
        option_id = event.option.id
        if not option_id:
            return
        peer = self._peers.get(option_id)
        if peer is not None:
            self._join_peer(peer)

    def action_back(self) -> None:
        if self._view == "pick":
            self.action_skip()
            return
        if self._view == "dashboard":
            self.dismiss(f"Dashboard open — join code {self.engine.join_code}")
            return
        self._scan_stop.set()
        self._show("pick")

    def action_skip(self) -> None:
        try:
            self.engine.stay_local()
        except Exception as exc:
            self._status(str(exc))
            return
        self.dismiss("Monitoring this machine only")

    def _show(self, view: str) -> None:
        self._view = view
        self.query_one("#view-pick").display = view == "pick"
        self.query_one("#view-dashboard").display = view == "dashboard"
        self.query_one("#view-server").display = view == "server"
        if view == "pick":
            self.query_one("#connect-title", Label).update("CONNECT")
            self._status("")
        elif view == "server":
            self.query_one("#connect-title", Label).update("THIS IS THE SERVER")
            root_note = (
                "This login is root — logins and commands can be captured."
                if _privileged()
                else "Not root. Restart with:  sudo .venv/bin/python -m watchdogs"
            )
            self.query_one("#server-steps", Static).update(
                "The other computer should already show a join code.\n"
                f"{root_note}\n"
                "Nearby dashboards appear below. Click one, or type the code."
            )
            self._status("Searching this network and Tailscale…")
        elif view == "dashboard":
            self.query_one("#connect-title", Label).update("DASHBOARD  ·  this computer")

    def _open_dashboard(self) -> None:
        try:
            self.engine.start_dashboard()
        except OSError as exc:
            self._status(str(exc))
            return
        except Exception as exc:
            self._status(f"Could not open dashboard: {exc}")
            return
        self._show_dashboard()

    def _show_dashboard(self) -> None:
        self._show("dashboard")
        code = self.engine.join_code
        pretty = "   ".join(code) if code else ""
        name = socket.gethostname()
        port = int((self.engine.cfg.get("link") or {}).get("port") or 8765)
        if self.engine.report_server and self.engine.report_server.actual_port:
            port = self.engine.report_server.actual_port
        addrs = "\n".join(describe_endpoints(port))
        self.query_one("#dash-identity", Static).update(
            f"Name   {name}\n"
            f"Code   {code}\n"
            f"The server list should show:  {name}   {code}"
        )
        self.query_one("#connect-code", Static).update(pretty)
        self.query_one("#dash-steps", Static).update(
            "1. On the other machine:  sudo .venv/bin/python -m watchdogs\n"
            "2. Tap the green button:  This is the server\n"
            "3. Click this name/code in Nearby. Same LAN usually finds it.\n"
            "   Different networks: Tailscale on both, then type a 100.x address."
        )
        self.query_one("#dash-addrs", Static).update(addrs)
        self.query_one("#dash-wait", Static).update(
            "Waiting for the server to join…"
            if self.engine.link_status != "up"
            else f"Linked to {self.engine.remote_host or 'server'}"
        )
        if not getattr(self, "_dash_ticking", False):
            self._dash_ticking = True
            self.set_interval(1.0, self._tick_dash)
        self._status(f"Join code {code}  ·  waiting")

    def _tick_dash(self) -> None:
        if self._view != "dashboard":
            return
        if self.engine.link_status == "up":
            self.query_one("#dash-wait", Static).update(
                f"Linked to {self.engine.remote_host or 'server'}"
            )
            self._status(f"Connected  ·  {self.engine.remote_host or 'server'}")
        else:
            self.query_one("#dash-wait", Static).update("Waiting for the server to join…")

    def _become_server(self) -> None:
        try:
            self.engine.stay_local()
        except Exception as exc:
            self._status(str(exc))
            return
        self._show("server")
        self._start_scan()

    def _start_scan(self) -> None:
        self._scan_stop.set()
        self._scan_stop = threading.Event()
        udp = int((self.engine.cfg.get("link") or {}).get("discover_port") or 8766)
        stop = self._scan_stop

        def work() -> None:
            while not stop.is_set():
                try:
                    peers = collect_peers(timeout=1.4, udp_port=udp)
                except Exception:
                    peers = []
                if stop.is_set():
                    return
                self.app.call_from_thread(self._set_nearby, peers)
                stop.wait(0.4)

        threading.Thread(target=work, name="watchdogs-scan", daemon=True).start()

    def _set_nearby(self, peers: list[Peer]) -> None:
        if self._view != "server":
            return
        listing = self.query_one("#nearby", OptionList)
        listing.clear_options()
        self._peers = {}
        if not peers:
            listing.add_option(Option("  searching… nothing yet", id="none", disabled=True))
            self._status("Nothing nearby yet — type the code and the 100.x address from the other screen")
            return
        for index, peer in enumerate(peers):
            key = f"p{index}"
            self._peers[key] = peer
            listing.add_option(Option(f"  {peer.label()}", id=key))
        self._status(f"Found {len(peers)} dashboard(s) — click one, or tap Connect")

    def _join(self) -> None:
        if self._joining:
            return
        code = normalize_join_code(self.query_one("#in-code", Input).value)
        host = self.query_one("#in-host", Input).value.strip()
        if not code and len(self._peers) == 1:
            self._join_peer(next(iter(self._peers.values())))
            return
        if not code:
            self._status("Type the join code, or click a dashboard in the list")
            return
        self._begin_join(code, host)

    def _join_peer(self, peer: Peer) -> None:
        dest = peer.candidates()[0] if peer.candidates() else peer.host
        self.query_one("#in-code", Input).value = peer.code
        self.query_one("#in-host", Input).value = f"{dest}:{peer.port}"
        self._begin_join(peer.code, f"{dest}:{peer.port}")

    def _begin_join(self, code: str, host: str) -> None:
        if self._joining:
            return
        self._joining = True
        self._scan_stop.set()
        where = host or "the network"
        self._status(f"Connecting to {where}…")

        def work() -> None:
            try:
                message = self.engine.join_dashboard(code, host)
            except Exception as exc:
                self.app.call_from_thread(self._join_failed, str(exc))
                return
            self.app.call_from_thread(self.dismiss, "__background__")

        threading.Thread(target=work, name="watchdogs-join", daemon=True).start()

    def _join_failed(self, text: str) -> None:
        self._joining = False
        self._status(text)
        if self._view == "server":
            self._start_scan()

    def _status(self, text: str) -> None:
        self.query_one("#connect-status", Static).update(text)
