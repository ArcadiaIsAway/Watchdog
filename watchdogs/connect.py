"""First-run / join screen: both machines connect from the same dashboard."""

from __future__ import annotations

import threading

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from watchdogs.discover import local_addresses, normalize_join_code
from watchdogs.engine import Engine


class ConnectScreen(ModalScreen[str | None]):
    BINDINGS = [
        Binding("escape", "skip", "This machine only", show=True),
    ]

    def __init__(self, engine: Engine) -> None:
        super().__init__()
        self.engine = engine
        self._joining = False

    def compose(self) -> ComposeResult:
        addrs = ", ".join(local_addresses()) or "no LAN address yet"
        with Vertical(id="connect-box"):
            yield Label("CONNECT", id="connect-title")
            yield Static(
                "Same app on both machines. Open the dashboard on your computer, "
                "then on the server tap Join and type the code. "
                "The server needs sudo to see logins and commands.",
                id="connect-lead",
            )
            yield Static("", id="connect-code")
            yield Static(f"This computer  {addrs}", id="connect-addrs")
            yield Label("Join code from the other screen")
            yield Input(placeholder="K7M2", id="in-code", max_length=8)
            yield Label("Address — only if they are not on the same network")
            yield Input(placeholder="optional  100.x.x.x  or  host:8765", id="in-host")
            yield Static("", id="connect-status")
            with Horizontal(id="connect-actions"):
                yield Button("Open dashboard", id="as-dashboard", variant="primary")
                yield Button("Join dashboard", id="as-agent", variant="success")
                yield Button("This machine only", id="as-local")
            with Horizontal(id="connect-after"):
                yield Button("Copy code", id="copy-code")
                yield Button("Show monitor", id="to-monitor", variant="primary")

    def on_mount(self) -> None:
        after = self.query_one("#connect-after")
        after.display = False
        if self.engine.link_role == "dashboard" and self.engine.join_code:
            self._show_dashboard()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "as-dashboard":
            self._open_dashboard()
        elif event.button.id == "as-agent":
            self._join()
        elif event.button.id == "as-local":
            self.action_skip()
        elif event.button.id == "copy-code":
            code = self.engine.join_code
            if code:
                self.app.copy_to_clipboard(code)
                self._status(f"Copied {code}")
        elif event.button.id == "to-monitor":
            self.dismiss(f"Dashboard open — join code {self.engine.join_code}")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "in-code":
            self._join()

    def action_skip(self) -> None:
        try:
            self.engine.stay_local()
        except Exception as exc:
            self._status(str(exc))
            return
        self.dismiss("Monitoring this machine only")

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
        code = self.engine.join_code
        pretty = "  ".join(code) if code else ""
        self.query_one("#connect-lead", Static).update(
            "On the other machine open WatchDogs and tap Join dashboard."
        )
        self.query_one("#connect-code", Static).update(pretty)
        self.query_one("#connect-actions").display = False
        self.query_one("#connect-after").display = True
        self.query_one("#in-code", Input).disabled = True
        self.query_one("#in-host", Input).disabled = True
        self._status(f"Waiting for the other machine  ·  code {code}")

    def _join(self) -> None:
        if self._joining:
            return
        code = normalize_join_code(self.query_one("#in-code", Input).value)
        host = self.query_one("#in-host", Input).value.strip()
        if not code:
            self._status("Type the join code shown on the other machine")
            return
        self._joining = True
        self._status("Looking for the dashboard…")

        def work() -> None:
            try:
                message = self.engine.join_dashboard(code, host)
            except Exception as exc:
                self.app.call_from_thread(self._join_failed, str(exc))
                return
            self.app.call_from_thread(self.dismiss, message)

        threading.Thread(target=work, name="watchdogs-join", daemon=True).start()

    def _join_failed(self, text: str) -> None:
        self._joining = False
        self._status(text)

    def _status(self, text: str) -> None:
        self.query_one("#connect-status", Static).update(text)
