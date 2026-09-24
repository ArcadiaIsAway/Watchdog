"""In-dashboard form for report target, token, and alert thresholds."""

from __future__ import annotations

import secrets
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static, Switch

from watchdogs.engine import Engine


def values_from_engine(engine: Engine) -> dict[str, Any]:
    cfg = engine.cfg
    report = cfg.get("report") or {}
    alerts = cfg.get("alerts") or {}
    off = alerts.get("off_hours") or {}
    token = engine.report_token or report.get("token") or ""
    return {
        "server": report.get("server") or "",
        "bind": report.get("bind") or "0.0.0.0:8765",
        "token": token,
        "reconnect_sec": int(float(report.get("reconnect_sec") or 3)),
        "failed_login_threshold": alerts.get("failed_login_threshold", 5),
        "failed_login_window_sec": alerts.get("failed_login_window_sec", 300),
        "always_alert_root_login": bool(alerts.get("always_alert_root_login", True)),
        "new_source_ip": bool(alerts.get("new_source_ip", True)),
        "alert_sudo_shell": bool(alerts.get("alert_sudo_shell", True)),
        "off_hours_start": off.get("start", 0),
        "off_hours_end": off.get("end", 6),
        "interactive_only": bool((cfg.get("watch") or {}).get("interactive_only", True)),
    }


def parse_form(screen: SettingsScreen) -> dict[str, Any]:
    def text(widget_id: str) -> str:
        return screen.query_one(widget_id, Input).value.strip()

    def number(widget_id: str, label: str, minimum: int = 0, maximum: int | None = None) -> int:
        raw = text(widget_id)
        if not raw or not raw.lstrip("-").isdigit():
            raise ValueError(f"{label} must be a number")
        value = int(raw)
        if value < minimum or (maximum is not None and value > maximum):
            span = f"{minimum}–{maximum}" if maximum is not None else f">={minimum}"
            raise ValueError(f"{label} must be {span}")
        return value

    return {
        "server": text("#in-target"),
        "bind": text("#in-bind") or "0.0.0.0:8765",
        "token": text("#in-token"),
        "reconnect_sec": number("#in-reconnect", "Retry seconds", minimum=1, maximum=120),
        "failed_login_threshold": number("#in-fail-count", "Failed-login count", minimum=1),
        "failed_login_window_sec": number("#in-fail-window", "Failed-login window", minimum=1),
        "off_hours_start": number("#in-off-start", "Off-hours start", minimum=0, maximum=23),
        "off_hours_end": number("#in-off-end", "Off-hours end", minimum=0, maximum=23),
        "always_alert_root_login": screen.query_one("#sw-root", Switch).value,
        "new_source_ip": screen.query_one("#sw-new-ip", Switch).value,
        "alert_sudo_shell": screen.query_one("#sw-sudo", Switch).value,
        "interactive_only": screen.query_one("#sw-interactive", Switch).value,
    }


class SettingsScreen(ModalScreen[str | None]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("ctrl+s", "save", "Save", show=True),
    ]

    def __init__(self, engine: Engine) -> None:
        super().__init__()
        self.engine = engine

    def compose(self) -> ComposeResult:
        values = values_from_engine(self.engine)
        role = "Dashboard (agents connect here)" if self.engine.receiver else "This host can report out"
        with Vertical(id="settings-box"):
            yield Label("SETTINGS", id="settings-title")
            yield Static(role, id="settings-role")
            with VerticalScroll(id="settings-form"):
                yield Label("LINK  —  where status is sent or received", classes="section-title")
                yield from _row(
                    "Report to",
                    Input(
                        value=str(values["server"]),
                        placeholder="YOUR_PC_IP:8765",
                        id="in-target",
                    ),
                    "Dashboard address this host should connect to",
                )
                yield from _row(
                    "Listen on",
                    Input(value=str(values["bind"]), placeholder="0.0.0.0:8765", id="in-bind"),
                    "Address the dashboard binds when you run listen",
                )
                with Horizontal(classes="field"):
                    yield Label("Shared token", classes="field-label")
                    yield Input(
                        value=str(values["token"]),
                        placeholder="same token on both sides",
                        id="in-token",
                    )
                    yield Button("Generate", id="gen-token", variant="default")
                yield Label("Both the server agent and this dashboard must match", classes="field-hint")
                yield from _row(
                    "Retry seconds",
                    Input(
                        value=str(values["reconnect_sec"]),
                        type="integer",
                        id="in-reconnect",
                    ),
                    "How long the agent waits before reconnecting",
                )

                yield Label("ALERTS  —  when to raise a warning", classes="section-title")
                with Horizontal(classes="field"):
                    yield Label("Failed logins", classes="field-label")
                    yield Input(
                        value=str(values["failed_login_threshold"]),
                        type="integer",
                        id="in-fail-count",
                    )
                    yield Label("in", classes="inline-label")
                    yield Input(
                        value=str(values["failed_login_window_sec"]),
                        type="integer",
                        id="in-fail-window",
                    )
                    yield Label("seconds", classes="inline-label")
                yield Label("Burst of failed/invalid SSH attempts from one IP", classes="field-hint")
                with Horizontal(classes="field"):
                    yield Label("Off-hours", classes="field-label")
                    yield Input(
                        value=str(values["off_hours_start"]),
                        type="integer",
                        id="in-off-start",
                    )
                    yield Label("to", classes="inline-label")
                    yield Input(
                        value=str(values["off_hours_end"]),
                        type="integer",
                        id="in-off-end",
                    )
                    yield Label("(24h)", classes="inline-label")
                yield Label("Accepted logins in this window also raise an alert", classes="field-hint")
                with Horizontal(classes="switch-row"):
                    yield Label("Root SSH", classes="switch-label")
                    yield Switch(value=values["always_alert_root_login"], id="sw-root")
                    yield Label("New source IP", classes="switch-label")
                    yield Switch(value=values["new_source_ip"], id="sw-new-ip")
                    yield Label("sudo/su shell", classes="switch-label")
                    yield Switch(value=values["alert_sudo_shell"], id="sw-sudo")
                with Horizontal(classes="switch-row"):
                    yield Label("Terminal commands only", classes="switch-label")
                    yield Switch(value=values["interactive_only"], id="sw-interactive")
                yield Label(
                    "On: only shells, sudo, and commands with a tty. Off: every process exec.",
                    classes="field-hint",
                )
            yield Static("", id="settings-status")
            with Horizontal(id="settings-actions"):
                yield Button("Save & apply", id="save", variant="primary")
                yield Button("Copy server command", id="copy-agent")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
        elif event.button.id == "gen-token":
            self.query_one("#in-token", Input).value = secrets.token_urlsafe(24)
            self._status("New token generated — save to use it on the other side too")
        elif event.button.id == "copy-agent":
            from watchdogs.pair import agent_command, local_addresses

            token = self.query_one("#in-token", Input).value.strip()
            bind = self.query_one("#in-bind", Input).value.strip() or "0.0.0.0:8765"
            target = self.query_one("#in-target", Input).value.strip()
            if not target:
                host = (local_addresses() or ["YOUR_PC_IP"])[0]
                port = bind.rsplit(":", 1)[-1]
                target = f"{host}:{port}"
            if not token:
                self._status("Set a shared token first")
                return
            cmd = agent_command(target, token)
            self.app.copy_to_clipboard(cmd)
            self._status(f"Copied: {cmd}")
        elif event.button.id == "save":
            self.action_save()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        try:
            values = parse_form(self)
            message = self.engine.apply_settings(values)
        except ValueError as exc:
            self._status(str(exc))
            return
        except Exception as exc:
            self._status(f"Could not save: {exc}")
            return
        self.dismiss(message)

    def _status(self, text: str) -> None:
        self.query_one("#settings-status", Static).update(text)


def _row(label: str, widget: Input, hint: str) -> list:
    return [
        Horizontal(Label(label, classes="field-label"), widget, classes="field"),
        Label(hint, classes="field-hint"),
    ]
