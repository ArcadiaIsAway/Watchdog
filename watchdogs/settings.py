"""In-dashboard form for alert thresholds."""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static, Switch

from watchdogs.engine import Engine


def values_from_engine(engine: Engine) -> dict[str, Any]:
    cfg = engine.cfg
    alerts = cfg.get("alerts") or {}
    off = alerts.get("off_hours") or {}
    return {
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
        role = {
            "dashboard": "This machine is the dashboard",
            "agent": "This machine reports to a dashboard",
            "local": "This machine only",
        }.get(self.engine.link_role, "Not connected yet — press j")
        with Vertical(id="settings-box"):
            yield Label("SETTINGS", id="settings-title")
            yield Static(role, id="settings-role")
            with VerticalScroll(id="settings-form"):
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
                yield Button("Change connection", id="change-link")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
        elif event.button.id == "change-link":
            self.dismiss("__connect__")
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
