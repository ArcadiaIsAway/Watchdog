"""Live Textual dashboard for sessions, logins, commands, and alerts."""

from __future__ import annotations

import socket
from datetime import datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Label, OptionList, RichLog, Static
from textual.widgets.option_list import Option

from watchdogs.engine import Engine
from watchdogs.models import Alert, CommandEvent, LoginEvent, Session

CSS_PATH = Path(__file__).with_name("tui.tcss")

_SEV_COLOR = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "yellow",
    "low": "cyan",
}

_LOGIN_COLOR = {
    "accepted": "green",
    "failed": "red",
    "invalid": "red",
    "sudo": "yellow",
    "su": "yellow",
    "session_open": "cyan",
    "session_close": "dim",
}


def _host() -> str:
    return socket.gethostname()


class WatchDogsApp(App[None]):
    TITLE = "WATCH·DOGS"
    CSS_PATH = CSS_PATH
    ALLOW_SELECT = True
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "open_settings", "Settings"),
        Binding("j", "open_connect", "Connect"),
        Binding("a", "focus_alerts", "Alerts"),
        Binding("c", "focus_commands", "Commands"),
        Binding("p", "toggle_follow", "Pause"),
        Binding("y", "copy_command", "Copy row"),
        Binding("Y", "copy_all_commands", "Copy all"),
        Binding("space", "ack_alert", "Ack"),
    ]

    def __init__(self, engine: Engine, *, prompt_connect: bool | None = None) -> None:
        super().__init__()
        self.engine = engine
        self._prompt_connect = prompt_connect
        self._sessions: list[Session] = []
        self._follow_commands = True
        self._held_commands: list[CommandEvent] = []
        self._command_keys: list[str] = []
        self._command_seq = 0

    def compose(self) -> ComposeResult:
        yield Static(self._header_text(), id="header-bar")
        with Horizontal(id="top"):
            with Vertical(id="sessions-panel", classes="panel"):
                yield Label("ACTIVE SESSIONS", classes="panel-title")
                yield Static("waiting…", id="sessions")
            with Vertical(id="alerts-panel", classes="panel"):
                yield Label("ALERTS", classes="panel-title")
                yield OptionList(id="alerts")
        with Vertical(id="logins-panel", classes="panel"):
            yield Label("LOGINS", classes="panel-title")
            yield RichLog(id="logins", highlight=False, markup=True, max_lines=400, wrap=True)
        with Vertical(id="commands-panel", classes="panel"):
            yield Label("COMMANDS  ·  live  ·  y copy row  ·  Y copy all", id="commands-title", classes="panel-title")
            yield DataTable(id="commands", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self.engine.add_listener(self._on_engine_event)
        self.set_interval(1.0, self._tick_clock)
        if self.engine.receiver or self.engine.link_role == "dashboard":
            mode = "DASHBOARD"
        elif self.engine.link_role == "agent":
            mode = "SERVER"
        elif self.engine.demo:
            mode = "DEMO"
        else:
            mode = "LIVE"
        self.sub_title = f"{mode}  {_host()}"
        table = self.query_one("#commands", DataTable)
        table.add_columns("Time", "User", "Tty", "Pid", "Command")
        self._refresh_command_title()
        should_prompt = self._prompt_connect
        if should_prompt is None:
            should_prompt = self.engine.link_role not in {"dashboard", "agent", "local"}
        if should_prompt:
            self.call_after_refresh(self.action_open_connect)

    def _on_engine_event(self, kind: str, payload: object) -> None:
        try:
            self.call_from_thread(self._apply, kind, payload)
        except RuntimeError:
            self._apply(kind, payload)

    def _apply(self, kind: str, payload: object) -> None:
        if kind == "login" and isinstance(payload, LoginEvent):
            self.query_one("#logins", RichLog).write(self._login_line(payload))
        elif kind == "command" and isinstance(payload, CommandEvent):
            if self._follow_commands:
                self._append_command(payload)
            else:
                self._held_commands.append(payload)
                self._refresh_command_title()
        elif kind == "alert" and isinstance(payload, Alert):
            color = _SEV_COLOR.get(payload.severity, "white")
            stamp = payload.ts.strftime("%H:%M:%S")
            label = f"[{color}]{payload.severity.upper():<8}[/{color}] {stamp}  {payload.message}"
            option_id = str(payload.id) if payload.id is not None else f"tmp-{id(payload)}"
            self.query_one("#alerts", OptionList).add_option(Option(label, id=option_id))
        elif kind == "sessions" and isinstance(payload, list):
            self._sessions = [item for item in payload if isinstance(item, Session)]
            self._render_sessions()
        self._refresh_header()

    def _render_sessions(self) -> None:
        if not self._sessions:
            text = "[dim]no sessions[/dim]"
        else:
            lines = []
            for session in self._sessions:
                src = session.source or "local"
                lines.append(f"{session.username:<12} {session.tty:<8} {src:<18} {session.since}")
            text = "\n".join(lines)
        self.query_one("#sessions", Static).update(text)

    def _refresh_header(self) -> None:
        self.query_one("#header-bar", Static).update(self._header_text())

    def _header_text(self) -> str:
        if self.engine.receiver or self.engine.link_role == "dashboard":
            mode = "DASHBOARD"
        elif self.engine.link_role == "agent":
            mode = "SERVER"
        elif self.engine.demo:
            mode = "DEMO"
        else:
            mode = "LIVE"
        priv = "root" if self.engine.demo is False and not self.engine.receiver else "unprivileged"
        try:
            import os

            priv = "root" if os.geteuid() == 0 else "unprivileged"
        except AttributeError:
            pass
        now = datetime.now().strftime("%H:%M:%S")
        if self.engine.link_role == "dashboard" or self.engine.receiver:
            link = self.engine.link_status.upper()
            remote = self.engine.remote_host or "waiting"
            code = self.engine.join_code or "----"
            identity = f"JOIN {code}     remote={remote}     LINK {link}"
            note = "On the server: sudo .venv/bin/python -m watchdogs → This is the server  ·  press j"
        elif self.engine.link_role == "agent":
            identity = f"{_host()}     {priv}     JOIN {self.engine.join_code or '----'}"
            note = "Sending logins and commands to the dashboard  ·  press j to change connection"
        else:
            identity = f"{_host()}     {priv}"
            note = "Captures logins and executed commands  ·  press j to connect both machines"
        return (
            f"WATCH·DOGS  // HOST MONITOR     {mode}     {identity}     {now}\n"
            f"SESSIONS {len(self._sessions)}    "
            f"LOGINS {self.engine.login_count}    "
            f"COMMANDS {self.engine.command_count}    "
            f"ALERTS {self.engine.alert_count}\n"
            f"{note}"
        )

    def _tick_clock(self) -> None:
        self._refresh_header()

    def action_open_settings(self) -> None:
        from watchdogs.settings import SettingsScreen

        def _done(message: str | None) -> None:
            if message == "__connect__":
                self.action_open_connect()
                return
            if message:
                self.notify(message, title="Settings", timeout=8)
                self._refresh_header()

        self.push_screen(SettingsScreen(self.engine), _done)

    def action_open_connect(self) -> None:
        from watchdogs.connect import ConnectScreen

        def _done(message: str | None) -> None:
            if message == "__background__":
                self.notify("Agent will keep running after you disconnect", title="Connect", timeout=6)
                self.exit()
                return
            if message:
                self.notify(message, title="Connect", timeout=8)
            self._refresh_header()
            if self.engine.link_role == "dashboard":
                self.sub_title = f"DASHBOARD  {_host()}"
            elif self.engine.link_role == "agent":
                self.sub_title = f"SERVER  {_host()}"

        self.push_screen(ConnectScreen(self.engine), _done)

    def _append_command(self, event: CommandEvent) -> None:
        table = self.query_one("#commands", DataTable)
        self._command_seq += 1
        key = f"cmd-{self._command_seq}"
        origin = {
            "sudo": "sudo",
            "shell": "typed",
            "demo": "demo",
        }.get(event.source, str(event.pid or ""))
        table.add_row(
            event.ts.strftime("%H:%M:%S"),
            event.username,
            event.tty or "",
            origin,
            event.cmdline,
            key=key,
        )
        self._command_keys.append(key)
        while len(self._command_keys) > 400:
            old = self._command_keys.pop(0)
            try:
                table.remove_row(old)
            except Exception:
                pass
        if self._follow_commands:
            table.move_cursor(row=table.row_count - 1)
            table.scroll_end(animate=False)
        self._refresh_command_title()

    def _refresh_command_title(self) -> None:
        title = self.query_one("#commands-title", Label)
        if self._follow_commands:
            title.update("COMMANDS  ·  live  ·  y copy row  ·  Y copy all")
        else:
            held = len(self._held_commands)
            title.update(f"COMMANDS  ·  paused  ·  {held} held  ·  p resume  ·  y copy")

    def _set_follow(self, follow: bool) -> None:
        self._follow_commands = follow
        if follow and self._held_commands:
            pending = list(self._held_commands)
            self._held_commands.clear()
            for event in pending:
                self._append_command(event)
        self._refresh_command_title()

    def action_toggle_follow(self) -> None:
        self._set_follow(not self._follow_commands)
        if self._follow_commands:
            table = self.query_one("#commands", DataTable)
            if table.row_count:
                table.move_cursor(row=table.row_count - 1)
                table.scroll_end(animate=False)

    def action_focus_commands(self) -> None:
        self.query_one("#commands", DataTable).focus()

    def selected_command_text(self) -> str:
        table = self.query_one("#commands", DataTable)
        if table.row_count == 0:
            return ""
        try:
            row = table.get_row_at(table.cursor_row)
        except Exception:
            return ""
        return str(row[-1]) if row else ""

    def all_commands_text(self) -> str:
        table = self.query_one("#commands", DataTable)
        lines: list[str] = []
        for index in range(table.row_count):
            try:
                row = table.get_row_at(index)
            except Exception:
                continue
            time_s, user, tty, pid, cmd = (str(row[i]) if i < len(row) else "" for i in range(5))
            lines.append(f"{time_s}\t{user}\t{tty}\t{pid}\t{cmd}")
        return "\n".join(lines)

    def _copy_text(self, text: str, what: str) -> None:
        if not text:
            self.notify("Nothing to copy", timeout=2)
            return
        self.copy_to_clipboard(text)
        preview = text.splitlines()[0]
        if len(preview) > 80:
            preview = preview[:77] + "..."
        extra = f" ({len(text.splitlines())} lines)" if "\n" in text else ""
        self.notify(f"Copied {what}{extra}: {preview}", timeout=3)

    def action_copy_command(self) -> None:
        self._copy_text(self.selected_command_text(), "command")

    def action_copy_all_commands(self) -> None:
        self._copy_text(self.all_commands_text(), "command list")

    def action_focus_alerts(self) -> None:
        self.query_one("#alerts", OptionList).focus()

    def action_ack_alert(self) -> None:
        widget = self.query_one("#alerts", OptionList)
        option_id = widget.highlighted
        if option_id is None:
            return
        try:
            highlighted = widget.get_option_at_index(option_id)
        except Exception:
            return
        raw_id = highlighted.id
        if raw_id and raw_id.isdigit():
            self.engine.ack(int(raw_id))
        prompt = str(highlighted.prompt)
        if not prompt.startswith("ACK "):
            widget.replace_option_prompt_at_index(option_id, f"ACK {prompt}")

    @staticmethod
    def _login_line(event: LoginEvent) -> str:
        color = _LOGIN_COLOR.get(event.result, "white")
        stamp = event.ts.strftime("%H:%M:%S")
        extra = event.source_ip or event.extra.get("command") or event.tty or ""
        return (
            f"{stamp}  [{color}]{event.result.upper():<12}[/{color}] "
            f"{event.username:<12} {event.service:<5} {extra}"
        )

    @staticmethod
    def _command_line(event: CommandEvent) -> str:
        stamp = event.ts.strftime("%H:%M:%S")
        tag = "sudo" if event.source == "sudo" else f"{event.pid}"
        return f"{stamp}  {event.username:<12} {tag:<8} {event.cmdline}"
