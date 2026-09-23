"""Alert rules for irregular logins and suspicious executed commands."""

from __future__ import annotations

import re
from collections import deque
from datetime import datetime, timedelta
from typing import Any

from watchdogs.models import Alert, CommandEvent, LoginEvent
from watchdogs.store import Store

_SHELL_NAMES = {
    "bash",
    "sh",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "sudo",
    "su",
}


def _basename(command: str) -> str:
    token = command.strip().split()[0] if command.strip() else ""
    return token.rsplit("/", 1)[-1]


class RuleEngine:
    def __init__(self, cfg: dict[str, Any], store: Store) -> None:
        alerts = cfg.get("alerts", {})
        self.store = store
        self.failed_threshold = int(alerts.get("failed_login_threshold", 5))
        self.failed_window = timedelta(seconds=int(alerts.get("failed_login_window_sec", 300)))
        self.alert_root = bool(alerts.get("always_alert_root_login", True))
        self.alert_new_ip = bool(alerts.get("new_source_ip", True))
        self.alert_sudo_shell = bool(alerts.get("alert_sudo_shell", True))
        off = alerts.get("off_hours") or {}
        self.off_start = int(off.get("start", 0))
        self.off_end = int(off.get("end", 6))
        self._fails: deque[tuple[datetime, str, str]] = deque()
        self._patterns: list[tuple[re.Pattern[str], dict[str, Any]]] = []
        for item in cfg.get("suspicious_commands") or []:
            try:
                compiled = re.compile(item["pattern"])
            except (KeyError, re.error):
                continue
            self._patterns.append((compiled, item))

    def reload(self, cfg: dict[str, Any]) -> None:
        kept = list(self._fails)
        self.__init__(cfg, self.store)
        self._fails.extend(kept)

    def evaluate(self, kind: str, payload: object) -> list[Alert]:
        if kind == "login" and isinstance(payload, LoginEvent):
            return self._login_alerts(payload)
        if kind == "command" and isinstance(payload, CommandEvent):
            return self._command_alerts(payload)
        return []

    def _login_alerts(self, event: LoginEvent) -> list[Alert]:
        alerts: list[Alert] = []
        if event.result in {"failed", "invalid"}:
            alerts.extend(self._failed_and_invalid(event))
        if event.result == "accepted":
            alerts.extend(self._accepted(event))
        if event.result in {"sudo", "su"}:
            alerts.extend(self._priv_shell(event))
        return alerts

    def _failed_and_invalid(self, event: LoginEvent) -> list[Alert]:
        alerts: list[Alert] = []
        if event.result == "invalid":
            alerts.append(
                Alert(
                    ts=event.ts,
                    severity="high",
                    rule="invalid_user",
                    message=f"Invalid user {event.username!r} from {event.source_ip or 'unknown'}",
                    context=event.to_dict(),
                )
            )
        self._fails.append((event.ts, event.source_ip, event.username))
        cutoff = event.ts - self.failed_window
        while self._fails and self._fails[0][0] < cutoff:
            self._fails.popleft()
        from_ip = [item for item in self._fails if item[1] and item[1] == event.source_ip]
        if event.source_ip and len(from_ip) >= self.failed_threshold:
            alerts.append(
                Alert(
                    ts=event.ts,
                    severity="high",
                    rule="failed_login_burst",
                    message=(
                        f"{len(from_ip)} failed/invalid SSH attempts from "
                        f"{event.source_ip} in {int(self.failed_window.total_seconds())}s"
                    ),
                    context={"ip": event.source_ip, "count": len(from_ip)},
                )
            )
        return alerts

    def _accepted(self, event: LoginEvent) -> list[Alert]:
        alerts: list[Alert] = []
        if self.alert_root and event.username == "root" and event.service == "sshd":
            alerts.append(
                Alert(
                    ts=event.ts,
                    severity="critical",
                    rule="root_ssh",
                    message=f"Root SSH login from {event.source_ip or 'unknown'} ({event.method})",
                    context=event.to_dict(),
                )
            )
        if self.alert_new_ip and event.source_ip:
            if self.store.note_source(event.username, event.source_ip, event.ts):
                alerts.append(
                    Alert(
                        ts=event.ts,
                        severity="medium",
                        rule="new_source_ip",
                        message=f"First-seen source {event.source_ip} for {event.username}",
                        context=event.to_dict(),
                    )
                )
        if self._is_off_hours(event.ts):
            alerts.append(
                Alert(
                    ts=event.ts,
                    severity="medium",
                    rule="off_hours_login",
                    message=(
                        f"Login for {event.username} at {event.ts.strftime('%H:%M')} "
                        f"(off-hours {self.off_start:02d}:00–{self.off_end:02d}:00)"
                    ),
                    context=event.to_dict(),
                )
            )
        return alerts

    def _priv_shell(self, event: LoginEvent) -> list[Alert]:
        if not self.alert_sudo_shell:
            return []
        target = str(event.extra.get("target") or "")
        command = str(event.extra.get("command") or "")
        if event.result == "su" and target == "root":
            return [
                Alert(
                    ts=event.ts,
                    severity="medium",
                    rule="su_root",
                    message=f"{event.username} used su to root on {event.tty or 'unknown tty'}",
                    context=event.to_dict(),
                )
            ]
        if event.result == "sudo" and target == "root" and _basename(command) in _SHELL_NAMES:
            return [
                Alert(
                    ts=event.ts,
                    severity="medium",
                    rule="sudo_shell",
                    message=f"{event.username} sudo shell as root: {command}",
                    context=event.to_dict(),
                )
            ]
        return []

    def _command_alerts(self, event: CommandEvent) -> list[Alert]:
        alerts: list[Alert] = []
        line = event.cmdline
        for pattern, spec in self._patterns:
            if pattern.search(line):
                alerts.append(
                    Alert(
                        ts=event.ts,
                        severity=str(spec.get("severity") or "medium"),
                        rule="suspicious_command",
                        message=f"{spec.get('reason', 'suspicious command')}: {line}",
                        context=event.to_dict(),
                    )
                )
        return alerts

    def _is_off_hours(self, ts: datetime) -> bool:
        hour = ts.hour
        start, end = self.off_start, self.off_end
        if start == end:
            return False
        if start < end:
            return start <= hour < end
        return hour >= start or hour < end
