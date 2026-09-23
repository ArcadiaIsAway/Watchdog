"""Poll `who` for active login sessions."""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
from typing import Callable

from watchdogs.models import Session

log = logging.getLogger("watchdogs.sessions")

EmitFn = Callable[[str, object], None]


def parse_who_line(line: str) -> Session | None:
    parts = line.split()
    if len(parts) < 3:
        return None
    username = parts[0]
    tty = parts[1]
    source = ""
    since = " ".join(parts[2:])
    if parts[-1].startswith("(") and parts[-1].endswith(")"):
        source = parts[-1][1:-1]
        since = " ".join(parts[2:-1])
    return Session(username=username, tty=tty, source=source, since=since)


def list_sessions() -> list[Session]:
    if not shutil.which("who"):
        return []
    try:
        out = subprocess.check_output(["who"], text=True, errors="replace")
    except (OSError, subprocess.CalledProcessError) as exc:
        log.debug("who failed: %s", exc)
        return []
    sessions: list[Session] = []
    for line in out.splitlines():
        session = parse_who_line(line)
        if session is not None:
            sessions.append(session)
    return sessions


class SessionCollector:
    def __init__(self, emit: EmitFn, interval: float = 2.0) -> None:
        self.emit = emit
        self.interval = max(0.5, float(interval))

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.emit("sessions", list_sessions())
            stop.wait(self.interval)
