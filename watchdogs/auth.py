"""Parse and tail auth logs / journald for logins and sudo."""

from __future__ import annotations

import os
import re
import select
import shutil
import subprocess
import threading
from datetime import datetime
from typing import Callable

from watchdogs.models import CommandEvent, LoginEvent

EmitFn = Callable[[str, object], None]

_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|[\dT:+-]+)\s+"
    r"(?P<host>\S+)\s+(?P<msg>.*)$"
)
_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive(?:/pam)?|hostbased)"
    r" for (?P<user>\S+) from (?P<ip>\S+)"
)
_FAILED = re.compile(
    r"Failed (?P<method>password|publickey|none|keyboard-interactive(?:/pam)?)"
    r" for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
_SUDO = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)"
    r"\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)
_SU = re.compile(r"\(to (?P<target>\S+)\)\s+(?P<user>\S+)\s+on\s+(?P<tty>\S+)")
_SESSION_OPEN = re.compile(r"session opened for user (?P<user>\S+)")
_SESSION_CLOSE = re.compile(r"session closed for user (?P<user>\S+)")


def _strip_uid_suffix(username: str) -> str:
    return re.sub(r"\(uid=\d+\)$", "", username)


def _parse_timestamp(raw: str, now: datetime | None = None) -> datetime:
    now = now or datetime.now()
    raw = raw.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(raw, fmt)
            return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
        except ValueError:
            continue
    # journalctl short-iso sometimes drops the colon in the offset: -0300
    compact = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", raw)
    try:
        parsed = datetime.strptime(compact, "%Y-%m-%dT%H:%M:%S%z")
        return parsed.replace(tzinfo=None)
    except ValueError:
        pass
    try:
        parsed = datetime.strptime(f"{now.year} {raw}", "%Y %b %d %H:%M:%S")
        return parsed
    except ValueError:
        return now


def parse_auth_line(line: str, now: datetime | None = None) -> LoginEvent | None:
    """Turn one syslog/journal auth line into a LoginEvent, or None if unrelated."""
    now = now or datetime.now()
    text = line.rstrip("\n")
    if not text.strip():
        return None
    ts = now
    message = text
    match = _SYSLOG_RE.match(text)
    if match:
        ts = _parse_timestamp(match.group("ts"), now)
        message = match.group("msg")

    accepted = _ACCEPTED.search(message)
    if accepted:
        return LoginEvent(
            ts=ts,
            result="accepted",
            username=accepted.group("user"),
            source_ip=accepted.group("ip"),
            method=accepted.group("method"),
            service="sshd",
            raw=text,
        )

    failed = _FAILED.search(message)
    if failed:
        result = "invalid" if failed.group("invalid") else "failed"
        return LoginEvent(
            ts=ts,
            result=result,
            username=failed.group("user"),
            source_ip=failed.group("ip"),
            method=failed.group("method"),
            service="sshd",
            raw=text,
        )

    invalid = _INVALID.search(message)
    if invalid:
        return LoginEvent(
            ts=ts,
            result="invalid",
            username=invalid.group("user"),
            source_ip=invalid.group("ip"),
            method="",
            service="sshd",
            raw=text,
        )

    sudo = _SUDO.search(message)
    if sudo:
        return LoginEvent(
            ts=ts,
            result="sudo",
            username=sudo.group("user"),
            method="sudo",
            service="sudo",
            tty=sudo.group("tty"),
            raw=text,
            extra={
                "target": sudo.group("target"),
                "pwd": sudo.group("pwd"),
                "command": sudo.group("cmd").strip(),
            },
        )

    su = _SU.search(message)
    if su:
        return LoginEvent(
            ts=ts,
            result="su",
            username=su.group("user"),
            method="su",
            service="su",
            tty=su.group("tty"),
            raw=text,
            extra={"target": su.group("target")},
        )

    opened = _SESSION_OPEN.search(message)
    if opened:
        return LoginEvent(
            ts=ts,
            result="session_open",
            username=_strip_uid_suffix(opened.group("user")),
            service="pam",
            raw=text,
        )

    closed = _SESSION_CLOSE.search(message)
    if closed:
        return LoginEvent(
            ts=ts,
            result="session_close",
            username=_strip_uid_suffix(closed.group("user")),
            service="pam",
            raw=text,
        )

    return None


def sudo_command_event(login: LoginEvent) -> CommandEvent | None:
    cmd = str(login.extra.get("command") or "").strip()
    if login.result != "sudo" or not cmd:
        return None
    return CommandEvent(
        ts=login.ts,
        pid=0,
        ppid=0,
        uid=0,
        username=login.username,
        cmdline=cmd,
        exe="",
        tty=login.tty,
        source="sudo",
    )


def _tail_file(path: str, stop: threading.Event, on_line: Callable[[str], None]) -> None:
    handle = None
    inode: int | None = None
    seek_end = True
    while not stop.is_set():
        if not os.path.exists(path):
            stop.wait(1.0)
            continue
        try:
            stat = os.stat(path)
        except OSError:
            stop.wait(0.5)
            continue
        if handle is None or stat.st_ino != inode:
            if handle is not None:
                leftover = handle.read()
                for part in leftover.splitlines():
                    on_line(part)
                handle.close()
            try:
                handle = open(path, "r", errors="replace")
            except OSError:
                stop.wait(1.0)
                continue
            inode = stat.st_ino
            if seek_end:
                handle.seek(0, os.SEEK_END)
                seek_end = False
        line = handle.readline()
        if line:
            on_line(line.rstrip("\n"))
            continue
        try:
            size = os.stat(path).st_size
        except OSError:
            handle.close()
            handle = None
            inode = None
            continue
        if handle.tell() > size:
            handle.seek(0)
        else:
            stop.wait(0.2)
    if handle is not None:
        handle.close()


def _follow_journal(stop: threading.Event, on_line: Callable[[str], None]) -> None:
    if not shutil.which("journalctl"):
        return
    cmd = [
        "journalctl",
        "-f",
        "-n",
        "0",
        "-o",
        "short-iso",
        "SYSLOG_FACILITY=4",
        "SYSLOG_FACILITY=10",
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except OSError:
        return
    try:
        assert proc.stdout is not None
        while not stop.is_set():
            ready, _, _ = select.select([proc.stdout], [], [], 0.5)
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            line = proc.stdout.readline()
            if not line:
                break
            on_line(line.rstrip("\n"))
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


class AuthCollector:
    def __init__(self, emit: EmitFn, paths: list[str], use_journal: bool = True) -> None:
        self.emit = emit
        self.paths = paths
        self.use_journal = use_journal

    def _handle_line(self, line: str) -> None:
        event = parse_auth_line(line)
        if event is None:
            return
        self.emit("login", event)
        command = sudo_command_event(event)
        if command is not None:
            self.emit("command", command)

    def run(self, stop: threading.Event) -> None:
        threads: list[threading.Thread] = []
        for path in self.paths:
            thread = threading.Thread(
                target=_tail_file,
                args=(path, stop, self._handle_line),
                name=f"auth-tail-{os.path.basename(path)}",
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        if self.use_journal:
            thread = threading.Thread(
                target=_follow_journal,
                args=(stop, self._handle_line),
                name="auth-journal",
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
