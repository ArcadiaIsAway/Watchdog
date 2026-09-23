"""Process-exec collector: netlink PROC_EVENT_EXEC with /proc scan fallback."""

from __future__ import annotations

import ctypes
import logging
import os
import pwd
import socket
import struct
import threading
from datetime import datetime
from typing import Callable

from watchdogs.models import CommandEvent

log = logging.getLogger("watchdogs.procs")

_SELF_PID = os.getpid()
_SELF_PGRP = os.getpgrp()
_SELF_MARKERS = ("watchdogs", "python -m watchdogs", "-m watchdogs")

EmitFn = Callable[[str, object], None]

NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
CN_VAL_PROC = 1
NLMSG_DONE = 3
PROC_CN_MCAST_LISTEN = 1
PROC_EVENT_EXEC = 0x00000002


class CnMsg(ctypes.Structure):
    _fields_ = [
        ("idx", ctypes.c_uint32),
        ("val", ctypes.c_uint32),
        ("seq", ctypes.c_uint32),
        ("ack", ctypes.c_uint32),
        ("len", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
    ]


class ProcEvent(ctypes.Structure):
    _fields_ = [
        ("what", ctypes.c_uint32),
        ("cpu", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("process_pid", ctypes.c_int32),
        ("process_tgid", ctypes.c_int32),
    ]


def username_for(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def read_proc(pid: int, source: str = "exec") -> CommandEvent | None:
    base = f"/proc/{pid}"
    try:
        raw_cmd = open(f"{base}/cmdline", "rb").read()
    except OSError:
        return None
    cmdline = raw_cmd.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    if not cmdline:
        try:
            comm = open(f"{base}/comm", "r", errors="replace").read().strip()
        except OSError:
            return None
        if not comm:
            return None
        cmdline = f"[{comm}]"
    uid = 0
    ppid = 0
    try:
        for line in open(f"{base}/status", "r", errors="replace"):
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
            elif line.startswith("PPid:"):
                ppid = int(line.split()[1])
    except OSError:
        return None
    exe = ""
    try:
        exe = os.readlink(f"{base}/exe")
    except OSError:
        pass
    tty = process_tty(pid)
    if not tty and _is_shell(ppid):
        tty = process_tty(ppid)
    return CommandEvent(
        ts=datetime.now(),
        pid=pid,
        ppid=ppid,
        uid=uid,
        username=username_for(uid),
        cmdline=cmdline,
        exe=exe,
        tty=tty,
        source=source,
    )


def _read_ppid(pid: int) -> int | None:
    try:
        for line in open(f"/proc/{pid}/status", "r", errors="replace"):
            if line.startswith("PPid:"):
                return int(line.split()[1])
    except (OSError, IndexError, ValueError):
        return None
    return None


def _read_pgrp(pid: int) -> int | None:
    try:
        stat = open(f"/proc/{pid}/stat", "r", errors="replace").read()
        close = stat.rfind(")")
        fields = stat[close + 2 :].split()
        return int(fields[2])
    except (OSError, IndexError, ValueError):
        return None


def _ancestor_is_self(pid: int) -> bool:
    seen: set[int] = set()
    current = pid
    while current > 1 and current not in seen:
        if current == _SELF_PID:
            return True
        seen.add(current)
        parent = _read_ppid(current)
        if parent is None:
            return False
        current = parent
    return False


_PTS_MAJOR = 136
_SHELLS = {
    "bash",
    "zsh",
    "fish",
    "sh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "sudo",
    "su",
    "sshd",
    "login",
    "tmux",
    "screen",
}
_NOISE_PREFIXES = (
    "/usr/lib/systemd",
    "/usr/lib/upower",
    "/usr/libexec/",
    "/usr/share/cursor",
    "/usr/share/code",
    "/opt/google/chrome",
    "/usr/bin/starship",
    "(sd-pam)",
)
_PROMPT_MARKERS = (
    "starship",
    "oh-my-posh",
    "powerline",
    "gitstatusd",
    "direnv export",
)
_NOISE_NAMES = {
    "systemd",
    "dbus-daemon",
    "dbus-broker",
    "pipewire",
    "wireplumber",
    "pulseaudio",
    "xdg-desktop-portal",
    "gsd-",
    "chrome",
    "chromium",
    "chrome_crashpad",
    "firefox",
    "electron",
    "cursor",
    "code",
    "slack",
    "discord",
    "gnome-shell",
    "xorg",
    "xwayland",
    "kwin",
    "plasmashell",
    "starship",
}


def _tty_from_stat(pid: int) -> str:
    try:
        stat = open(f"/proc/{pid}/stat", "r", errors="replace").read()
        close = stat.rfind(")")
        tty_nr = int(stat[close + 2 :].split()[4])
    except (OSError, IndexError, ValueError):
        return ""
    if not tty_nr:
        return ""
    major = (tty_nr >> 8) & 0xFFF
    minor = tty_nr & 0xFF
    if major == _PTS_MAJOR:
        return f"pts/{minor}"
    return ""


def _tty_from_fd(pid: int) -> str:
    for fd in ("0", "1"):
        try:
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if target.startswith("/dev/pts/"):
            return target[5:]
    return ""


def is_user_tty(name: str) -> bool:
    return bool(name) and name.startswith("pts/")


def process_tty(pid: int) -> str:
    if pid <= 0:
        return ""
    name = _tty_from_fd(pid) or _tty_from_stat(pid)
    return name if is_user_tty(name) else ""


def controlling_tty(pid: int) -> str:
    """pts of this process only — do not inherit a session tty from desktop apps."""
    return process_tty(pid)


def _comm(pid: int) -> str:
    try:
        return open(f"/proc/{pid}/comm", "r", errors="replace").read().strip().lower()
    except OSError:
        return ""


def _is_shell(pid: int) -> bool:
    comm = _comm(pid)
    return comm in _SHELLS or comm.startswith("tmux") or comm.startswith("sshd")


def _looks_like_noise(event: CommandEvent) -> bool:
    line = (event.cmdline or "").strip()
    if line.startswith("[") and line.endswith("]"):
        return True
    lowered = line.lower()
    if any(marker in lowered for marker in _PROMPT_MARKERS):
        return True
    if any(lowered.startswith(prefix) for prefix in _NOISE_PREFIXES):
        return True
    comm = line.split()[0].rsplit("/", 1)[-1] if line else ""
    return any(comm.startswith(name) for name in _NOISE_NAMES)


def is_user_command(event: CommandEvent, interactive_only: bool = True) -> bool:
    """Keep commands from a real terminal or sudo; drop desktop/service churn."""
    if event.source in {"sudo", "demo", "shell"}:
        return True
    if _looks_like_noise(event):
        return False
    if not interactive_only:
        return True
    if is_user_tty(event.tty):
        return True
    if event.pid > 0 and is_user_tty(process_tty(event.pid)):
        return True
    if event.ppid > 1 and _is_shell(event.ppid) and is_user_tty(process_tty(event.ppid)):
        return True
    return False


def is_internal_command(event: CommandEvent) -> bool:
    """True for WatchDogs itself and the helpers it spawns (who, journalctl, …)."""
    if event.pid == _SELF_PID or event.ppid == _SELF_PID:
        return True
    if event.pid > 0 and _read_pgrp(event.pid) == _SELF_PGRP:
        return True
    if event.pid > 0 and _ancestor_is_self(event.pid):
        return True
    if event.ppid > 1 and _ancestor_is_self(event.ppid):
        return True
    blob = f"{event.cmdline} {event.exe}".lower()
    return any(marker in blob for marker in _SELF_MARKERS)


def _pid_starttime(pid: int) -> int | None:
    try:
        stat = open(f"/proc/{pid}/stat", "r", errors="replace").read()
        close = stat.rfind(")")
        fields = stat[close + 2 :].split()
        return int(fields[19])
    except (OSError, IndexError, ValueError):
        return None


def _listen_packet(pid: int) -> bytes:
    op = struct.pack("=I", PROC_CN_MCAST_LISTEN)
    cn = struct.pack("=IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(op), 0) + op
    nlh = struct.pack("=IHHII", 16 + len(cn), NLMSG_DONE, 0, 0, pid)
    return nlh + cn


def _parse_exec_pid(data: bytes) -> int | None:
    header = 16 + ctypes.sizeof(CnMsg)
    if len(data) < header + ctypes.sizeof(ProcEvent):
        return None
    try:
        event = ProcEvent.from_buffer_copy(data[header : header + ctypes.sizeof(ProcEvent)])
    except (ValueError, TypeError):
        return None
    if event.what != PROC_EVENT_EXEC:
        return None
    pid = int(event.process_pid or event.process_tgid)
    return pid if pid > 0 else None


def _open_netlink() -> socket.socket | None:
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        sock.bind((os.getpid(), CN_IDX_PROC))
        sock.send(_listen_packet(os.getpid()))
        sock.settimeout(1.0)
        return sock
    except OSError as exc:
        log.info("netlink process connector unavailable: %s", exc)
        return None


def _run_netlink(stop: threading.Event, emit: EmitFn) -> bool:
    sock = _open_netlink()
    if sock is None:
        return False
    log.info("watching process exec via netlink")
    try:
        while not stop.is_set():
            try:
                data = sock.recv(65535)
            except TimeoutError:
                continue
            except OSError:
                break
            pid = _parse_exec_pid(data)
            if pid is None:
                continue
            event = read_proc(pid, source="exec")
            if event is not None and not is_internal_command(event):
                emit("command", event)
    finally:
        sock.close()
    return True


def _scan_proc_snapshot() -> dict[int, int]:
    found: dict[int, int] = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return found
    for name in entries:
        if not name.isdigit():
            continue
        pid = int(name)
        start = _pid_starttime(pid)
        if start is not None:
            found[pid] = start
    return found


def _run_proc_scan(stop: threading.Event, emit: EmitFn) -> None:
    log.info("watching process exec via /proc scan")
    seen = _scan_proc_snapshot()
    while not stop.is_set():
        current = _scan_proc_snapshot()
        for pid, start in current.items():
            if seen.get(pid) != start:
                event = read_proc(pid, source="proc")
                if event is not None and not is_internal_command(event):
                    emit("command", event)
        seen = current
        stop.wait(0.4)


class ProcessCollector:
    def __init__(self, emit: EmitFn, prefer_netlink: bool = True) -> None:
        self.emit = emit
        self.prefer_netlink = prefer_netlink

    def run(self, stop: threading.Event) -> None:
        if self.prefer_netlink and _run_netlink(stop, self.emit):
            if not stop.is_set():
                _run_proc_scan(stop, self.emit)
            return
        _run_proc_scan(stop, self.emit)
