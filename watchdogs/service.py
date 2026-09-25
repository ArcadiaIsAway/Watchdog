"""Keep the server agent alive after the SSH/TUI session ends."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

UNIT_NAME = "watchdogs.service"
UNIT_PATH = Path("/etc/systemd/system/watchdogs.service")


def _pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _pidfile(data_dir: Path) -> Path:
    return Path(data_dir) / "agent.pid"


def _read_pid(data_dir: Path) -> int | None:
    path = _pidfile(data_dir)
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if _pid_running(pid):
        return pid
    return None


def _write_pid(data_dir: Path, pid: int) -> None:
    path = _pidfile(data_dir)
    try:
        path.write_text(str(pid), encoding="utf-8")
    except OSError:
        pass


def _agent_argv(config_path: str) -> list[str]:
    return [sys.executable, "-m", "watchdogs", "--headless", "-c", str(config_path)]


def _systemd_available() -> bool:
    return os.path.isdir("/run/systemd/system") and shutil_which("systemctl") is not None


def shutil_which(name: str) -> str | None:
    from shutil import which

    return which(name)


def _install_systemd(config_path: str) -> bool:
    if not _systemd_available() or not (hasattr(os, "geteuid") and os.geteuid() == 0):
        return False
    python = os.path.realpath(sys.executable)
    config = str(Path(config_path).resolve())
    unit = f"""[Unit]
Description=WatchDogs host agent
After=network.target systemd-journald.service

[Service]
Type=simple
ExecStart={python} -m watchdogs --headless -c {config}
Restart=always
RestartSec=3
User=root
Nice=5
Environment=WATCHDOGS_AGENT=1

[Install]
WantedBy=multi-user.target
"""
    try:
        UNIT_PATH.write_text(unit, encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"], check=False, timeout=8)
        started = subprocess.run(
            ["systemctl", "enable", "--now", UNIT_NAME],
            check=False,
            timeout=12,
            capture_output=True,
            text=True,
        )
        return started.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _spawn_detached(config_path: str, data_dir: Path) -> int:
    log = Path(data_dir) / "agent.stdout"
    log.parent.mkdir(parents=True, exist_ok=True)
    handle = log.open("a", encoding="utf-8")
    env = os.environ.copy()
    env["WATCHDOGS_AGENT"] = "1"
    proc = subprocess.Popen(
        _agent_argv(config_path),
        stdin=subprocess.DEVNULL,
        stdout=handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        cwd=str(Path(data_dir)),
        env=env,
        close_fds=True,
    )
    _write_pid(data_dir, proc.pid)
    return proc.pid


def ensure_background_agent(config_path: str | None, data_dir: Path) -> str | None:
    """Start a detached headless agent if this process is the interactive one."""
    if os.environ.get("WATCHDOGS_AGENT"):
        return None
    if not config_path:
        return None
    existing = _read_pid(data_dir)
    if existing and existing != os.getpid():
        return f"already running (pid {existing})"
    if _install_systemd(config_path):
        return "systemd service watchdogs.service"
    pid = _spawn_detached(config_path, data_dir)
    return f"background pid {pid}"
