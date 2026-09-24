"""Make dashboard ↔ server pairing a single copy-paste (and optional SSH tunnel)."""

from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path

from watchdogs.config import save_config


def local_addresses() -> list[str]:
    found: list[str] = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("1.1.1.1", 80))
        found.append(sock.getsockname()[0])
        sock.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                found.append(ip)
    except OSError:
        pass
    unique: list[str] = []
    for ip in found:
        if ip not in unique and not ip.startswith("127."):
            unique.append(ip)
    return unique


def agent_command(report_to: str, token: str) -> str:
    return f"sudo python -m watchdogs --headless --report {report_to} --token {token}"


def pairing_card(token: str, port: int, *, via_ssh: str | None = None) -> str:
    addrs = local_addresses()
    primary = addrs[0] if addrs else "YOUR_PC_IP"
    lan_target = f"{primary}:{port}"
    lines = [
        "WatchDogs pairing",
        f"  Token     {token}",
        f"  Listen    0.0.0.0:{port}" if not via_ssh else f"  Listen    127.0.0.1:{port} (SSH tunnel)",
    ]
    if addrs:
        lines.append(f"  This PC   {', '.join(addrs)}")
    lines.append("")
    if via_ssh:
        lines.extend(
            [
                f"Tunnel: this PC ← {via_ssh}  (server uses 127.0.0.1:{port})",
                "On the server:",
                f"  {agent_command(f'127.0.0.1:{port}', token)}",
            ]
        )
    else:
        lines.extend(
            [
                "On the server (same network):",
                f"  {agent_command(lan_target, token)}",
                "",
                "If the server cannot reach this PC:",
                f"  python -m watchdogs pair --ssh user@SERVER --token {token}",
            ]
        )
    return "\n".join(lines)


def persist_pair(cfg: dict, token: str, bind: str, server: str | None = None) -> Path:
    report = cfg.setdefault("report", {})
    report["token"] = token
    report["bind"] = bind
    if server:
        report["server"] = server
    return save_config(cfg)


def write_pair_env(path: Path, token: str, report_to: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"WATCHDOGS_TOKEN={token}\nWATCHDOGS_REPORT={report_to}\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def start_reverse_tunnel(ssh_target: str, port: int) -> subprocess.Popen:
    """Server:port → this machine's dashboard. ssh can prompt for a password/key."""
    cmd = [
        "ssh",
        "-N",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-R",
        f"{port}:127.0.0.1:{port}",
        ssh_target,
    ]
    proc = subprocess.Popen(cmd)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(
                f"SSH tunnel to {ssh_target} failed (exit {proc.returncode}). "
                "Check the host, keys, and that RemoteForward is allowed."
            )
        time.sleep(0.2)
    return proc


def remote_start_agent(ssh_target: str, token: str, port: int) -> int:
    remote = agent_command(f"127.0.0.1:{port}", token)
    return subprocess.call(["ssh", "-t", ssh_target, remote])
