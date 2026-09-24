"""Load defaults and optional YAML overlay."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "data_dir": None,
    "watch": {
        "auth_logs": ["/var/log/auth.log", "/var/log/secure"],
        "journal": True,
        "process_events": True,
        "session_poll_sec": 2.0,
        "interactive_only": True,
        "typed_commands": True,
    },
    "alerts": {
        "failed_login_threshold": 5,
        "failed_login_window_sec": 300,
        "always_alert_root_login": True,
        "new_source_ip": True,
        "alert_sudo_shell": True,
        "off_hours": {"start": 0, "end": 6},
    },
    "report": {
        "server": None,
        "bind": "0.0.0.0:8765",
        "token": None,
        "reconnect_sec": 3.0,
    },
    "link": {
        "role": None,
        "join_code": None,
        "host": None,
        "port": 8765,
        "discover_port": 8766,
    },
    "suspicious_commands": [
        {"pattern": "/dev/tcp/", "severity": "critical", "reason": "bash TCP reverse shell"},
        {
            "pattern": r"(?:^|[/\s])nc(?:\.traditional)?(?:\s|$).*(?:-e|-c|/bin/(?:ba)?sh)",
            "severity": "critical",
            "reason": "netcat reverse shell",
        },
        {
            "pattern": r"ncat\s+.*--(?:exec|sh-exec)",
            "severity": "critical",
            "reason": "ncat reverse shell",
        },
        {"pattern": r"socat\s+.*exec:", "severity": "critical", "reason": "socat reverse shell"},
        {
            "pattern": r"python[0-9.]*\s+-c\s+.*(socket|pty|subprocess)",
            "severity": "high",
            "reason": "inline Python shell",
        },
        {
            "pattern": r"(?:curl|wget)\s+.*\|\s*(?:ba)?sh",
            "severity": "critical",
            "reason": "pipe remote script to shell",
        },
        {"pattern": r"\bnmap\b", "severity": "medium", "reason": "network reconnaissance"},
        {"pattern": r"\bmasscan\b", "severity": "high", "reason": "mass port scan"},
        {
            "pattern": r"(?:^|[/\s])(?:vim|nvim|nano|vi|emacs|sed|tee)\s+.*/(?:etc/|authorized_keys|sudoers)",
            "severity": "high",
            "reason": "editing sensitive files",
        },
        {
            "pattern": r"chmod\s+(?:-R\s+)?(?:[0-7]*7[0-7]{2}|777)\b",
            "severity": "medium",
            "reason": "world-writable permissions",
        },
        {"pattern": r"crontab\s+-", "severity": "medium", "reason": "crontab modification"},
        {
            "pattern": r"systemctl\s+(?:enable|link|edit)\b",
            "severity": "medium",
            "reason": "persistence via systemd",
        },
        {
            "pattern": r"(?:useradd|adduser|usermod\s+-aG\s+sudo)\b",
            "severity": "high",
            "reason": "account or sudo-group change",
        },
    ],
}


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def discover_config_path(explicit: str | None = None) -> Path | None:
    if explicit:
        return Path(explicit)
    here = Path.cwd() / "config.yaml"
    if here.is_file():
        return here
    system = Path("/etc/watchdogs/config.yaml")
    if system.is_file():
        return system
    return None


def config_save_path(cfg: dict[str, Any]) -> Path:
    raw = cfg.get("_config_path")
    if raw:
        path = Path(raw)
        if _writable_target(path):
            return path
    cwd = Path.cwd() / "config.yaml"
    if _writable_target(cwd):
        return cwd
    return data_dir(cfg) / "config.yaml"


def _writable_target(path: Path) -> bool:
    try:
        if path.exists():
            return os.access(path, os.W_OK)
        path.parent.mkdir(parents=True, exist_ok=True)
        return os.access(path.parent, os.W_OK)
    except OSError:
        return False


def save_config(cfg: dict[str, Any], path: str | Path | None = None) -> Path:
    dest = Path(path) if path else config_save_path(cfg)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dumped = copy.deepcopy(cfg)
    dumped.pop("_config_path", None)
    dest.write_text(
        yaml.safe_dump(dumped, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    cfg["_config_path"] = str(dest)
    return dest


def apply_form_values(cfg: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    """Write dashboard form values into the live config mapping."""
    alerts = cfg.setdefault("alerts", {})
    off = alerts.setdefault("off_hours", {})
    alerts["failed_login_threshold"] = int(values["failed_login_threshold"])
    alerts["failed_login_window_sec"] = int(values["failed_login_window_sec"])
    alerts["always_alert_root_login"] = bool(values.get("always_alert_root_login"))
    alerts["new_source_ip"] = bool(values.get("new_source_ip"))
    alerts["alert_sudo_shell"] = bool(values.get("alert_sudo_shell"))
    off["start"] = int(values["off_hours_start"])
    off["end"] = int(values["off_hours_end"])
    watch = cfg.setdefault("watch", {})
    if "interactive_only" in values:
        watch["interactive_only"] = bool(values["interactive_only"])
    return cfg


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    cfg = copy.deepcopy(DEFAULTS)
    resolved = Path(path) if path else discover_config_path()
    if resolved and resolved.is_file():
        loaded = yaml.safe_load(resolved.read_text()) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Config {resolved} must be a mapping")
        cfg = _deep_merge(cfg, loaded)
        cfg["_config_path"] = str(resolved)
    else:
        cfg["_config_path"] = None
    return cfg


def _usable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write-test"
        probe.write_text("ok")
        probe.unlink()
    except OSError:
        return False
    return True


def data_dir(cfg: dict[str, Any], demo: bool = False) -> Path:
    candidates: list[Path] = []
    raw = cfg.get("data_dir") or os.environ.get("WATCHDOGS_DATA_DIR")
    if raw:
        candidates.append(Path(raw).expanduser())
    if demo or not hasattr(os, "geteuid") or os.geteuid() != 0:
        candidates.append(Path.home() / ".local/share/watchdogs")
    else:
        candidates.append(Path("/var/lib/watchdogs"))
        candidates.append(Path.home() / ".local/share/watchdogs")
    candidates.append(Path.cwd() / ".watchdogs-data")

    seen: set[Path] = set()
    for path in candidates:
        resolved = path.expanduser()
        if resolved in seen:
            continue
        seen.add(resolved)
        if _usable(resolved):
            return resolved
    raise SystemExit("WatchDogs could not create a writable data directory")
