"""Event and alert types used across collectors, rules, and the TUI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


def _iso(ts: datetime) -> str:
    return ts.isoformat(timespec="seconds")


def parse_datetime(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed


@dataclass
class LoginEvent:
    ts: datetime
    result: str  # accepted, failed, invalid, sudo, su, session_open, session_close
    username: str
    source_ip: str = ""
    method: str = ""
    service: str = ""
    tty: str = ""
    raw: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ts"] = _iso(self.ts)
        data["kind"] = "login"
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LoginEvent:
        return cls(
            ts=parse_datetime(data["ts"]),
            result=str(data.get("result") or ""),
            username=str(data.get("username") or ""),
            source_ip=str(data.get("source_ip") or ""),
            method=str(data.get("method") or ""),
            service=str(data.get("service") or ""),
            tty=str(data.get("tty") or ""),
            raw=str(data.get("raw") or ""),
            extra=dict(data.get("extra") or {}),
        )


@dataclass
class CommandEvent:
    ts: datetime
    pid: int
    ppid: int
    uid: int
    username: str
    cmdline: str
    exe: str = ""
    tty: str = ""
    source: str = "exec"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ts"] = _iso(self.ts)
        data["kind"] = "command"
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommandEvent:
        return cls(
            ts=parse_datetime(data["ts"]),
            pid=int(data.get("pid") or 0),
            ppid=int(data.get("ppid") or 0),
            uid=int(data.get("uid") or 0),
            username=str(data.get("username") or ""),
            cmdline=str(data.get("cmdline") or ""),
            exe=str(data.get("exe") or ""),
            tty=str(data.get("tty") or ""),
            source=str(data.get("source") or "exec"),
        )


@dataclass
class Session:
    username: str
    tty: str
    source: str
    since: str
    pid: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        return cls(
            username=str(data.get("username") or ""),
            tty=str(data.get("tty") or ""),
            source=str(data.get("source") or ""),
            since=str(data.get("since") or ""),
            pid=int(data.get("pid") or 0),
        )


@dataclass
class Alert:
    ts: datetime
    severity: str
    rule: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)
    acked: bool = False
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ts"] = _iso(self.ts)
        data["kind"] = "alert"
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        return cls(
            ts=parse_datetime(data["ts"]),
            severity=str(data.get("severity") or "medium"),
            rule=str(data.get("rule") or ""),
            message=str(data.get("message") or ""),
            context=dict(data.get("context") or {}),
            acked=bool(data.get("acked")),
            id=int(data["id"]) if data.get("id") is not None else None,
        )


@dataclass
class HostStatus:
    host: str
    logins: int = 0
    commands: int = 0
    alerts: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = "status"
        return data
