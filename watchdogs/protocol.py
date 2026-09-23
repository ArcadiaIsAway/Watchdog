"""Line-delimited JSON messages between a host agent and the dashboard."""

from __future__ import annotations

import json
from typing import Any

from watchdogs.models import Alert, CommandEvent, HostStatus, LoginEvent, Session

PROTOCOL_NAME = "watchdogs-report"
PROTOCOL_VERSION = 1


def encode_hello(token: str, host: str, version: str) -> dict[str, Any]:
    return {
        "type": "hello",
        "protocol": PROTOCOL_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "token": token,
        "host": host,
        "version": version,
    }


def encode_event(kind: str, payload: object, host: str) -> dict[str, Any] | None:
    body = _payload_to_dict(kind, payload)
    if body is None:
        return None
    return {"type": "event", "kind": kind, "host": host, "payload": body}


def encode_status(status: HostStatus) -> dict[str, Any]:
    return {"type": "status", "host": status.host, "payload": status.to_dict()}


def dumps(message: dict[str, Any]) -> bytes:
    return (json.dumps(message, default=str) + "\n").encode("utf-8")


def loads(line: str | bytes) -> dict[str, Any]:
    if isinstance(line, bytes):
        line = line.decode("utf-8", "replace")
    data = json.loads(line)
    if not isinstance(data, dict):
        raise ValueError("message must be an object")
    return data


def decode_payload(kind: str, data: dict[str, Any]) -> object | None:
    if kind == "login":
        return LoginEvent.from_dict(data)
    if kind == "command":
        return CommandEvent.from_dict(data)
    if kind == "alert":
        return Alert.from_dict(data)
    if kind == "sessions":
        return [Session.from_dict(item) for item in data.get("sessions", data if isinstance(data, list) else [])]
    if kind == "status":
        return HostStatus(
            host=str(data.get("host") or ""),
            logins=int(data.get("logins") or 0),
            commands=int(data.get("commands") or 0),
            alerts=int(data.get("alerts") or 0),
        )
    return None


def _payload_to_dict(kind: str, payload: object) -> Any | None:
    if kind == "sessions":
        if not isinstance(payload, list):
            return None
        return {"sessions": [item.to_dict() if hasattr(item, "to_dict") else item for item in payload]}
    if hasattr(payload, "to_dict"):
        return payload.to_dict()
    return None


def parse_endpoint(value: str, default_port: int = 8765) -> tuple[str, int]:
    text = (value or "").strip()
    if not text:
        raise ValueError("empty endpoint")
    if text.count(":") == 0:
        return text, default_port
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"invalid endpoint {value!r}")
    return host, int(port)
