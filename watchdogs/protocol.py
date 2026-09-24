"""Line-delimited JSON stream from a monitored host to the dashboard."""

from __future__ import annotations

import json
from typing import Any

from watchdogs.models import Alert, CommandEvent, HostStatus, LoginEvent, Session

PROTOCOL_NAME = "watchdogs-report"
PROTOCOL_VERSION = 2
STREAM_KINDS = frozenset({"login", "command", "alert", "sessions", "status"})


def encode_hello(token: str, host: str, version: str) -> dict[str, Any]:
    return {
        "v": PROTOCOL_VERSION,
        "type": "hello",
        "protocol": PROTOCOL_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "token": token,
        "host": host,
        "version": version,
    }


def encode_probe(token: str) -> dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "type": "probe", "protocol": PROTOCOL_NAME, "token": token}


def encode_ok(**extra: Any) -> dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "type": "ok", **extra}


def encode_error(reason: str) -> dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "type": "error", "reason": reason}


def encode_ack(seq: int) -> dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "type": "ack", "seq": int(seq)}


def encode_ping() -> dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "type": "ping"}


def encode_pong() -> dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "type": "pong"}


def encode_event(kind: str, payload: object, host: str, seq: int = 0) -> dict[str, Any] | None:
    body = _payload_to_dict(kind, payload)
    if body is None:
        return None
    return {
        "v": PROTOCOL_VERSION,
        "type": "status" if kind == "status" else "event",
        "kind": kind,
        "host": host,
        "seq": int(seq),
        "payload": body,
    }


def dumps(message: dict[str, Any]) -> bytes:
    return (json.dumps(message, default=str, separators=(",", ":")) + "\n").encode("utf-8")


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
        items = data.get("sessions", data if isinstance(data, list) else [])
        return [Session.from_dict(item) for item in items]
    if kind == "status":
        return HostStatus(
            host=str(data.get("host") or ""),
            logins=int(data.get("logins") or 0),
            commands=int(data.get("commands") or 0),
            alerts=int(data.get("alerts") or 0),
        )
    return None


def decode_frame(message: dict[str, Any]) -> tuple[str | None, object | None]:
    """Turn a stream frame into an engine (kind, payload) pair."""
    mtype = str(message.get("type") or "")
    if mtype == "status":
        kind = "status"
    elif mtype == "event":
        kind = str(message.get("kind") or "")
    else:
        return None, None
    raw = message.get("payload")
    if raw is None:
        raw = message.get("body")
    if kind == "sessions" and isinstance(raw, list):
        raw = {"sessions": raw}
    if not isinstance(raw, dict):
        return None, None
    if kind == "status":
        host = str(message.get("host") or raw.get("host") or "")
        raw = {**raw, "host": host or raw.get("host")}
    decoded = decode_payload(kind, raw)
    if decoded is None:
        return None, None
    return kind, decoded


def _payload_to_dict(kind: str, payload: object) -> Any | None:
    if kind not in STREAM_KINDS:
        return None
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
