"""LAN join-code beacons so two dashboards can find each other without IPs."""

from __future__ import annotations

import json
import secrets
import socket
import time
from dataclasses import dataclass

APP = "watchdogs"
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DEFAULT_UDP_PORT = 8766


def make_join_code(length: int = 4) -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))


def normalize_join_code(value: str) -> str:
    cleaned = "".join(ch for ch in (value or "").upper() if ch.isalnum())
    return "".join(ch for ch in cleaned if ch in CODE_ALPHABET)


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
    unique.sort(key=lambda ip: (not ip.startswith("100."), ip))
    return unique


def parse_beacon(data: bytes) -> dict | None:
    try:
        message = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(message, dict) or message.get("app") != APP:
        return None
    return message


def encode_beacon(code: str, tcp_port: int, name: str) -> bytes:
    return json.dumps(
        {
            "v": 1,
            "app": APP,
            "code": normalize_join_code(code),
            "port": int(tcp_port),
            "name": name,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def encode_probe(code: str) -> bytes:
    return json.dumps(
        {"v": 1, "app": APP, "want": normalize_join_code(code)},
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class Peer:
    host: str
    port: int
    code: str
    name: str


class Beacon:
    """Advertise a dashboard join code on the LAN and answer probes."""

    def __init__(
        self,
        code: str,
        tcp_port: int,
        name: str = "",
        udp_port: int = DEFAULT_UDP_PORT,
    ) -> None:
        self.code = normalize_join_code(code)
        self.tcp_port = int(tcp_port)
        self.name = name or socket.gethostname()
        self.udp_port = int(udp_port)
        self._sock: socket.socket | None = None

    def payload(self) -> bytes:
        return encode_beacon(self.code, self.tcp_port, self.name)

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass

    def run(self, stop) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", self.udp_port))
        sock.settimeout(0.4)
        self._sock = sock
        payload = self.payload()
        dests = [("255.255.255.255", self.udp_port), ("127.0.0.1", self.udp_port)]
        last_send = 0.0
        try:
            while not stop.is_set():
                now = time.monotonic()
                if now - last_send >= 1.0:
                    for dest in dests:
                        try:
                            sock.sendto(payload, dest)
                        except OSError:
                            pass
                    last_send = now
                try:
                    data, addr = sock.recvfrom(2048)
                except TimeoutError:
                    continue
                except OSError:
                    break
                message = parse_beacon(data)
                if message and message.get("want") == self.code:
                    try:
                        sock.sendto(payload, addr)
                    except OSError:
                        pass
        finally:
            self.close()


def find_peer(code: str, timeout: float = 5.0, udp_port: int = DEFAULT_UDP_PORT) -> Peer | None:
    """Ask the LAN for a dashboard advertising this join code."""
    code = normalize_join_code(code)
    if not code:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.4)
    probe = encode_probe(code)
    dests = [("255.255.255.255", udp_port), ("127.0.0.1", udp_port)]
    deadline = time.monotonic() + max(0.4, timeout)
    try:
        while time.monotonic() < deadline:
            for dest in dests:
                try:
                    sock.sendto(probe, dest)
                except OSError:
                    pass
            try:
                data, addr = sock.recvfrom(2048)
            except TimeoutError:
                continue
            except OSError:
                break
            message = parse_beacon(data)
            if not message:
                continue
            found = normalize_join_code(str(message.get("code") or ""))
            port = message.get("port")
            if found == code and port:
                return Peer(
                    host=addr[0],
                    port=int(port),
                    code=found,
                    name=str(message.get("name") or addr[0]),
                )
    finally:
        sock.close()
    return None
