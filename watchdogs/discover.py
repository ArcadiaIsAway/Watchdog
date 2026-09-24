"""Find a dashboard: LAN beacons, interface broadcasts, Tailscale, TCP check."""

from __future__ import annotations

import json
import secrets
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field

APP = "watchdogs"
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DEFAULT_UDP_PORT = 8766
DEFAULT_TCP_PORT = 8765
MCAST_GROUP = "239.255.87.65"


def make_join_code(length: int = 4) -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))


def normalize_join_code(value: str) -> str:
    cleaned = "".join(ch for ch in (value or "").upper() if ch.isalnum())
    return "".join(ch for ch in cleaned if ch in CODE_ALPHABET)


def _uniq(items: list[str]) -> list[str]:
    out: list[str] = []
    for item in items:
        if item and item not in out:
            out.append(item)
    return out


def _ip_cmd_addrs() -> tuple[list[str], list[str]]:
    ips: list[str] = []
    broadcasts: list[str] = []
    try:
        raw = subprocess.run(
            ["ip", "-4", "-json", "addr"],
            capture_output=True,
            text=True,
            timeout=0.4,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ips, broadcasts
    if raw.returncode != 0 or not raw.stdout.strip():
        return ips, broadcasts
    try:
        payload = json.loads(raw.stdout)
    except json.JSONDecodeError:
        return ips, broadcasts
    if not isinstance(payload, list):
        return ips, broadcasts
    for iface in payload:
        for info in iface.get("addr_info") or []:
            local = str(info.get("local") or "")
            if local and not local.startswith("127."):
                ips.append(local)
            brd = str(info.get("broadcast") or "")
            if brd:
                broadcasts.append(brd)
    return ips, broadcasts


def local_addresses() -> list[str]:
    found, _ = _ip_cmd_addrs()
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
    unique = [ip for ip in _uniq(found) if _publicish(ip)]
    unique.sort(key=lambda ip: (_address_rank(ip), ip))
    return unique


def _publicish(ip: str) -> bool:
    if not ip or ip.startswith("127."):
        return False
    # Docker/libvirt default bridges — not useful for joining
    if ip.startswith(("172.17.", "172.18.", "172.19.")):
        return False
    return True


def _address_rank(ip: str) -> tuple:
    if ip.startswith("100."):
        return (0,)
    if ip.startswith("192.168."):
        return (1,)
    if ip.startswith("10."):
        return (2,)
    return (3,)


def address_kind(ip: str) -> str:
    if ip.startswith("100."):
        return "Tailscale"
    if ip.startswith(("172.17.", "172.18.", "172.19.")):
        return "Docker"
    return "LAN"


def broadcast_targets() -> list[str]:
    _, broadcasts = _ip_cmd_addrs()
    return _uniq(["255.255.255.255", "127.0.0.1", *broadcasts, MCAST_GROUP])


def describe_endpoints(port: int) -> list[str]:
    lines: list[str] = []
    for ip in local_addresses():
        kind = address_kind(ip)
        mark = "  ← server needs Tailscale too" if kind == "Tailscale" else ""
        lines.append(f"{kind:<10}  {ip}:{port}{mark}")
    if not lines:
        lines.append(f"unknown    0.0.0.0:{port}")
    return lines


def tailscale_peers() -> list[str]:
    try:
        raw = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=0.4,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if raw.returncode != 0 or not raw.stdout.strip():
        return []
    try:
        data = json.loads(raw.stdout)
    except json.JSONDecodeError:
        return []
    ips: list[str] = []
    for peer in (data.get("Peer") or {}).values():
        if not isinstance(peer, dict):
            continue
        if peer.get("Online") is False:
            continue
        for ip in peer.get("TailscaleIPs") or []:
            text = str(ip)
            if text and ":" not in text:
                ips.append(text)
    return _uniq(ips)


def parse_beacon(data: bytes) -> dict | None:
    try:
        message = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(message, dict) or message.get("app") != APP:
        return None
    return message


def encode_beacon(code: str, tcp_port: int, name: str, ips: list[str] | None = None) -> bytes:
    return json.dumps(
        {
            "v": 1,
            "app": APP,
            "code": normalize_join_code(code),
            "port": int(tcp_port),
            "name": name,
            "ips": ips if ips is not None else local_addresses(),
        },
        separators=(",", ":"),
    ).encode("utf-8")


def encode_probe(code: str = "") -> bytes:
    return json.dumps(
        {"v": 1, "app": APP, "want": normalize_join_code(code)},
        separators=(",", ":"),
    ).encode("utf-8")


def tcp_reachable(host: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def token_accepted(host: str, port: int, code: str, timeout: float = 1.2) -> bool:
    """Ask a dashboard if this join code is right, without staying connected."""
    from watchdogs.protocol import dumps, encode_probe, loads

    sock = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(dumps(encode_probe(code)))
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and b"\n" not in buf:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
        if b"\n" not in buf:
            return False
        line, _ = buf.split(b"\n", 1)
        return loads(line).get("type") == "ok"
    except OSError:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def prefer_hosts(hosts: list[str]) -> list[str]:
    ranked = _uniq(hosts)
    ranked.sort(key=lambda ip: (not str(ip).startswith("100."), str(ip).startswith("127."), ip))
    return ranked


@dataclass
class Peer:
    host: str
    port: int
    code: str
    name: str
    ips: tuple[str, ...] = field(default_factory=tuple)

    def candidates(self) -> list[str]:
        return prefer_hosts([*self.ips, self.host])

    def label(self) -> str:
        dest = self.candidates()[0] if self.candidates() else self.host
        return f"{self.name or dest}   {self.code}   {dest}:{self.port}"


def _peer_from_message(message: dict, src_host: str) -> Peer | None:
    code = normalize_join_code(str(message.get("code") or ""))
    port = message.get("port")
    if not code or not port:
        return None
    ips = [str(ip) for ip in (message.get("ips") or []) if ip]
    return Peer(
        host=src_host,
        port=int(port),
        code=code,
        name=str(message.get("name") or src_host),
        ips=tuple(_uniq(ips)),
    )


def _open_udp(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", int(port)))
    try:
        mreq = struct.pack("=4sl", socket.inet_aton(MCAST_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass
    sock.settimeout(0.35)
    return sock


_HOSTS_AT = time.monotonic()
_HOSTS: list[str] = ["255.255.255.255", "127.0.0.1", MCAST_GROUP]


def _discovery_hosts() -> list[str]:
    global _HOSTS_AT, _HOSTS
    now = time.monotonic()
    if now - _HOSTS_AT < 8.0:
        return _HOSTS
    _HOSTS_AT = now
    _HOSTS = _uniq([*_HOSTS, *broadcast_targets(), *tailscale_peers()])
    return _HOSTS


def _probe_dests(udp_port: int) -> list[tuple[str, int]]:
    return [(host, udp_port) for host in _discovery_hosts()]


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
        sock = _open_udp(self.udp_port)
        self._sock = sock
        last_send = 0.0
        try:
            while not stop.is_set():
                payload = self.payload()
                now = time.monotonic()
                if now - last_send >= 0.8:
                    for dest in _probe_dests(self.udp_port):
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
                if not message or "want" not in message:
                    continue
                want = normalize_join_code(str(message.get("want") or ""))
                if want and want != self.code:
                    continue
                try:
                    sock.sendto(payload, addr)
                except OSError:
                    pass
        finally:
            self.close()


def collect_peers(timeout: float = 2.0, udp_port: int = DEFAULT_UDP_PORT, want: str = "") -> list[Peer]:
    """Listen for dashboard beacons and ask the LAN/Tailscale who is there."""
    want = normalize_join_code(want)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.3)
    found: dict[tuple[str, int, str], Peer] = {}
    deadline = time.monotonic() + max(0.4, timeout)
    last_probe = 0.0
    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now - last_probe >= 0.6:
                probe = encode_probe(want)
                for dest in _probe_dests(udp_port):
                    try:
                        sock.sendto(probe, dest)
                    except OSError:
                        pass
                last_probe = now
            try:
                data, addr = sock.recvfrom(2048)
            except TimeoutError:
                continue
            except OSError:
                break
            message = parse_beacon(data)
            if not message:
                continue
            peer = _peer_from_message(message, addr[0])
            if peer is None:
                continue
            if want and peer.code != want:
                continue
            found[(peer.code, peer.port, peer.name)] = peer
    finally:
        sock.close()
    return list(found.values())


def find_peer(code: str, timeout: float = 5.0, udp_port: int = DEFAULT_UDP_PORT) -> Peer | None:
    code = normalize_join_code(code)
    if not code:
        return None
    peers = collect_peers(timeout=timeout, udp_port=udp_port, want=code)
    return peers[0] if peers else None


def locate_dashboard(
    code: str,
    timeout: float = 8.0,
    udp_port: int = DEFAULT_UDP_PORT,
    tcp_port: int = DEFAULT_TCP_PORT,
) -> Peer | None:
    """Find a reachable dashboard for this join code (LAN, then Tailscale)."""
    code = normalize_join_code(code)
    if not code:
        return None
    peers = collect_peers(timeout=timeout, udp_port=udp_port, want=code)
    for peer in peers:
        for host in peer.candidates():
            if tcp_reachable(host, peer.port):
                return Peer(host=host, port=peer.port, code=peer.code, name=peer.name, ips=peer.ips)
    for host in tailscale_peers():
        if token_accepted(host, tcp_port, code):
            return Peer(host=host, port=tcp_port, code=code, name=host, ips=(host,))
    return None
