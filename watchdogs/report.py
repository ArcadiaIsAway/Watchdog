"""Monitored host streams events to the dashboard over a sequenced TCP link."""

from __future__ import annotations

import hashlib
import hmac
import logging
import socket
import threading
import time
from collections import deque
from typing import Callable

from watchdogs import __version__
from watchdogs.models import HostStatus
from watchdogs.protocol import (
    PROTOCOL_NAME,
    STREAM_KINDS,
    decode_frame,
    dumps,
    encode_ack,
    encode_error,
    encode_event,
    encode_hello,
    encode_ok,
    encode_ping,
    encode_pong,
    loads,
)

log = logging.getLogger("watchdogs.report")

OnEvent = Callable[[str, object], None]
OnLink = Callable[[str, str], None]

_COALESCE = frozenset({"sessions", "status"})


def tokens_match(offered: str, expected: str) -> bool:
    left = hashlib.sha256(offered.encode("utf-8")).digest()
    right = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(left, right)


class Outbox:
    """Sequence events on the server; hold them until the dashboard acks."""

    def __init__(self, maxlen: int = 3000) -> None:
        self.maxlen = maxlen
        self._lock = threading.Lock()
        self._seq = 0
        self._log: deque[dict] = deque()
        self._latest: dict[str, dict] = {}
        self._new = threading.Event()

    def push(self, kind: str, payload: object, host: str) -> int | None:
        frame = encode_event(kind, payload, host)
        if frame is None:
            return None
        with self._lock:
            self._seq += 1
            frame["seq"] = self._seq
            if kind in _COALESCE:
                self._latest[kind] = frame
            else:
                self._log.append(frame)
                while len(self._log) > self.maxlen:
                    self._log.popleft()
            self._new.set()
            return self._seq

    def wait(self, timeout: float) -> bool:
        flagged = self._new.wait(timeout)
        if flagged:
            self._new.clear()
        return flagged

    def snapshot(self) -> list[dict]:
        with self._lock:
            items = list(self._log) + list(self._latest.values())
        items.sort(key=lambda frame: int(frame.get("seq") or 0))
        return items

    def ack(self, seq: int) -> None:
        seq = int(seq)
        with self._lock:
            self._log = deque(frame for frame in self._log if int(frame.get("seq") or 0) > seq)
            self._latest = {
                kind: frame
                for kind, frame in self._latest.items()
                if int(frame.get("seq") or 0) > seq
            }


class ReportClient:
    """Server side of the link: connect out, send sequenced frames, wait for acks."""

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        local_host: str | None = None,
        counts: Callable[[], HostStatus] | None = None,
        reconnect_sec: float = 3.0,
    ) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.local_host = local_host or socket.gethostname()
        self.counts = counts
        self.reconnect_sec = max(1.0, float(reconnect_sec))
        self.outbox = Outbox()
        self._sock: socket.socket | None = None
        self._halt = threading.Event()
        self._last_pong = 0.0
        self.connected = False

    def halt(self) -> None:
        self._halt.set()
        self.outbox._new.set()
        self.disconnect()

    def on_event(self, kind: str, payload: object) -> None:
        if kind not in STREAM_KINDS:
            return
        self.outbox.push(kind, payload, self.local_host)

    def update_target(
        self,
        host: str,
        port: int,
        token: str,
        reconnect_sec: float | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.token = token
        if reconnect_sec is not None:
            self.reconnect_sec = max(1.0, float(reconnect_sec))
        self.disconnect()

    def disconnect(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set() and not self._halt.is_set():
            try:
                self._session(stop)
            except Exception:
                log.exception("report client session failed")
            self.connected = False
            if not stop.is_set() and not self._halt.is_set():
                log.info("reconnect to %s:%s in %.1fs", self.host, self.port, self.reconnect_sec)
                stop.wait(self.reconnect_sec)

    def _session(self, stop: threading.Event) -> None:
        log.info("reporting to %s:%s as %s", self.host, self.port, self.local_host)
        sock = socket.create_connection((self.host, self.port), timeout=8)
        self._sock = sock
        reader = threading.Thread(target=self._recv, args=(sock, stop), name="report-recv", daemon=True)
        try:
            sock.sendall(dumps(encode_hello(self.token, self.local_host, __version__)))
            reply_line = _wait_line(sock, stop, timeout=8)
            if reply_line is None:
                return
            reply = loads(reply_line)
            if reply.get("type") != "ok":
                log.error("dashboard rejected hello: %s", reply)
                return
            self.connected = True
            self._last_pong = time.monotonic()
            log.info("report link up")
            reader.start()
            sent_seq = 0
            last_status = 0.0
            last_ping = 0.0
            while not stop.is_set() and not self._halt.is_set() and self._sock is sock:
                if self.counts and time.monotonic() - last_status >= 5:
                    status = self.counts()
                    status.host = self.local_host
                    self.outbox.push("status", status, self.local_host)
                    last_status = time.monotonic()
                for frame in self.outbox.snapshot():
                    seq = int(frame.get("seq") or 0)
                    if seq <= sent_seq:
                        continue
                    sock.sendall(dumps(frame))
                    sent_seq = seq
                now = time.monotonic()
                if now - last_ping >= 4:
                    sock.sendall(dumps(encode_ping()))
                    last_ping = now
                if now - self._last_pong > 15:
                    log.warning("dashboard heartbeat lost")
                    return
                self.outbox.wait(0.4)
        except OSError:
            return
        finally:
            self.connected = False
            if self._sock is sock:
                self.disconnect()
            if reader.is_alive():
                reader.join(timeout=1.0)

    def _recv(self, sock: socket.socket, stop: threading.Event) -> None:
        try:
            for line in _iter_lines(sock, stop):
                try:
                    message = loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                mtype = message.get("type")
                if mtype == "ack":
                    self.outbox.ack(int(message.get("seq") or 0))
                elif mtype == "pong":
                    self._last_pong = time.monotonic()
                elif mtype == "error":
                    log.error("dashboard error: %s", message)
                    if self._sock is sock:
                        self.disconnect()
                    return
        except OSError:
            return
        finally:
            if self._sock is sock:
                self.disconnect()


class ReportServer:
    """Dashboard side: accept one host stream and feed the monitor."""

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        on_event: OnEvent,
        on_link: OnLink | None = None,
    ) -> None:
        self.bind_host = host
        self.port = port
        self.token = token
        self.on_event = on_event
        self.on_link = on_link
        self.actual_port: int | None = None
        self.ready = threading.Event()
        self._clients = 0
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass

    def prepare(self) -> tuple[str, int]:
        last: OSError | None = None
        hosts = [self.bind_host]
        if self.bind_host not in {"0.0.0.0", "127.0.0.1"}:
            hosts.append("0.0.0.0")
        for host in hosts:
            for port in range(self.port, self.port + 8):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind((host, port))
                    sock.listen(8)
                    sock.settimeout(0.5)
                    self._sock = sock
                    self.bind_host = host
                    self.actual_port = int(sock.getsockname()[1])
                    return host, self.actual_port
                except OSError as exc:
                    last = exc
                    sock.close()
        hint = ""
        if last is not None and getattr(last, "errno", None) == 98:
            hint = (
                "\nPort is already in use. On this machine run:\n"
                "  ss -lntp | grep 8765\n"
                "  pkill -f 'python -m watchdogs'\n"
                "Then open the dashboard again from the Connect screen."
            )
        raise OSError(f"cannot listen on {self.bind_host}:{self.port}: {last}{hint}") from last

    def run(self, stop: threading.Event) -> None:
        sock = self._sock
        if sock is None:
            self.prepare()
            sock = self._sock
        assert sock is not None
        self.ready.set()
        log.info("listening for agents on %s:%s", self.bind_host, self.actual_port)
        workers: list[threading.Thread] = []
        try:
            while not stop.is_set():
                try:
                    conn, addr = sock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                worker = threading.Thread(
                    target=self._handle,
                    args=(conn, addr, stop),
                    name=f"report-{addr[0]}",
                    daemon=True,
                )
                worker.start()
                workers.append(worker)
        finally:
            sock.close()
            for worker in workers:
                worker.join(timeout=1.5)

    def _handle(self, conn: socket.socket, addr: tuple, stop: threading.Event) -> None:
        host = "unknown"
        try:
            hello_line = _wait_line(conn, stop, timeout=10)
            if hello_line is None:
                return
            hello = loads(hello_line)
            if hello.get("type") == "probe" and hello.get("protocol") == PROTOCOL_NAME:
                offered = str(hello.get("token") or "")
                if tokens_match(offered, self.token):
                    conn.sendall(dumps(encode_ok(kind="probe")))
                else:
                    conn.sendall(dumps(encode_error("bad token")))
                return
            if hello.get("type") != "hello" or hello.get("protocol") != PROTOCOL_NAME:
                conn.sendall(dumps(encode_error("bad handshake")))
                return
            offered = str(hello.get("token") or "")
            if not tokens_match(offered, self.token):
                conn.sendall(dumps(encode_error("bad token")))
                log.warning("rejected agent from %s (bad token)", addr)
                return
            host = str(hello.get("host") or addr[0])
            conn.sendall(dumps(encode_ok()))
            with self._lock:
                self._clients += 1
            if self.on_link:
                self.on_link("up", host)
            log.info("agent connected host=%s from=%s", host, addr)
            last_ack = 0
            for line in _iter_lines(conn, stop):
                message = loads(line)
                mtype = message.get("type")
                if mtype == "ping":
                    conn.sendall(dumps(encode_pong()))
                    continue
                kind, payload = decode_frame(message)
                if kind is None:
                    continue
                self.on_event(kind, payload)
                seq = int(message.get("seq") or 0)
                if seq and seq != last_ack:
                    conn.sendall(dumps(encode_ack(seq)))
                    last_ack = seq
        except Exception:
            log.exception("agent session from %s failed", addr)
        finally:
            with self._lock:
                self._clients = max(0, self._clients - 1)
                remaining = self._clients
            if self.on_link and remaining == 0:
                self.on_link("down", host)
            try:
                conn.close()
            except OSError:
                pass


def _iter_lines(sock: socket.socket, stop: threading.Event, timeout: float = 0.5):
    leftover = b""
    sock.settimeout(timeout)
    while not stop.is_set():
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            continue
        except OSError:
            return
        if not chunk:
            return
        leftover += chunk
        while b"\n" in leftover:
            line, leftover = leftover.split(b"\n", 1)
            yield line
        if len(leftover) > 1_000_000:
            return


def _wait_line(sock: socket.socket, stop: threading.Event, timeout: float) -> bytes | None:
    sock.settimeout(0.5)
    leftover = b""
    deadline = time.monotonic() + timeout
    while not stop.is_set() and time.monotonic() < deadline:
        if b"\n" in leftover:
            line, leftover = leftover.split(b"\n", 1)
            return line
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            continue
        except OSError:
            return None
        if not chunk:
            return None
        leftover += chunk
    return None
