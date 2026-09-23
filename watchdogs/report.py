"""Agent reporter (connects out) and dashboard listener (accepts reports)."""

from __future__ import annotations

import hashlib
import hmac
import logging
import queue
import socket
import threading
from typing import Callable

from watchdogs import __version__
from watchdogs.models import HostStatus
from watchdogs.protocol import (
    PROTOCOL_NAME,
    decode_payload,
    dumps,
    encode_event,
    encode_hello,
    encode_status,
    loads,
)

log = logging.getLogger("watchdogs.report")

OnEvent = Callable[[str, object], None]
OnLink = Callable[[str, str], None]  # status, hostname


def tokens_match(offered: str, expected: str) -> bool:
    left = hashlib.sha256(offered.encode("utf-8")).digest()
    right = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(left, right)


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


class ReportClient:
    """Connects from the monitored host to the dashboard and streams events."""

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
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=2000)
        self._sock: socket.socket | None = None
        self.connected = False

    def on_event(self, kind: str, payload: object) -> None:
        message = encode_event(kind, payload, self.local_host)
        if message is None:
            return
        try:
            self._queue.put_nowait(message)
        except queue.Full:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(message)
            except queue.Full:
                pass

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
        while not stop.is_set():
            try:
                self._session(stop)
            except Exception:
                log.exception("report client session failed")
            self.connected = False
            if not stop.is_set():
                log.info("reconnect to %s:%s in %.1fs", self.host, self.port, self.reconnect_sec)
                stop.wait(self.reconnect_sec)

    def _session(self, stop: threading.Event) -> None:
        log.info("reporting to %s:%s as %s", self.host, self.port, self.local_host)
        sock = socket.create_connection((self.host, self.port), timeout=8)
        self._sock = sock
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
            log.info("report link up")
            import time

            last_status = 0.0
            while not stop.is_set():
                try:
                    message = self._queue.get(timeout=0.4)
                    sock.sendall(dumps(message))
                except queue.Empty:
                    pass
                except OSError:
                    return
                now = time.monotonic()
                if self.counts and now - last_status >= 5:
                    status = self.counts()
                    status.host = self.local_host
                    sock.sendall(dumps(encode_status(status)))
                    last_status = now
        finally:
            self.connected = False
            try:
                sock.close()
            except OSError:
                pass


def _wait_line(sock: socket.socket, stop: threading.Event, timeout: float) -> bytes | None:
    sock.settimeout(0.5)
    leftover = b""
    import time

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


class ReportServer:
    """Accepts outbound agent connections and feeds events into the dashboard."""

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

    def run(self, stop: threading.Event) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_host, self.port))
        self.actual_port = int(sock.getsockname()[1])
        sock.listen(8)
        sock.settimeout(0.5)
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
            if hello.get("type") != "hello" or hello.get("protocol") != PROTOCOL_NAME:
                conn.sendall(dumps({"type": "error", "reason": "bad handshake"}))
                return
            offered = str(hello.get("token") or "")
            if not tokens_match(offered, self.token):
                conn.sendall(dumps({"type": "error", "reason": "bad token"}))
                log.warning("rejected agent from %s (bad token)", addr)
                return
            host = str(hello.get("host") or addr[0])
            conn.sendall(dumps({"type": "ok"}))
            with self._lock:
                self._clients += 1
            if self.on_link:
                self.on_link("up", host)
            log.info("agent connected host=%s from=%s", host, addr)
            for line in _iter_lines(conn, stop):
                message = loads(line)
                kind, payload = _message_to_event(message)
                if kind is None:
                    continue
                self.on_event(kind, payload)
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


def _message_to_event(message: dict) -> tuple[str | None, object | None]:
    mtype = message.get("type")
    if mtype == "status":
        payload = message.get("payload") or message
        host = str(message.get("host") or payload.get("host") or "")
        if isinstance(payload, dict):
            payload = {**payload, "host": host or payload.get("host")}
            decoded = decode_payload("status", payload)
            return "status", decoded
        return None, None
    if mtype != "event":
        return None, None
    kind = str(message.get("kind") or "")
    raw = message.get("payload")
    if not isinstance(raw, dict) and kind != "sessions":
        if kind == "sessions" and isinstance(raw, list):
            raw = {"sessions": raw}
        else:
            return None, None
    if kind == "sessions" and isinstance(raw, list):
        raw = {"sessions": raw}
    if not isinstance(raw, dict):
        return None, None
    decoded = decode_payload(kind, raw)
    if decoded is None:
        return None, None
    return kind, decoded
