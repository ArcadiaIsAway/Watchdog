"""Inbound queue, persistence, rule evaluation, and listener fan-out."""

from __future__ import annotations

import logging
import os
import queue
import socket
import threading
from typing import Any, Callable

from watchdogs.auth import AuthCollector
from watchdogs.config import data_dir
from watchdogs.demo import DemoFeeder
from watchdogs.models import Alert, CommandEvent, HostStatus
from watchdogs.procs import ProcessCollector, is_internal_command, is_user_command
from watchdogs.rules import RuleEngine
from watchdogs.sessions import SessionCollector
from watchdogs.shellcmds import ShellCommandCollector
from watchdogs.store import Store

log = logging.getLogger("watchdogs")

Listener = Callable[[str, object], None]


class Engine:
    def __init__(self, cfg: dict[str, Any], demo: bool = False, receiver: bool = False) -> None:
        self.cfg = cfg
        self.demo = demo
        self.receiver = receiver
        self.store = Store(data_dir(cfg, demo=demo or receiver))
        self.rules = RuleEngine(cfg, self.store)
        self._inbound: queue.Queue[tuple[str, object] | None] = queue.Queue()
        self._stop = threading.Event()
        self._listeners: list[Listener] = []
        self._threads: list[threading.Thread] = []
        self._services: list[Any] = []
        self._lock = threading.Lock()
        self.login_count = 0
        self.command_count = 0
        self.alert_count = 0
        self.remote_host = ""
        link = cfg.get("link") or {}
        self.link_role = str(link.get("role") or ("dashboard" if receiver else ""))
        self.join_code = str(link.get("join_code") or "")
        self.link_status = "waiting" if receiver or self.link_role == "dashboard" else "local"
        self.report_token = self.join_code or str((cfg.get("report") or {}).get("token") or "")
        self.report_client: Any = None
        self.report_server: Any = None
        self.beacon: Any = None
        self._started = False

    def add_listener(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def submit(self, kind: str, payload: object) -> None:
        self._inbound.put((kind, payload))

    def ack(self, alert_id: int) -> None:
        self.store.ack_alert(alert_id)

    def attach(self, service: Any) -> None:
        from watchdogs.report import ReportClient, ReportServer

        self._services.append(service)
        if isinstance(service, ReportClient):
            self.report_client = service
            self.report_token = service.token
        elif isinstance(service, ReportServer):
            self.report_server = service
            self.report_token = service.token
        else:
            from watchdogs.discover import Beacon

            if isinstance(service, Beacon):
                self.beacon = service
        if self._started:
            self._spawn(service)

    def host_status(self) -> HostStatus:
        host = self.remote_host if self.receiver and self.remote_host else socket.gethostname()
        return HostStatus(
            host=host,
            logins=self.login_count,
            commands=self.command_count,
            alerts=self.alert_count,
        )

    def set_link(self, status: str, hostname: str = "") -> None:
        with self._lock:
            self.link_status = status
            if hostname:
                self.remote_host = hostname
        self._fanout("link", {"status": status, "host": hostname})

    def apply_settings(self, values: dict[str, Any]) -> str:
        from watchdogs.config import apply_form_values, save_config

        apply_form_values(self.cfg, values)
        self.rules.reload(self.cfg)
        path = save_config(self.cfg)
        return f"saved {path}"

    def stay_local(self) -> str:
        from watchdogs.config import save_config

        self._stop_link()
        self.link_role = "local"
        self.join_code = ""
        self.receiver = False
        self.link_status = "local"
        link = self.cfg.setdefault("link", {})
        link["role"] = "local"
        link["join_code"] = None
        link["host"] = None
        path = save_config(self.cfg)
        return f"local monitor — {path}"

    def start_dashboard(self, join_code: str = "") -> str:
        from watchdogs.config import save_config
        from watchdogs.discover import Beacon, make_join_code, normalize_join_code
        from watchdogs.report import ReportServer

        self._stop_link()
        code = normalize_join_code(join_code) or self.join_code or make_join_code()
        self.join_code = code
        self.link_role = "dashboard"
        self.receiver = True
        self.report_token = code
        self.remote_host = ""
        self.link_status = "waiting"
        link = self.cfg.setdefault("link", {})
        tcp_port = int(link.get("port") or 8765)
        udp_port = int(link.get("discover_port") or 8766)
        server = ReportServer("0.0.0.0", tcp_port, code, self.submit, self.set_link)
        host, port = server.prepare()
        beacon = Beacon(code, port, udp_port=udp_port)
        self.attach(server)
        self.attach(beacon)
        link["role"] = "dashboard"
        link["join_code"] = code
        link["host"] = None
        self.cfg.setdefault("report", {})["token"] = code
        save_config(self.cfg)
        log.info("dashboard listening on %s:%s code=%s", host, port, code)
        return f"Dashboard open. Join code {code}"

    def join_dashboard(self, join_code: str, host: str = "") -> str:
        from watchdogs.config import save_config
        from watchdogs.discover import locate_dashboard, normalize_join_code, tcp_reachable
        from watchdogs.protocol import parse_endpoint
        from watchdogs.report import ReportClient

        code = normalize_join_code(join_code)
        if not code:
            raise ValueError("Type the join code shown on the other machine")
        target = (host or "").strip()
        if target:
            if ":" in target:
                peer_host, peer_port = parse_endpoint(target)
            else:
                peer_host, peer_port = target, int((self.cfg.get("link") or {}).get("port") or 8765)
            if not tcp_reachable(peer_host, peer_port, timeout=2.0):
                raise ValueError(
                    f"Nothing is listening at {peer_host}:{peer_port}. "
                    "On the other computer tap My computer, then use a LAN address, "
                    "or a 100.x address if BOTH machines are on Tailscale."
                )
        else:
            link = self.cfg.get("link") or {}
            peer = locate_dashboard(
                code,
                timeout=8.0,
                udp_port=int(link.get("discover_port") or 8766),
                tcp_port=int(link.get("port") or 8765),
            )
            if peer is None:
                raise ValueError(
                    f"Could not find a dashboard with code {code}. "
                    "Same network: leave Connect open on the other computer and retry. "
                    "Different networks: Tailscale must be running on both machines; "
                    "then type the 100.x address from the other screen."
                )
            peer_host, peer_port = peer.host, peer.port
        self._stop_link()
        self.join_code = code
        self.link_role = "agent"
        self.receiver = False
        self.report_token = code
        self.link_status = "connecting"
        retry = float((self.cfg.get("report") or {}).get("reconnect_sec") or 3)
        client = ReportClient(
            peer_host,
            peer_port,
            code,
            counts=self.host_status,
            reconnect_sec=retry,
        )
        self.add_listener(client.on_event)
        self.attach(client)
        link = self.cfg.setdefault("link", {})
        link["role"] = "agent"
        link["join_code"] = code
        link["host"] = f"{peer_host}:{peer_port}"
        self.cfg.setdefault("report", {})["token"] = code
        self.cfg["report"]["server"] = f"{peer_host}:{peer_port}"
        save_config(self.cfg)
        return f"Joining {peer_host}:{peer_port}  ·  code {code}"

    def restore_link(self) -> str | None:
        link = self.cfg.get("link") or {}
        role = str(link.get("role") or "")
        code = str(link.get("join_code") or "")
        if role == "dashboard":
            return self.start_dashboard(code)
        if role == "agent":
            return self.join_dashboard(code, str(link.get("host") or ""))
        return None

    def _stop_link(self) -> None:
        if self.report_client is not None:
            self.report_client.halt()
        if self.report_server is not None:
            self.report_server.close()
        if self.beacon is not None:
            self.beacon.close()
        self.report_client = None
        self.report_server = None
        self.beacon = None
        self.receiver = False
        if self.link_status not in {"local"}:
            self.set_link("local")

    def start(self) -> None:
        self._stop.clear()
        self._started = True
        worker = threading.Thread(target=self._loop, name="watchdogs-engine", daemon=True)
        worker.start()
        self._threads.append(worker)
        for collector in self._collectors():
            self._spawn(collector)
        for service in self._services:
            self._spawn(service)
        log.info(
            "engine started demo=%s receiver=%s data_dir=%s",
            self.demo,
            self.receiver,
            self.store.directory,
        )

    def _spawn(self, service: Any) -> None:
        thread = threading.Thread(
            target=service.run,
            args=(self._stop,),
            name=type(service).__name__,
            daemon=True,
        )
        thread.start()
        self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        self._inbound.put(None)
        if self.report_client is not None:
            self.report_client.halt()
        if self.report_server is not None:
            self.report_server.close()
        if self.beacon is not None:
            self.beacon.close()
        for thread in self._threads:
            thread.join(timeout=2.5)
        self._threads.clear()
        self.store.close()

    def _collectors(self) -> list[Any]:
        if self.receiver:
            return []
        emit = self.submit
        if self.demo:
            return [DemoFeeder(emit), SessionCollector(emit, self.cfg["watch"]["session_poll_sec"])]
        watch = self.cfg["watch"]
        collectors: list[Any] = [
            AuthCollector(emit, list(watch.get("auth_logs") or []), bool(watch.get("journal", True))),
            SessionCollector(emit, watch.get("session_poll_sec", 2.0)),
        ]
        if watch.get("process_events", True):
            collectors.append(ProcessCollector(emit))
        if watch.get("typed_commands", True):
            collectors.append(ShellCommandCollector(emit, self.store.directory))
        return collectors

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._inbound.get(timeout=0.4)
            except queue.Empty:
                continue
            if item is None:
                break
            kind, payload = item
            self._dispatch(kind, payload)

    def _dispatch(self, kind: str, payload: object) -> None:
        if kind == "status" and isinstance(payload, HostStatus):
            with self._lock:
                if payload.host:
                    self.remote_host = payload.host
                if payload.logins:
                    self.login_count = max(self.login_count, payload.logins)
                if payload.commands:
                    self.command_count = max(self.command_count, payload.commands)
                if payload.alerts:
                    self.alert_count = max(self.alert_count, payload.alerts)
            self._fanout(kind, payload)
            return
        if kind == "link":
            self._fanout(kind, payload)
            return
        if kind == "command" and isinstance(payload, CommandEvent):
            interactive = bool((self.cfg.get("watch") or {}).get("interactive_only", True))
            if is_internal_command(payload) or not is_user_command(payload, interactive):
                return
        if kind in {"login", "command"}:
            self.store.write_event(payload)  # type: ignore[arg-type]
            with self._lock:
                if kind == "login":
                    self.login_count += 1
                else:
                    self.command_count += 1
        if self.receiver:
            if kind == "alert" and isinstance(payload, Alert):
                stored = self.store.write_alert(payload)
                with self._lock:
                    self.alert_count += 1
                self._fanout("alert", stored)
                return
            self._fanout(kind, payload)
            return
        for alert in self.rules.evaluate(kind, payload):
            stored = self.store.write_alert(alert)
            with self._lock:
                self.alert_count += 1
            self._fanout("alert", stored)
        self._fanout(kind, payload)

    def _fanout(self, kind: str, payload: object) -> None:
        for listener in list(self._listeners):
            try:
                listener(kind, payload)
            except Exception:
                log.exception("listener failed kind=%s", kind)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def require_root_or_demo(demo: bool, listen: bool = False) -> None:
    if demo or listen:
        return
    if is_root():
        return
    raise SystemExit(
        "WatchDogs needs root to read auth logs and process exec events.\n"
        "Run: sudo python -m watchdogs\n"
        "Or:  python -m watchdogs --demo"
    )


def format_headless(kind: str, payload: object) -> str | None:
    if kind == "alert" and isinstance(payload, Alert):
        stamp = payload.ts.strftime("%H:%M:%S")
        return f"{stamp} ALERT {payload.severity.upper():<8} {payload.rule}: {payload.message}"
    if kind == "login":
        stamp = payload.ts.strftime("%H:%M:%S")  # type: ignore[attr-defined]
        return (
            f"{stamp} LOGIN {payload.result:<12} {payload.username:<12} "  # type: ignore[attr-defined]
            f"{payload.service} {payload.source_ip}"  # type: ignore[attr-defined]
        )
    if kind == "command":
        stamp = payload.ts.strftime("%H:%M:%S")  # type: ignore[attr-defined]
        return (
            f"{stamp} EXEC  {payload.username:<12} pid={payload.pid:<7} "  # type: ignore[attr-defined]
            f"{payload.cmdline}"  # type: ignore[attr-defined]
        )
    return None
