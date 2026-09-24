"""CLI entry: live TUI, headless logger, pair/listen dashboard, or agent."""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import signal
import sys
import time
from pathlib import Path

from watchdogs import __version__
from watchdogs.config import load_config
from watchdogs.engine import Engine, format_headless, require_root_or_demo
from watchdogs.pair import (
    agent_command,
    pairing_card,
    persist_pair,
    remote_start_agent,
    start_reverse_tunnel,
    write_pair_env,
)
from watchdogs.protocol import parse_endpoint
from watchdogs.report import ReportClient, ReportServer


def _normalize_argv(argv: list[str] | None) -> list[str]:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return args
    command = args[0]
    rest = args[1:]
    if command in {"listen", "pair"}:
        extra = ["--listen"]
        if command == "pair":
            extra.append("--pair")
        return extra + rest
    if command in {"agent", "connect"}:
        return ["--headless"] + rest
    return args


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="watchdogs",
        description=(
            "Host monitor with a live dashboard. "
            "On your computer:  python -m watchdogs pair "
            "On the server:     the printed sudo command. "
            "Does not capture keystrokes."
        ),
    )
    parser.add_argument("-c", "--config", help="Path to config.yaml")
    parser.add_argument("--demo", action="store_true", help="Synthetic events, no root")
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Log to stdout instead of the TUI (used by: watchdogs agent)",
    )
    parser.add_argument(
        "--listen",
        action="store_true",
        help="Dashboard that receives a remote agent (watchdogs listen / pair)",
    )
    parser.add_argument(
        "--pair",
        action="store_true",
        help="Print a copy-paste server command and remember the token",
    )
    parser.add_argument(
        "--report",
        metavar="HOST:PORT",
        help="Agent: stream status to this dashboard",
    )
    parser.add_argument("--bind", help="Dashboard listen address (default 0.0.0.0:8765)")
    parser.add_argument("--token", help="Shared token")
    parser.add_argument("--token-file", help="Read token from a file")
    parser.add_argument(
        "--ssh",
        metavar="USER@HOST",
        help="Reverse-tunnel the dashboard through SSH so the server uses 127.0.0.1",
    )
    parser.add_argument(
        "--remote-run",
        action="store_true",
        help="With --ssh, also ssh in and start the agent (needs WatchDogs on the server)",
    )
    parser.add_argument(
        "--seconds",
        type=float,
        default=0,
        help="Exit after N seconds",
    )
    parser.add_argument("--version", action="version", version=f"watchdogs {__version__}")
    return parser.parse_args(_normalize_argv(argv))


def _setup_logging(headless: bool, log_path) -> None:
    handlers: list[logging.Handler] = []
    if headless:
        handlers.append(logging.StreamHandler(sys.stderr))
    try:
        handlers.append(logging.FileHandler(log_path / "watchdogs.log"))
    except OSError:
        pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers or [logging.StreamHandler(sys.stderr)],
    )


def resolve_token(args: argparse.Namespace, cfg: dict, *, required: bool, generate: bool) -> str:
    if args.token:
        return str(args.token)
    if args.token_file:
        return Path(args.token_file).read_text(encoding="utf-8").strip()
    env = os.environ.get("WATCHDOGS_TOKEN")
    if env:
        return env.strip()
    cfg_token = (cfg.get("report") or {}).get("token")
    if cfg_token:
        return str(cfg_token).strip()
    if generate:
        return secrets.token_urlsafe(24)
    if required:
        raise SystemExit(
            "Need a token. Run: python -m watchdogs pair\n"
            "Or set --token, --token-file, WATCHDOGS_TOKEN, or report.token"
        )
    return ""


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    listen = bool(args.listen or args.pair or args.ssh)
    require_root_or_demo(args.demo, listen=listen)
    cfg = load_config(args.config)
    report_cfg = cfg.get("report") or {}
    tunnel = None

    if listen:
        token = resolve_token(args, cfg, required=True, generate=True)
        default_bind = "127.0.0.1:8765" if args.ssh else (report_cfg.get("bind") or "0.0.0.0:8765")
        bind = args.bind or default_bind
        host, port = parse_endpoint(str(bind))
        saved = persist_pair(cfg, token, f"{host}:{port}")
        write_pair_env(saved.parent / "pair.env", token, f"{host}:{port}")
        print(pairing_card(token, port, via_ssh=args.ssh), flush=True)
        if args.ssh:
            print(f"\nOpening SSH tunnel to {args.ssh} …", flush=True)
            tunnel = start_reverse_tunnel(args.ssh, port)
            print("Tunnel is up.", flush=True)
            if args.remote_run:
                print("Starting agent on the server …", flush=True)
                remote_start_agent(args.ssh, token, port)
        engine = Engine(cfg, demo=args.demo, receiver=True)
        engine.report_token = token
        _setup_logging(args.headless, engine.store.directory)
        engine.attach(ReportServer(host, port, token, engine.submit, engine.set_link))
        try:
            if args.headless:
                return _run_headless(engine, args.seconds)
            return _run_tui(engine)
        finally:
            if tunnel is not None and tunnel.poll() is None:
                tunnel.terminate()

    engine = Engine(cfg, demo=args.demo, receiver=False)
    _setup_logging(args.headless, engine.store.directory)
    target = args.report or os.environ.get("WATCHDOGS_REPORT") or report_cfg.get("server")
    if target:
        token = resolve_token(args, cfg, required=True, generate=False)
        host, port = parse_endpoint(str(target))
        client = ReportClient(
            host,
            port,
            token,
            counts=engine.host_status,
            reconnect_sec=float(report_cfg.get("reconnect_sec") or 3),
        )
        engine.add_listener(client.on_event)
        engine.attach(client)
        print(f"WatchDogs agent → {host}:{port}", flush=True)
        print(f"  {agent_command(f'{host}:{port}', token)}", flush=True)
    elif args.headless:
        print("Agent has no dashboard target. Use --report HOST:PORT or: watchdogs pair", flush=True)

    if args.headless:
        return _run_headless(engine, args.seconds)
    return _run_tui(engine)


def _run_headless(engine: Engine, seconds: float) -> int:
    def on_event(kind: str, payload: object) -> None:
        line = format_headless(kind, payload)
        if line:
            print(line, flush=True)

    engine.add_listener(on_event)
    engine.start()
    mode = "listen" if engine.receiver else "agent"
    print(f"WatchDogs {mode}  demo={engine.demo}  data={engine.store.directory}", flush=True)
    stop = False

    def _handle(_signum, _frame) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)
    started = time.monotonic()
    try:
        while not stop:
            time.sleep(0.2)
            if seconds and time.monotonic() - started >= seconds:
                break
    finally:
        engine.stop()
    return 0


def _run_tui(engine: Engine) -> int:
    from watchdogs.tui import WatchDogsApp

    engine.start()
    try:
        WatchDogsApp(engine).run()
    finally:
        engine.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
