"""CLI entry: live TUI, headless logger, remote report, or dashboard listen."""

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
from watchdogs.protocol import parse_endpoint
from watchdogs.report import ReportClient, ReportServer


def _normalize_argv(argv: list[str] | None) -> list[str]:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "listen":
        args = ["--listen", *args[1:]]
    return args


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="watchdogs",
        description=(
            "Single-host Linux monitor: live terminal dashboard of logins and "
            "executed commands, with alerts for irregular logins and suspicious execs. "
            "The agent can connect to a dashboard on your computer and stream status. "
            "Does not capture keystrokes or passwords as they are typed."
        ),
    )
    parser.add_argument("-c", "--config", help="Path to config.yaml")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Synthetic events, no root required",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Log to stdout and disk instead of opening the TUI",
    )
    parser.add_argument(
        "--listen",
        action="store_true",
        help="Run the dashboard and wait for a remote watchdog to connect",
    )
    parser.add_argument(
        "--report",
        metavar="HOST:PORT",
        help="Connect to a dashboard and stream status (typical on the server)",
    )
    parser.add_argument(
        "--bind",
        help="Dashboard listen address (default 0.0.0.0:8765)",
    )
    parser.add_argument("--token", help="Shared token for the report link")
    parser.add_argument("--token-file", help="Read the shared token from a file")
    parser.add_argument(
        "--seconds",
        type=float,
        default=0,
        help="Exit after N seconds (useful with --headless --demo)",
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
        token = secrets.token_urlsafe(24)
        print(f"WatchDogs token (give this to the server agent):\n  {token}", flush=True)
        return token
    if required:
        raise SystemExit(
            "A shared token is required for the report link.\n"
            "Use --token, --token-file, WATCHDOGS_TOKEN, or report.token in config.yaml"
        )
    return ""


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    require_root_or_demo(args.demo, listen=args.listen)
    cfg = load_config(args.config)
    report_cfg = cfg.get("report") or {}
    engine = Engine(cfg, demo=args.demo, receiver=args.listen)
    _setup_logging(args.headless or args.listen, engine.store.directory)

    if args.listen:
        token = resolve_token(args, cfg, required=True, generate=True)
        bind = args.bind or report_cfg.get("bind") or "0.0.0.0:8765"
        host, port = parse_endpoint(str(bind))
        server = ReportServer(host, port, token, engine.submit, engine.set_link)
        engine.attach(server)
        print(f"WatchDogs dashboard listening on {host}:{port}", flush=True)
        print("On the monitored server run:", flush=True)
        print(
            f"  sudo python -m watchdogs --headless --report THIS_PC:{port} --token <token>",
            flush=True,
        )
    else:
        target = args.report or report_cfg.get("server")
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
            print(f"WatchDogs will report to {host}:{port}", flush=True)

    if args.headless or (args.listen and args.headless):
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
    print(
        f"WatchDogs {mode}  demo={engine.demo}  data={engine.store.directory}",
        flush=True,
    )
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
