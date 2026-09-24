"""CLI entry: one command opens the dashboard on every machine."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

from watchdogs import __version__
from watchdogs.config import load_config
from watchdogs.engine import Engine, format_headless, is_root, require_root_or_demo


def _use_project_venv() -> None:
    """Re-run under .venv when system Python is missing the dashboard deps."""
    try:
        import textual  # noqa: F401
        return
    except ImportError:
        pass
    root = Path(__file__).resolve().parent.parent
    for venv in (root / ".venv", root / "venv"):
        candidate = venv / "bin" / "python"
        already_in = Path(sys.prefix).resolve() == venv.resolve()
        if candidate.is_file() and not already_in:
            os.execv(str(candidate), [str(candidate), "-m", "watchdogs", *sys.argv[1:]])
    raise SystemExit(
        "WatchDogs needs Textual. From this folder run:\n"
        "  python -m venv .venv\n"
        "  .venv/bin/pip install -e .\n"
        "  .venv/bin/python -m watchdogs"
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="watchdogs",
        description=(
            "Host monitor with a live dashboard. "
            "Run the same command on both machines and connect from the screen. "
            "Does not capture keystrokes."
        ),
    )
    parser.add_argument("-c", "--config", help="Path to config.yaml")
    parser.add_argument("--demo", action="store_true", help="Synthetic events, no root")
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Log to stdout (uses the last Connect choice from the dashboard)",
    )
    parser.add_argument(
        "--seconds",
        type=float,
        default=0,
        help="Exit after N seconds",
    )
    parser.add_argument("--version", action="version", version=f"watchdogs {__version__}")
    return parser.parse_args(argv)


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


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        _use_project_venv()
    args = _parse_args(argv)
    cfg = load_config(args.config)
    role = str((cfg.get("link") or {}).get("role") or "")
    if args.headless and not args.demo and role != "dashboard":
        require_root_or_demo(False)

    engine = Engine(cfg, demo=args.demo, receiver=role == "dashboard")
    _setup_logging(args.headless, engine.store.directory)

    if role in {"dashboard", "agent"}:
        try:
            message = engine.restore_link()
            if message:
                print(message, flush=True)
        except Exception as exc:
            print(f"Could not restore last connection: {exc}", flush=True)
            if args.headless:
                raise SystemExit(
                    "Open WatchDogs on this machine (no --headless) and use Connect."
                ) from exc
    elif args.headless and not args.demo:
        print(
            "No dashboard link saved yet. Run `python -m watchdogs` and tap "
            "Open dashboard or Join dashboard.",
            flush=True,
        )

    if args.headless:
        if not args.demo and not is_root() and engine.link_role != "dashboard":
            require_root_or_demo(False)
        return _run_headless(engine, args.seconds)
    return _run_tui(engine)


def _run_headless(engine: Engine, seconds: float) -> int:
    def on_event(kind: str, payload: object) -> None:
        line = format_headless(kind, payload)
        if line:
            print(line, flush=True)

    engine.add_listener(on_event)
    engine.start()
    mode = engine.link_role or ("listen" if engine.receiver else "local")
    extra = f"  code={engine.join_code}" if engine.join_code else ""
    print(f"WatchDogs {mode}  demo={engine.demo}  data={engine.store.directory}{extra}", flush=True)
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
