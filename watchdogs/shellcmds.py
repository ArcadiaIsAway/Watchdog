"""Record the command line the shell just ran (including typos / builtins)."""

from __future__ import annotations

import getpass
import os
import pwd
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable

from watchdogs.models import CommandEvent
from watchdogs.procs import _looks_like_noise

EmitFn = Callable[[str, object], None]

_ZSH_LINE = re.compile(r"^: (\d+):\d+;(.*)$")
_HOOK_MARK = "watchdogs-typed-commands"
_SKIP_PREFIXES = ("watchdogs", "source ", ".", "history ", "fc ")


def parse_zsh_history_line(line: str) -> tuple[datetime | None, str]:
    match = _ZSH_LINE.match(line.rstrip("\n"))
    if not match:
        return None, line.strip()
    try:
        ts = datetime.fromtimestamp(int(match.group(1)))
    except (OSError, ValueError):
        ts = None
    return ts, match.group(2).strip()


def parse_typed_log_line(line: str) -> CommandEvent | None:
    parts = line.rstrip("\n").split("|", 3)
    if len(parts) != 4:
        return None
    stamp, user, tty, cmd = parts
    cmd = cmd.strip()
    if not cmd:
        return None
    try:
        ts = datetime.fromisoformat(stamp)
        if ts.tzinfo:
            ts = ts.replace(tzinfo=None)
    except ValueError:
        ts = datetime.now()
    return CommandEvent(
        ts=ts,
        pid=0,
        ppid=0,
        uid=0,
        username=user,
        cmdline=cmd,
        tty=tty.replace("/dev/", ""),
        source="shell",
    )


def should_keep_typed(cmdline: str) -> bool:
    text = cmdline.strip()
    if not text:
        return False
    if any(text == prefix or text.startswith(prefix) for prefix in _SKIP_PREFIXES):
        return False
    fake = CommandEvent(
        ts=datetime.now(),
        pid=0,
        ppid=0,
        uid=0,
        username="",
        cmdline=text,
        source="shell",
    )
    return not _looks_like_noise(fake)


def history_paths_for(home: Path) -> list[Path]:
    return [
        home / ".zsh_history",
        home / ".bash_history",
        home / ".local/share/fish/fish_history",
    ]


def _homes() -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    try:
        me = getpass.getuser()
        found.append((me, Path.home()))
    except Exception:
        pass
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            for entry in pwd.getpwall():
                if entry.pw_uid < 1000 or not entry.pw_dir:
                    continue
                path = Path(entry.pw_dir)
                if (entry.pw_name, path) not in found and path.is_dir():
                    found.append((entry.pw_name, path))
        except Exception:
            pass
    return found


_BASH_HOOK = r"""# watchdogs-typed-commands
_watchdogs_typed() {
  local raw cmd
  raw=$(HISTTIMEFORMAT= builtin history 1 2>/dev/null) || return 0
  read -r _ cmd <<< "$raw"
  [ -n "$cmd" ] || return 0
  printf '%s|%s|%s|%s\n' "$(date -Iseconds 2>/dev/null || date)" "${USER:-unknown}" "${TTY#/dev/}" "$cmd" >> "__LOG__"
  builtin history -a 2>/dev/null || true
}
case ";${PROMPT_COMMAND:-};" in
  *"_watchdogs_typed"*) ;;
  *) PROMPT_COMMAND="_watchdogs_typed${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
"""

_ZSH_HOOK = r"""# watchdogs-typed-commands
_watchdogs_typed() {
  print -r -- "$(date -Iseconds 2>/dev/null || date)|${USER:-unknown}|${TTY#/dev/}|$1" >> "__LOG__"
}
typeset -ga preexec_functions
if [[ " ${preexec_functions[*]} " != *" _watchdogs_typed "* ]]; then
  preexec_functions+=(_watchdogs_typed)
fi
"""


def _bash_hook(log_path: Path) -> str:
    return _BASH_HOOK.replace("__LOG__", str(log_path))


def _zsh_hook(log_path: Path) -> str:
    return _ZSH_HOOK.replace("__LOG__", str(log_path))


def install_hooks(log_path: Path, hook_dir: Path) -> None:
    hook_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(exist_ok=True)
    bash = hook_dir / "watchdogs.bash"
    zsh = hook_dir / "watchdogs.zsh"
    bash.write_text(_bash_hook(log_path), encoding="utf-8")
    zsh.write_text(_zsh_hook(log_path), encoding="utf-8")
    for user, home in _homes():
        _ensure_source(home / ".bashrc", bash)
        _ensure_source(home / ".zshrc", zsh)
        _ = user


def _ensure_source(rc: Path, hook: Path) -> None:
    line = f'[ -f "{hook}" ] && . "{hook}"  # {_HOOK_MARK}\n'
    try:
        existing = rc.read_text(encoding="utf-8", errors="replace") if rc.is_file() else ""
        if _HOOK_MARK in existing:
            return
        with rc.open("a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write(line)
    except OSError:
        return


class _FileTail:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh = None
        self._inode: int | None = None

    def _open_end(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
        if not self.path.is_file():
            return
        self._fh = self.path.open("r", errors="replace")
        self._inode = self.path.stat().st_ino
        self._fh.seek(0, os.SEEK_END)

    def read_new_lines(self) -> list[str]:
        if self._fh is None:
            self._open_end()
            return []
        try:
            stat = self.path.stat()
        except OSError:
            return []
        if stat.st_ino != self._inode or stat.st_size < (self._fh.tell() if self._fh else 0):
            self._open_end()
            return []
        lines: list[str] = []
        while True:
            pos = self._fh.tell()
            line = self._fh.readline()
            if not line:
                break
            if not line.endswith("\n"):
                self._fh.seek(pos)
                break
            text = line.rstrip("\n")
            if text.strip():
                lines.append(text)
        return lines


class ShellCommandCollector:
    """Typed command lines from a shell hook and history files (not keystrokes)."""

    def __init__(self, emit: EmitFn, data_dir: Path) -> None:
        self.emit = emit
        self.data_dir = Path(data_dir)
        self.log_path = self.data_dir / "typed-commands.log"
        self.hook_dir = self.data_dir / "hooks"
        self._seen: list[tuple[str, str, float]] = []

    def _remember(self, user: str, cmd: str) -> bool:
        now = datetime.now().timestamp()
        self._seen = [item for item in self._seen if now - item[2] < 4]
        key = (user, cmd)
        if any(item[0] == key[0] and item[1] == key[1] for item in self._seen):
            return False
        self._seen.append((user, cmd, now))
        return True

    def _emit(self, event: CommandEvent) -> None:
        if not should_keep_typed(event.cmdline):
            return
        if not self._remember(event.username, event.cmdline):
            return
        self.emit("command", event)

    def run(self, stop: threading.Event) -> None:
        write_rc = not os.environ.get("PYTEST_CURRENT_TEST")
        if write_rc:
            install_hooks(self.log_path, self.hook_dir)
        else:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self.log_path.touch(exist_ok=True)
        tails: list[tuple[_FileTail, str, str]] = [(_FileTail(self.log_path), "typed", getpass.getuser())]
        for user, home in _homes():
            for path in history_paths_for(home):
                tails.append((_FileTail(path), path.name, user))
        while not stop.is_set():
            for tail, kind, user in tails:
                for line in tail.read_new_lines():
                    event = self._line_to_event(line, kind, user)
                    if event is not None:
                        self._emit(event)
            stop.wait(0.35)

    def _line_to_event(self, line: str, kind: str, user: str) -> CommandEvent | None:
        if kind == "typed":
            return parse_typed_log_line(line)
        if kind == "fish_history":
            text = line.strip()
            if text.startswith("- cmd:"):
                cmd = text.split(":", 1)[1].strip()
            else:
                return None
            ts = datetime.now()
        elif kind == ".zsh_history" or kind.endswith("zsh_history"):
            ts, cmd = parse_zsh_history_line(line)
            ts = ts or datetime.now()
        else:
            cmd = line.strip()
            ts = datetime.now()
        if not cmd:
            return None
        return CommandEvent(
            ts=ts,
            pid=0,
            ppid=0,
            uid=0,
            username=user,
            cmdline=cmd,
            source="shell",
        )
