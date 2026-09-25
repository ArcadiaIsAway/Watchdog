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
_SENTINEL_NAME = "typed.enabled"
_SENTINEL_MAX_AGE = 90


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
_watchdogs_alive() {
  local flag age now
  now=$(date +%s 2>/dev/null) || return 1
  for flag in /run/watchdogs/typed.enabled /var/lib/watchdogs/typed.enabled \
    "${XDG_DATA_HOME:-$HOME/.local/share}/watchdogs/typed.enabled"; do
    [ -f "$flag" ] || continue
    age=$(( now - $(stat -c %Y "$flag" 2>/dev/null || echo 0) ))
    [ "$age" -ge 0 ] && [ "$age" -lt 90 ] && return 0
  done
  return 1
}
_watchdogs_disable() {
  case ";${PROMPT_COMMAND:-};" in
    *"_watchdogs_typed"*)
      PROMPT_COMMAND="${PROMPT_COMMAND//_watchdogs_typed;/}"
      PROMPT_COMMAND="${PROMPT_COMMAND//;_watchdogs_typed/}"
      PROMPT_COMMAND="${PROMPT_COMMAND//_watchdogs_typed/}"
      ;;
  esac
  unset -f _watchdogs_typed 2>/dev/null
  unset -f _watchdogs_alive 2>/dev/null
  unset -f _watchdogs_disable 2>/dev/null
}
_watchdogs_typed() {
  local raw cmd logdir log
  if ! _watchdogs_alive; then
    _watchdogs_disable
    return 0
  fi
  logdir="${XDG_DATA_HOME:-$HOME/.local/share}/watchdogs"
  log="$logdir/typed-commands.log"
  mkdir -p "$logdir" 2>/dev/null || return 0
  raw=$(HISTTIMEFORMAT= builtin history 1 2>/dev/null) || return 0
  read -r _ cmd <<< "$raw"
  [ -n "$cmd" ] || return 0
  printf '%s|%s|%s|%s\n' "$(date -Iseconds 2>/dev/null || date)" "${USER:-unknown}" "${TTY#/dev/}" "$cmd" >> "$log" 2>/dev/null || return 0
  builtin history -a 2>/dev/null || true
}
if _watchdogs_alive; then
  case ";${PROMPT_COMMAND:-};" in
    *"_watchdogs_typed"*) ;;
    *) PROMPT_COMMAND="_watchdogs_typed${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
  esac
else
  _watchdogs_disable
fi
"""

_ZSH_HOOK = r"""# watchdogs-typed-commands
_watchdogs_alive() {
  local flag age now
  now=$(date +%s 2>/dev/null) || return 1
  for flag in /run/watchdogs/typed.enabled /var/lib/watchdogs/typed.enabled \
    "${XDG_DATA_HOME:-$HOME/.local/share}/watchdogs/typed.enabled"; do
    [ -f "$flag" ] || continue
    age=$(( now - $(stat -c %Y "$flag" 2>/dev/null || echo 0) ))
    [ "$age" -ge 0 ] && [ "$age" -lt 90 ] && return 0
  done
  return 1
}
_watchdogs_disable() {
  typeset -ga preexec_functions
  preexec_functions=(${preexec_functions:#_watchdogs_typed})
  unfunction _watchdogs_typed 2>/dev/null
  unfunction _watchdogs_alive 2>/dev/null
  unfunction _watchdogs_disable 2>/dev/null
}
_watchdogs_typed() {
  local logdir
  _watchdogs_alive || { _watchdogs_disable; return 0; }
  logdir="${XDG_DATA_HOME:-$HOME/.local/share}/watchdogs"
  mkdir -p "$logdir" 2>/dev/null || return 0
  print -r -- "$(date -Iseconds 2>/dev/null || date)|${USER:-unknown}|${TTY#/dev/}|$1" >> "$logdir/typed-commands.log" 2>/dev/null || return 0
}
if _watchdogs_alive; then
  typeset -ga preexec_functions
  if [[ " ${preexec_functions[*]} " != *" _watchdogs_typed "* ]]; then
    preexec_functions+=(_watchdogs_typed)
  fi
else
  _watchdogs_disable
fi
"""

_BASH_HOOK_OFF = r"""# watchdogs-typed-commands
_watchdogs_disable() {
  case ";${PROMPT_COMMAND:-};" in
    *"_watchdogs_typed"*)
      PROMPT_COMMAND="${PROMPT_COMMAND//_watchdogs_typed;/}"
      PROMPT_COMMAND="${PROMPT_COMMAND//;_watchdogs_typed/}"
      PROMPT_COMMAND="${PROMPT_COMMAND//_watchdogs_typed/}"
      ;;
  esac
  unset -f _watchdogs_typed 2>/dev/null
  unset -f _watchdogs_alive 2>/dev/null
  unset -f _watchdogs_disable 2>/dev/null
}
_watchdogs_disable
"""

_ZSH_HOOK_OFF = r"""# watchdogs-typed-commands
_watchdogs_disable() {
  typeset -ga preexec_functions
  preexec_functions=(${preexec_functions:#_watchdogs_typed})
  unfunction _watchdogs_typed 2>/dev/null
  unfunction _watchdogs_alive 2>/dev/null
  unfunction _watchdogs_disable 2>/dev/null
}
_watchdogs_disable
"""


def _bash_hook(log_path: Path | None = None) -> str:
    _ = log_path
    return _BASH_HOOK


def _zsh_hook(log_path: Path | None = None) -> str:
    _ = log_path
    return _ZSH_HOOK


def user_typed_log(home: Path) -> Path:
    return Path(home) / ".local/share/watchdogs" / "typed-commands.log"


def typed_log_paths(data_dir: Path) -> list[Path]:
    paths = [Path(data_dir) / "typed-commands.log"]
    for _user, home in _homes():
        paths.append(user_typed_log(home))
    unique: list[Path] = []
    for path in paths:
        if path not in unique:
            unique.append(path)
    return unique


def _hook_files(hook_dir: Path) -> tuple[Path, Path]:
    return Path(hook_dir) / "watchdogs.bash", Path(hook_dir) / "watchdogs.zsh"


def _write_hooks(hook_dir: Path, bash_text: str, zsh_text: str) -> None:
    hook_dir = Path(hook_dir)
    try:
        hook_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    bash, zsh = _hook_files(hook_dir)
    try:
        bash.write_text(bash_text, encoding="utf-8")
        zsh.write_text(zsh_text, encoding="utf-8")
        bash.chmod(0o644)
        zsh.chmod(0o644)
    except OSError:
        return


def sentinel_paths(data_dir: Path) -> list[Path]:
    paths = [
        Path("/run/watchdogs") / _SENTINEL_NAME,
        Path("/var/lib/watchdogs") / _SENTINEL_NAME,
        Path(data_dir) / _SENTINEL_NAME,
    ]
    unique: list[Path] = []
    for path in paths:
        if path not in unique:
            unique.append(path)
    return unique


def _write_sentinels(data_dir: Path) -> None:
    payload = f"{os.getpid()}\n"
    for path in sentinel_paths(data_dir):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
            path.chmod(0o644)
        except OSError:
            continue


def touch_typed_hooks(data_dir: Path) -> None:
    for path in sentinel_paths(data_dir):
        try:
            if path.is_file():
                path.touch()
        except OSError:
            continue


def enable_typed_hooks(
    data_dir: Path,
    hook_dir: Path | None = None,
    *,
    source_rc: bool = True,
) -> None:
    hook_dir = Path(hook_dir or Path(data_dir) / "hooks")
    _write_hooks(hook_dir, _BASH_HOOK, _ZSH_HOOK)
    _write_sentinels(data_dir)
    if not source_rc:
        return
    bash, zsh = _hook_files(hook_dir)
    for _user, home in _homes():
        _ensure_source(home / ".bashrc", bash)
        _ensure_source(home / ".zshrc", zsh)


def disable_typed_hooks(data_dir: Path, hook_dir: Path | None = None) -> None:
    """Turn hooks off. Other WatchDogs processes keep their own sentinel."""
    mine = str(os.getpid())
    leftover = False
    for path in sentinel_paths(data_dir):
        try:
            owner = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if owner and owner != mine:
            leftover = True
            continue
        try:
            path.unlink()
        except OSError:
            pass
    if leftover:
        return
    hook_dir = Path(hook_dir or Path(data_dir) / "hooks")
    _write_hooks(hook_dir, _BASH_HOOK_OFF, _ZSH_HOOK_OFF)


def install_hooks(log_path: Path, hook_dir: Path) -> None:
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        Path(log_path).touch(exist_ok=True)
    except OSError:
        pass
    enable_typed_hooks(Path(log_path).parent, hook_dir)


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
        tails: list[tuple[_FileTail, str, str]] = []
        seen_paths: set[Path] = set()
        last_touch = 0.0

        def _watch(path: Path, kind: str, user: str) -> None:
            if path in seen_paths:
                return
            seen_paths.add(path)
            tails.append((_FileTail(path), kind, user))

        try:
            while not stop.is_set():
                now = datetime.now().timestamp()
                if write_rc and now - last_touch >= 8:
                    touch_typed_hooks(self.data_dir)
                    last_touch = now
                for path in typed_log_paths(self.data_dir):
                    _watch(path, "typed", getpass.getuser())
                for user, home in _homes():
                    for path in history_paths_for(home):
                        _watch(path, path.name, user)
                for tail, kind, user in tails:
                    for line in tail.read_new_lines():
                        event = self._line_to_event(line, kind, user)
                        if event is not None:
                            self._emit(event)
                stop.wait(0.35)
        finally:
            if write_rc:
                disable_typed_hooks(self.data_dir, self.hook_dir)

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
