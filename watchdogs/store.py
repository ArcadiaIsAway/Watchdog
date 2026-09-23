"""SQLite + JSONL persistence for events, alerts, and known login sources."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from watchdogs.models import Alert, CommandEvent, LoginEvent


class Store:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.directory / "watchdogs.db", check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._events_log = self.directory / "events.jsonl"
        self._alerts_log = self.directory / "alerts.jsonl"
        self._init()

    def _init(self) -> None:
        with self._lock:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY,
                    kind TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY,
                    ts TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    message TEXT NOT NULL,
                    context TEXT NOT NULL,
                    acked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS known_sources (
                    username TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (username, source_ip)
                );
                """
            )
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def write_event(self, event: LoginEvent | CommandEvent) -> int:
        payload = event.to_dict()
        line = json.dumps(payload, default=str)
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO events (kind, ts, payload) VALUES (?, ?, ?)",
                (payload["kind"], payload["ts"], line),
            )
            self._db.commit()
            with self._events_log.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            return int(cur.lastrowid)

    def write_alert(self, alert: Alert) -> Alert:
        payload = alert.to_dict()
        line = json.dumps(payload, default=str)
        with self._lock:
            cur = self._db.execute(
                """
                INSERT INTO alerts (ts, severity, rule, message, context, acked)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["ts"],
                    alert.severity,
                    alert.rule,
                    alert.message,
                    json.dumps(alert.context, default=str),
                    1 if alert.acked else 0,
                ),
            )
            self._db.commit()
            alert.id = int(cur.lastrowid)
            payload["id"] = alert.id
            with self._alerts_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, default=str) + "\n")
        return alert

    def ack_alert(self, alert_id: int) -> None:
        with self._lock:
            self._db.execute("UPDATE alerts SET acked = 1 WHERE id = ?", (alert_id,))
            self._db.commit()

    def alert_count(self, unacked_only: bool = False) -> int:
        sql = "SELECT COUNT(*) FROM alerts"
        if unacked_only:
            sql += " WHERE acked = 0"
        with self._lock:
            row = self._db.execute(sql).fetchone()
        return int(row[0]) if row else 0

    def event_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._db.execute(
                "SELECT kind, COUNT(*) AS n FROM events GROUP BY kind"
            ).fetchall()
        return {str(r["kind"]): int(r["n"]) for r in rows}

    def note_source(self, username: str, source_ip: str, ts: datetime) -> bool:
        """Record a user/IP pair. Returns True if this pair is new."""
        stamp = ts.isoformat(timespec="seconds")
        with self._lock:
            row = self._db.execute(
                "SELECT username FROM known_sources WHERE username = ? AND source_ip = ?",
                (username, source_ip),
            ).fetchone()
            if row:
                self._db.execute(
                    "UPDATE known_sources SET last_seen = ? WHERE username = ? AND source_ip = ?",
                    (stamp, username, source_ip),
                )
                self._db.commit()
                return False
            self._db.execute(
                """
                INSERT INTO known_sources (username, source_ip, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                """,
                (username, source_ip, stamp, stamp),
            )
            self._db.commit()
            return True

    def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
