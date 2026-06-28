from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .models import ScanResult, ScanStatus, ScanSummary, SourceType

DB_PATH = Path(os.environ.get("SKRILLS_DB", "./data/skrills.db"))


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'complete',
                source_type TEXT NOT NULL DEFAULT 'paste',
                source_label TEXT NOT NULL DEFAULT '',
                input_hash TEXT NOT NULL,
                input_size INTEGER NOT NULL,
                file_count INTEGER NOT NULL DEFAULT 1,
                ephemeral INTEGER NOT NULL DEFAULT 0,
                score INTEGER NOT NULL DEFAULT 100,
                severity_counts TEXT NOT NULL DEFAULT '{}',
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC);
            """
        )
        # Lightweight migrations for existing v1 DBs
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
        for col, ddl in [
            ("status", "ALTER TABLE scans ADD COLUMN status TEXT NOT NULL DEFAULT 'complete'"),
            ("source_type", "ALTER TABLE scans ADD COLUMN source_type TEXT NOT NULL DEFAULT 'paste'"),
            ("source_label", "ALTER TABLE scans ADD COLUMN source_label TEXT NOT NULL DEFAULT ''"),
            ("file_count", "ALTER TABLE scans ADD COLUMN file_count INTEGER NOT NULL DEFAULT 1"),
        ]:
            if col not in cols:
                conn.execute(ddl)


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_scan(result: ScanResult) -> None:
    with connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scans
               (id, created_at, status, source_type, source_label,
                input_hash, input_size, file_count, ephemeral, score,
                severity_counts, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result.id,
                result.created_at.isoformat(),
                result.status.value,
                result.source_type.value,
                result.source_label,
                result.input_hash,
                result.input_size,
                result.file_count,
                int(result.ephemeral),
                result.score,
                json.dumps(result.severity_counts),
                result.model_dump_json(),
            ),
        )


def get_scan(scan_id: str) -> ScanResult | None:
    with connect() as conn:
        row = conn.execute("SELECT payload FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return ScanResult.model_validate_json(row["payload"])


def reap_stale_scans() -> int:
    """Fail scans left mid-flight (pending/running) by a previous process.

    In-process jobs do not survive a restart, so any row still marked pending or
    running is orphaned — its task is gone but the status page would poll it
    forever. Called on startup. Returns the number of rows updated.
    """
    stale = (ScanStatus.PENDING.value, ScanStatus.RUNNING.value)
    with connect() as conn:
        rows = conn.execute(
            "SELECT payload FROM scans WHERE status IN (?, ?)", stale
        ).fetchall()
    for row in rows:
        result = ScanResult.model_validate_json(row["payload"])
        result.status = ScanStatus.FAILED
        result.error = "scan interrupted by a server restart — re-run it"
        save_scan(result)
    return len(rows)


def list_scans(limit: int = 25) -> list[ScanSummary]:
    with connect() as conn:
        rows = conn.execute(
            """SELECT id, created_at, status, source_type, source_label,
                      score, input_size, file_count, severity_counts
               FROM scans ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [
        ScanSummary(
            id=r["id"],
            created_at=datetime.fromisoformat(r["created_at"]),
            status=ScanStatus(r["status"]),
            source_type=SourceType(r["source_type"]),
            source_label=r["source_label"],
            score=r["score"],
            input_size=r["input_size"],
            file_count=r["file_count"],
            severity_counts=json.loads(r["severity_counts"]),
        )
        for r in rows
    ]
