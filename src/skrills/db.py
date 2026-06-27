from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .models import ScanResult, ScanSummary

DB_PATH = Path(os.environ.get("SKRILLS_DB", "./data/skrills.db"))


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                input_size INTEGER NOT NULL,
                ephemeral INTEGER NOT NULL DEFAULT 0,
                score INTEGER NOT NULL,
                severity_counts TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC);
            """
        )


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
               (id, created_at, input_hash, input_size, ephemeral, score, severity_counts, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result.id,
                result.created_at.isoformat(),
                result.input_hash,
                result.input_size,
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


def list_scans(limit: int = 25) -> list[ScanSummary]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, created_at, score, input_size, severity_counts FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        ScanSummary(
            id=r["id"],
            created_at=datetime.fromisoformat(r["created_at"]),
            score=r["score"],
            input_size=r["input_size"],
            severity_counts=json.loads(r["severity_counts"]),
        )
        for r in rows
    ]
