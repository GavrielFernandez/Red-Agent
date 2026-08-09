"""Lightweight sqlite persistence for tool runs and findings."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, Optional
import json
import sqlite3

_DB_PATH: Optional[Path] = None
_DB_LOCK = Lock()


def init_runtime_store(db_path: str | Path) -> None:
    """Initialize the sqlite database and create tables if needed."""
    global _DB_PATH
    _DB_PATH = Path(db_path)
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with _get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                target TEXT,
                params_json TEXT NOT NULL,
                status TEXT,
                return_code INTEGER,
                execution_time REAL,
                stdout TEXT,
                stderr TEXT,
                metadata_json TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                assessment_job_id TEXT,
                target TEXT,
                finding_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


def persist_tool_run(
    *,
    tool_name: str,
    target: str,
    params: Dict[str, Any],
    result: Dict[str, Any],
    source: str,
) -> None:
    """Store a tool execution result in sqlite."""
    with _DB_LOCK:
        with _get_connection() as conn:
            conn.execute(
                """
                INSERT INTO tool_runs (
                    created_at, source, tool_name, target,
                    params_json, status, return_code, execution_time,
                    stdout, stderr, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now().isoformat(),
                    source,
                    tool_name,
                    target,
                    json.dumps(params, default=str),
                    str(result.get("status", "unknown")),
                    int(result.get("return_code", -1) or -1),
                    float(result.get("execution_time", 0) or 0),
                    str(result.get("stdout", ""))[:20000],
                    str(result.get("stderr", ""))[:8000],
                    json.dumps(result.get("metadata", {}), default=str),
                ),
            )
            conn.commit()


def persist_findings(
    *,
    source: str,
    tool_name: str,
    assessment_job_id: Optional[str],
    target: str,
    findings: Iterable[Dict[str, Any]],
) -> None:
    """Store findings for later review and dashboard history."""
    rows = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        rows.append(
            (
                datetime.now().isoformat(),
                source,
                tool_name,
                assessment_job_id,
                target,
                json.dumps(finding, default=str),
            )
        )

    if not rows:
        return

    with _DB_LOCK:
        with _get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO findings (
                    created_at, source, tool_name, assessment_job_id, target, finding_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()


def get_runtime_counts() -> Dict[str, int]:
    """Return durable storage counts for dashboard health summaries."""
    with _get_connection() as conn:
        tool_runs = conn.execute("SELECT COUNT(*) AS count FROM tool_runs").fetchone()["count"]
        findings = conn.execute("SELECT COUNT(*) AS count FROM findings").fetchone()["count"]
    return {"tool_runs": int(tool_runs or 0), "findings": int(findings or 0)}


def get_recent_tool_runs(limit: int = 20) -> list[Dict[str, Any]]:
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM tool_runs ORDER BY id DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
    return [dict(row) for row in rows]


def get_recent_findings(limit: int = 20) -> list[Dict[str, Any]]:
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY id DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
    return [dict(row) for row in rows]


def _get_connection() -> sqlite3.Connection:
    if _DB_PATH is None:
        default_path = Path("logs") / "redagent_runtime.db"
        init_runtime_store(default_path)
    assert _DB_PATH is not None
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
