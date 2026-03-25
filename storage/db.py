from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from config import DB_PATH
from storage.models import DiffReport, Package, ReleaseEvent


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS packages (
                name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                latest_version TEXT DEFAULT '',
                downloads INTEGER DEFAULT 0,
                direct_deps TEXT DEFAULT '[]',
                updated_at TEXT DEFAULT '',
                PRIMARY KEY (name, ecosystem)
            );

            CREATE TABLE IF NOT EXISTS release_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                version TEXT NOT NULL,
                previous_version TEXT DEFAULT '',
                timestamp TEXT DEFAULT '',
                processed INTEGER DEFAULT 0,
                UNIQUE(package_name, ecosystem, version)
            );

            CREATE TABLE IF NOT EXISTS diff_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                version TEXT NOT NULL,
                previous_version TEXT DEFAULT '',
                risk_score INTEGER DEFAULT 0,
                flags TEXT DEFAULT '[]',
                files_added TEXT DEFAULT '[]',
                files_removed TEXT DEFAULT '[]',
                files_modified TEXT DEFAULT '[]',
                summary TEXT DEFAULT '',
                ai_classification TEXT DEFAULT '',
                timestamp TEXT DEFAULT '',
                UNIQUE(package_name, ecosystem, version)
            );

            CREATE INDEX IF NOT EXISTS idx_reports_score
                ON diff_reports(risk_score DESC);

            CREATE INDEX IF NOT EXISTS idx_events_processed
                ON release_events(processed);
        """)


def upsert_package(pkg: Package):
    with db() as conn:
        conn.execute(
            """INSERT INTO packages (name, ecosystem, latest_version, downloads, direct_deps, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(name, ecosystem) DO UPDATE SET
                   latest_version=excluded.latest_version,
                   downloads=excluded.downloads,
                   direct_deps=excluded.direct_deps,
                   updated_at=excluded.updated_at""",
            (pkg.name, pkg.ecosystem, pkg.latest_version, pkg.downloads,
             json.dumps(pkg.direct_deps), pkg.updated_at),
        )


def get_package(name: str, ecosystem: str) -> Package | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM packages WHERE name=? AND ecosystem=?", (name, ecosystem)
        ).fetchone()
        if not row:
            return None
        return Package(
            name=row["name"],
            ecosystem=row["ecosystem"],
            latest_version=row["latest_version"],
            downloads=row["downloads"],
            direct_deps=json.loads(row["direct_deps"]),
            updated_at=row["updated_at"],
        )


def insert_release_event(event: ReleaseEvent) -> bool:
    """Returns True if inserted, False if duplicate."""
    with db() as conn:
        try:
            conn.execute(
                """INSERT INTO release_events (package_name, ecosystem, version, previous_version, timestamp)
                   VALUES (?, ?, ?, ?, ?)""",
                (event.package_name, event.ecosystem, event.version,
                 event.previous_version, event.timestamp),
            )
            return True
        except sqlite3.IntegrityError:
            return False


def mark_event_processed(package_name: str, ecosystem: str, version: str):
    with db() as conn:
        conn.execute(
            "UPDATE release_events SET processed=1 WHERE package_name=? AND ecosystem=? AND version=?",
            (package_name, ecosystem, version),
        )


def save_diff_report(report: DiffReport):
    d = report.to_dict()
    with db() as conn:
        conn.execute(
            """INSERT INTO diff_reports
               (package_name, ecosystem, version, previous_version, risk_score,
                flags, files_added, files_removed, files_modified, summary,
                ai_classification, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(package_name, ecosystem, version) DO UPDATE SET
                   risk_score=excluded.risk_score, flags=excluded.flags,
                   summary=excluded.summary, ai_classification=excluded.ai_classification""",
            (report.package_name, report.ecosystem, report.version,
             report.previous_version, report.risk_score,
             json.dumps(d["flags"]), json.dumps(report.files_added),
             json.dumps(report.files_removed), json.dumps(report.files_modified),
             report.summary, report.ai_classification, report.timestamp),
        )


def get_top_risky(limit: int = 20) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM diff_reports ORDER BY risk_score DESC LIMIT ?", (limit,)
        ).fetchall()
        results = []
        for r in rows:
            results.append({
                "package": r["package_name"],
                "ecosystem": r["ecosystem"],
                "version": r["version"],
                "previous_version": r["previous_version"],
                "risk_score": r["risk_score"],
                "flags": json.loads(r["flags"]),
                "summary": r["summary"],
                "ai_classification": r["ai_classification"],
                "timestamp": r["timestamp"],
            })
        return results


def get_report(package_name: str, ecosystem: str, version: str = "") -> dict | None:
    with db() as conn:
        if version:
            row = conn.execute(
                "SELECT * FROM diff_reports WHERE package_name=? AND ecosystem=? AND version=?",
                (package_name, ecosystem, version),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM diff_reports WHERE package_name=? AND ecosystem=? ORDER BY timestamp DESC LIMIT 1",
                (package_name, ecosystem),
            ).fetchone()
        if not row:
            return None
        return {
            "package": row["package_name"],
            "ecosystem": row["ecosystem"],
            "version": row["version"],
            "previous_version": row["previous_version"],
            "risk_score": row["risk_score"],
            "flags": json.loads(row["flags"]),
            "files_added": json.loads(row["files_added"]),
            "files_removed": json.loads(row["files_removed"]),
            "files_modified": json.loads(row["files_modified"]),
            "summary": row["summary"],
            "ai_classification": row["ai_classification"],
            "timestamp": row["timestamp"],
        }
