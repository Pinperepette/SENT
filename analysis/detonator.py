from __future__ import annotations

"""
Dynamic analysis via dyana, with background queue.

Flow:
  Worker finds suspicious package → enqueue_detonation() → worker continues
  Background thread picks from queue → detonate() → save result → next

Dyana runs one at a time in its own thread. Never blocks the main workers.
"""

import json
import os
import queue
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import List


DYANA_ENABLED = os.environ.get("SENT_DYANA", "0") == "1"


def dyana_available() -> bool:
    return shutil.which("dyana") is not None


def docker_running() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


@dataclass
class DyanaReport:
    package_name: str
    version: str
    success: bool = False
    network_activity: list = field(default_factory=list)
    filesystem_activity: list = field(default_factory=list)
    security_events: list = field(default_factory=list)
    raw_output: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "package": self.package_name,
            "version": self.version,
            "success": self.success,
            "network_activity": self.network_activity,
            "filesystem_activity": self.filesystem_activity,
            "security_events": self.security_events,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Background detonation queue
# ---------------------------------------------------------------------------

@dataclass
class DetonationTask:
    package_name: str
    ecosystem: str
    version: str
    risk_score: int
    ai_classification: str


_dyana_queue: queue.Queue = queue.Queue(maxsize=50)
_dyana_thread: threading.Thread | None = None
_dyana_running = False


def enqueue_detonation(
    package_name: str,
    ecosystem: str,
    version: str,
    risk_score: int,
    ai_classification: str,
):
    """Add a package to the dyana queue. Non-blocking. Drops if queue is full."""
    if not DYANA_ENABLED:
        return

    task = DetonationTask(
        package_name=package_name,
        ecosystem=ecosystem,
        version=version,
        risk_score=risk_score,
        ai_classification=ai_classification,
    )
    try:
        _dyana_queue.put_nowait(task)
        print(f"  [dyana] Queued {ecosystem}/{package_name}=={version} "
              f"(score={risk_score}, ai={ai_classification})")
    except queue.Full:
        print(f"  [dyana] Queue full, skipping {package_name}")

    _ensure_dyana_thread()


def _ensure_dyana_thread():
    """Start the background dyana thread if not already running."""
    global _dyana_thread, _dyana_running
    if _dyana_thread is not None and _dyana_thread.is_alive():
        return

    _dyana_running = True
    _dyana_thread = threading.Thread(target=_dyana_worker, daemon=True, name="dyana-worker")
    _dyana_thread.start()


def _dyana_worker():
    """Background thread: detonates one package at a time."""
    global _dyana_running

    if not dyana_available():
        print("[dyana] dyana not installed, background worker stopping")
        _dyana_running = False
        return

    if not docker_running():
        print("[dyana] Docker not running, background worker stopping")
        _dyana_running = False
        return

    print("[dyana] Background worker started (one at a time)")

    while _dyana_running:
        try:
            task = _dyana_queue.get(timeout=10)
        except queue.Empty:
            continue

        print(f"\n  [dyana] Detonating {task.ecosystem}/{task.package_name}=={task.version}...")
        report = detonate(task.package_name, task.version)

        # Save result to DB
        _save_dyana_result(task, report)

        if report.success:
            print(f"  [dyana] {task.package_name}: "
                  f"net={len(report.network_activity)} "
                  f"fs={len(report.filesystem_activity)} "
                  f"sec={len(report.security_events)}")
            if report.security_events:
                print(f"  [dyana] SECURITY EVENTS:")
                for ev in report.security_events[:5]:
                    print(f"    {ev}")
        else:
            print(f"  [dyana] {task.package_name}: {report.error[:100]}")

        _dyana_queue.task_done()

    print("[dyana] Background worker stopped")


def stop_dyana_worker():
    """Signal the dyana worker to stop."""
    global _dyana_running
    _dyana_running = False


def dyana_queue_size() -> int:
    return _dyana_queue.qsize()


# ---------------------------------------------------------------------------
# Core detonation (unchanged, called by the background thread)
# ---------------------------------------------------------------------------

def detonate(package_name: str, version: str, timeout: int = 300) -> DyanaReport:
    """Run dyana on a package. Called by background thread."""
    report = DyanaReport(package_name=package_name, version=version)

    pkg_spec = f"{package_name}=={version}" if version else package_name

    try:
        result = subprocess.run(
            ["dyana", "trace", "--loader", "pip", "--package", pkg_spec],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        report.raw_output = result.stdout + result.stderr

        if result.returncode == 0:
            report.success = True
            _parse_dyana_output(report, result.stdout)
        else:
            report.error = result.stderr[:500] if result.stderr else f"Exit code {result.returncode}"

    except subprocess.TimeoutExpired:
        report.error = f"Timeout after {timeout}s"
    except Exception as e:
        report.error = str(e)

    return report


def _parse_dyana_output(report: DyanaReport, output: str):
    for line in output.splitlines():
        line_lower = line.lower()
        if any(kw in line_lower for kw in ("connect", "dns", "http", "socket", "tcp", "udp")):
            report.network_activity.append(line.strip())
        elif any(kw in line_lower for kw in ("open", "write", "read", "unlink", "mkdir", "chmod")):
            report.filesystem_activity.append(line.strip())
        elif any(kw in line_lower for kw in ("exec", "ptrace", "mmap", "mprotect", "shell", "suspicious")):
            report.security_events.append(line.strip())


def _save_dyana_result(task: DetonationTask, report: DyanaReport):
    """Append dyana results to the existing diff report in DB."""
    try:
        from storage.db import db
        dyana_summary = ""
        if report.success:
            dyana_summary = (
                f" | Dyana: net={len(report.network_activity)}"
                f" fs={len(report.filesystem_activity)}"
                f" sec={len(report.security_events)}"
            )
        else:
            dyana_summary = f" | Dyana: {report.error[:80]}"

        with db() as conn:
            conn.execute(
                "UPDATE diff_reports SET summary = summary || ? "
                "WHERE package_name = ? AND ecosystem = ? AND version = ?",
                (dyana_summary, task.package_name, task.ecosystem, task.version),
            )
    except Exception as e:
        print(f"  [dyana] DB save error: {e}")
