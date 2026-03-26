from __future__ import annotations

"""
Main orchestrator with concurrent worker pool.

Pipeline:
  1. Poll PyPI/npm for new releases
  2. For each release, compute priority score (fast — 2µs)
  3. If score > threshold, enqueue in priority queue
  4. Worker pool (N threads) drains queue highest-priority-first
  5. Each worker: download (cached) → diff → analyze → classify → store
  6. Backpressure: if queue > max_size, drop lowest-priority tasks

Metrics tracked:
  - Queue: enqueued, dropped, processed, peak size, avg wait
  - Download: cache hits/misses, saved bytes
  - Workers: active count, total analysis time
"""

import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime

from config import POLL_INTERVAL, SCORE_THRESHOLD
from storage import db as store
from storage.models import ReleaseEvent
from ingestion import pypi, npm, wordpress
from graph.dependency_graph import graph
from scoring.scorer import compute_priority_score, should_analyze
from task_queue.analysis_queue import AnalysisTask, analysis_queue
from analysis.differ import analyze_package
from analysis.detonator import enqueue_detonation, stop_dyana_worker, dyana_queue_size, DYANA_ENABLED
from ai.classifier import classify_with_ai
from alerts import should_alert, send_alert

AI_CLASSIFICATION_THRESHOLD = 30
NUM_WORKERS = 6


# ---------------------------------------------------------------------------
# Worker metrics
# ---------------------------------------------------------------------------

@dataclass
class WorkerMetrics:
    active_workers: int = 0
    total_download_ms: float = 0.0
    total_analysis_ms: float = 0.0
    packages_analyzed: int = 0
    packages_failed: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, download_ms: float, analysis_ms: float, success: bool):
        with self._lock:
            self.total_download_ms += download_ms
            self.total_analysis_ms += analysis_ms
            if success:
                self.packages_analyzed += 1
            else:
                self.packages_failed += 1

    def enter(self):
        with self._lock:
            self.active_workers += 1

    def exit(self):
        with self._lock:
            self.active_workers -= 1

    @property
    def avg_download_ms(self) -> float:
        n = self.packages_analyzed + self.packages_failed
        return self.total_download_ms / n if n else 0.0

    @property
    def avg_analysis_ms(self) -> float:
        n = self.packages_analyzed
        return self.total_analysis_ms / n if n else 0.0


worker_metrics = WorkerMetrics()


# ---------------------------------------------------------------------------
# Single worker — processes one task
# ---------------------------------------------------------------------------

def _worker_analyze(task: AnalysisTask):
    """Run full analysis pipeline for one task. Called by worker pool."""
    worker_metrics.enter()
    try:
        t_start = time.perf_counter()

        report = analyze_package(
            task.package_name, task.ecosystem,
            task.new_version, task.old_version,
        )

        t_analysis = time.perf_counter()

        # AI classification if suspicious
        if report.risk_score >= AI_CLASSIFICATION_THRESHOLD:
            classification, reason = classify_with_ai(report)
            report.ai_classification = classification
            report.summary += f" | AI: {classification} — {reason}"
            print(f"  [ai] {task.ecosystem}/{task.package_name} → {classification}: {reason}")

        store.save_diff_report(report)

        # If AI says suspicious/malicious and dyana is enabled, queue for detonation
        # Runs in background thread, worker continues immediately
        if DYANA_ENABLED and report.ai_classification in ("suspicious", "malicious"):
            enqueue_detonation(
                task.package_name, task.ecosystem, task.new_version,
                report.risk_score, report.ai_classification,
            )
        store.mark_event_processed(task.package_name, task.ecosystem, task.new_version)

        t_done = time.perf_counter()
        dl_ms = (t_analysis - t_start) * 1000
        an_ms = (t_done - t_start) * 1000
        worker_metrics.record(dl_ms, an_ms, True)

        if report.risk_score > 0:
            print(f"  [worker] {task.ecosystem}/{task.package_name} "
                  f"{task.old_version}→{task.new_version} "
                  f"score={report.risk_score} ({an_ms:.0f}ms)")

            # Alert only if AI says suspicious/malicious (or no AI and score high)
            ai = report.ai_classification
            if should_alert(report.risk_score) and ai != "benign":
                rd = report.to_dict()
                send_alert(
                    package_name=task.package_name,
                    ecosystem=task.ecosystem,
                    version=task.new_version,
                    previous_version=task.old_version,
                    risk_score=report.risk_score,
                    summary=report.summary,
                    ai_classification=report.ai_classification,
                    flags=rd.get("flags"),
                    features=rd.get("features"),
                )
        else:
            print(f"  [worker] {task.ecosystem}/{task.package_name} — clean ({an_ms:.0f}ms)")

    except Exception as e:
        worker_metrics.record(0, 0, False)
        print(f"  [worker] FAIL {task.package_name}: {e}")
    finally:
        worker_metrics.exit()


# ---------------------------------------------------------------------------
# Worker pool — drains the priority queue with N threads
# ---------------------------------------------------------------------------

def run_worker_pool(num_workers: int = NUM_WORKERS, drain: bool = False):
    """
    Start worker pool. Each worker blocks on queue.dequeue().

    Args:
        num_workers: concurrent workers
        drain: if True, run until queue is empty then stop
    """
    with ThreadPoolExecutor(max_workers=num_workers, thread_name_prefix="sent-worker") as pool:
        if drain:
            # Submit all current tasks
            while True:
                task = analysis_queue.dequeue_nowait()
                if task is None:
                    break
                pool.submit(_worker_analyze, task)
        else:
            # Continuous mode — workers block waiting for tasks
            def _worker_loop():
                while True:
                    task = analysis_queue.dequeue(timeout=2.0)
                    if task is None:
                        return
                    _worker_analyze(task)

            futures = [pool.submit(_worker_loop) for _ in range(num_workers)]
            for f in futures:
                f.result()


# ---------------------------------------------------------------------------
# Release processing (scoring + enqueue)
# ---------------------------------------------------------------------------

def process_release(event: ReleaseEvent):
    """Score a release and enqueue if high-priority. No downloading here."""
    name = event.package_name
    eco = event.ecosystem

    if eco == "pypi":
        pkg_info = pypi.fetch_package_info(name)
        prev_version = pypi.get_previous_version(name, event.version)
    elif eco == "npm":
        pkg_info = npm.fetch_package_info(name)
        prev_version = npm.get_previous_version(name, event.version)
    elif eco == "wordpress":
        pkg_info = wordpress.fetch_package_info(name)
        prev_version = wordpress.get_previous_version(name, event.version)
    else:
        return

    downloads = 0
    if pkg_info:
        downloads = pkg_info.downloads
        graph.add_package(name, eco, pkg_info.direct_deps, downloads)
        store.upsert_package(pkg_info)

    do_analyze, score = should_analyze(name, eco, downloads)
    event.previous_version = prev_version

    is_new = store.insert_release_event(event)
    if not is_new:
        return

    print(f"  [{eco}] {name} {prev_version} → {event.version}  "
          f"score={score:.1f} {'→ QUEUE' if do_analyze else '→ skip'}")

    if do_analyze:
        task = AnalysisTask.create(
            package_name=name,
            ecosystem=eco,
            new_version=event.version,
            old_version=prev_version,
            priority_score=score,
        )
        analysis_queue.enqueue(task)


# ---------------------------------------------------------------------------
# Polling + dispatch
# ---------------------------------------------------------------------------

def poll_once(ecosystems: list[str] | None = None):
    """Run one polling cycle: ingest → score → enqueue → drain queue."""
    if ecosystems is None:
        ecosystems = ["pypi", "npm", "wordpress"]

    events = []
    if "pypi" in ecosystems:
        events.extend(pypi.fetch_recent_releases())
    if "wordpress" in ecosystems:
        events.extend(wordpress.fetch_recent_releases())
    if "npm" in ecosystems:
        events.extend(npm.fetch_recent_releases())

    if not events:
        print("[poll] No new releases found")
        return

    print(f"[poll] Found {len(events)} releases")

    for event in events:
        try:
            process_release(event)
        except Exception as e:
            print(f"  [error] {event.package_name}: {e}")

    # Drain queue with worker pool
    queue_size = analysis_queue.size()
    if queue_size > 0:
        print(f"\n[pool] Draining {queue_size} tasks with {NUM_WORKERS} workers...")
        run_worker_pool(num_workers=NUM_WORKERS, drain=True)
        _print_metrics()


def _print_metrics():
    """Print current metrics snapshot and persist to DB."""
    qm = analysis_queue.metrics
    wm = worker_metrics

    from analysis.download_cache import cache_metrics as cm

    print(f"\n[metrics] Queue: {qm.enqueued} enqueued, {qm.dropped} dropped, "
          f"{qm.processed} processed, peak={qm.peak_size}, "
          f"avg_wait={qm.avg_wait_ms:.0f}ms")
    print(f"[metrics] Workers: {wm.packages_analyzed} ok, {wm.packages_failed} failed, "
          f"avg_total={wm.avg_analysis_ms:.0f}ms")
    print(f"[metrics] Cache: {cm.hits} hits, {cm.misses} misses, "
          f"rate={cm.hit_rate:.0%}, saved={cm.bytes_saved / 1024 / 1024:.1f}MB")

    # Persist to DB so `cli.py metrics` can read from another process
    _save_metrics_to_db(qm, wm, cm)


def _save_metrics_to_db(qm, wm, cm):
    import json
    from datetime import datetime
    from storage.db import db
    try:
        with db() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS runtime_metrics (
                key TEXT PRIMARY KEY,
                data TEXT,
                updated_at TEXT
            )""")
            metrics = {
                "queue_enqueued": qm.enqueued,
                "queue_dropped": qm.dropped,
                "queue_processed": qm.processed,
                "queue_peak": qm.peak_size,
                "queue_avg_wait_ms": round(qm.avg_wait_ms),
                "workers_analyzed": wm.packages_analyzed,
                "workers_failed": wm.packages_failed,
                "workers_avg_ms": round(wm.avg_analysis_ms),
                "workers_active": wm.active_workers,
                "cache_hits": cm.hits,
                "cache_misses": cm.misses,
                "cache_hit_rate": round(cm.hit_rate, 2),
                "cache_bytes_saved": cm.bytes_saved,
                "dyana_queue": dyana_queue_size(),
            }
            conn.execute(
                "INSERT OR REPLACE INTO runtime_metrics (key, data, updated_at) VALUES (?, ?, ?)",
                ("latest", json.dumps(metrics), datetime.utcnow().isoformat()),
            )
    except Exception:
        pass


def load_metrics_from_db() -> dict:
    """Load persisted metrics (called from CLI)."""
    import json
    from storage.db import db
    try:
        with db() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS runtime_metrics (
                key TEXT PRIMARY KEY, data TEXT, updated_at TEXT
            )""")
            row = conn.execute(
                "SELECT data, updated_at FROM runtime_metrics WHERE key='latest'"
            ).fetchone()
            if row:
                m = json.loads(row["data"])
                m["updated_at"] = row["updated_at"]
                return m
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Daemon mode
# ---------------------------------------------------------------------------

def run_daemon(ecosystems: list[str] | None = None):
    """Continuous polling with worker pool."""
    print(f"[sent] Starting daemon (poll every {POLL_INTERVAL}s, "
          f"threshold={SCORE_THRESHOLD}, workers={NUM_WORKERS})")
    print(f"[sent] Ecosystems: {ecosystems or ['pypi', 'npm', 'wordpress']}")
    print(f"[sent] Press Ctrl+C to stop\n")

    store.init_db()

    # Load persisted graph or bootstrap
    if not graph.load_from_db():
        print("[sent] No graph found — run `sent bootstrap` first for best results")
        print("[sent] Continuing with empty graph (scores based on own downloads only)\n")

    while True:
        try:
            poll_once(ecosystems)
            print(f"\n[poll] Sleeping {POLL_INTERVAL}s...")
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            print("\n[sent] Shutting down workers...")
            analysis_queue.shutdown()
            stop_dyana_worker()
            _print_metrics()
            print("[sent] Done.")
            break


# ---------------------------------------------------------------------------
# Single-package analysis (CLI)
# ---------------------------------------------------------------------------

def analyze_single(name: str, ecosystem: str, version: str = "",
                   old_version: str = "", ai_backend: str = ""):
    """Analyze a single package on demand (bypasses scoring)."""
    store.init_db()

    if ecosystem == "pypi":
        pkg = pypi.fetch_package_info(name)
        if not version and pkg:
            version = pkg.latest_version
        if not old_version:
            old_version = pypi.get_previous_version(name, version)
    elif ecosystem == "npm":
        pkg = npm.fetch_package_info(name)
        if not version and pkg:
            version = pkg.latest_version
        if not old_version:
            old_version = npm.get_previous_version(name, version)
    elif ecosystem == "wordpress":
        pkg = wordpress.fetch_package_info(name)
        if not version and pkg:
            version = pkg.latest_version
        if not old_version:
            old_version = wordpress.get_previous_version(name, version)
    else:
        pkg = None

    if pkg:
        graph.add_package(name, ecosystem, pkg.direct_deps)
        store.upsert_package(pkg)

    print(f"[analyze] {ecosystem}/{name} {old_version} → {version}")

    report = analyze_package(name, ecosystem, version, old_version)

    if report.risk_score > 0:
        classification, reason = classify_with_ai(report, backend=ai_backend)
        report.ai_classification = classification
        report.summary += f" | AI: {classification} — {reason}"

    store.save_diff_report(report)

    # Alert only if not benign
    if should_alert(report.risk_score) and report.ai_classification != "benign":
        rd = report.to_dict()
        send_alert(
            package_name=name, ecosystem=ecosystem,
            version=version, previous_version=old_version,
            risk_score=report.risk_score, summary=report.summary,
            ai_classification=report.ai_classification,
            flags=rd.get("flags"), features=rd.get("features"),
        )

    return report
