from __future__ import annotations

"""
Per-package behavioral baseline.

Tracks what a package NORMALLY does across versions:
  - does it use networking? (requests, urllib, etc.)
  - does it call exec/eval?
  - does it access env vars?
  - does it use subprocess?

When analyzing a new version, we compare the extracted features
against the baseline. A behavior that was ALREADY PRESENT in previous
versions is not suspicious — only NEW behaviors are anomalies.

This eliminates the main source of false positives: flagging things
that are normal for the package's domain.
"""

import json
from dataclasses import dataclass, field, asdict
from typing import Dict, Set

from storage.db import db


@dataclass
class PackageBaseline:
    """What this package is known to do across all analyzed versions."""
    uses_network: bool = False
    uses_exec: bool = False
    uses_env: bool = False
    uses_subprocess: bool = False
    uses_file_io: bool = False
    uses_crypto: bool = False
    uses_obfuscation: bool = False
    uses_dynamic_attrs: bool = False
    known_imports: Set[str] = field(default_factory=set)
    known_calls: Set[str] = field(default_factory=set)
    versions_analyzed: int = 0

    def to_json(self) -> str:
        d = asdict(self)
        d["known_imports"] = sorted(d["known_imports"])
        d["known_calls"] = sorted(d["known_calls"])
        return json.dumps(d)

    @classmethod
    def from_json(cls, s: str) -> PackageBaseline:
        d = json.loads(s)
        d["known_imports"] = set(d.get("known_imports", []))
        d["known_calls"] = set(d.get("known_calls", []))
        return cls(**d)


def init_baseline_table():
    """Create baseline table if it doesn't exist."""
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS package_baselines (
                name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                baseline TEXT DEFAULT '{}',
                updated_at TEXT DEFAULT '',
                PRIMARY KEY (name, ecosystem)
            )
        """)


def load_baseline(name: str, ecosystem: str) -> PackageBaseline:
    """Load the behavioral baseline for a package. Returns empty if none exists."""
    with db() as conn:
        row = conn.execute(
            "SELECT baseline FROM package_baselines WHERE name=? AND ecosystem=?",
            (name, ecosystem),
        ).fetchone()
        if row and row["baseline"]:
            try:
                return PackageBaseline.from_json(row["baseline"])
            except Exception:
                pass
    return PackageBaseline()


def save_baseline(name: str, ecosystem: str, baseline: PackageBaseline):
    """Persist updated baseline."""
    from datetime import datetime
    with db() as conn:
        conn.execute(
            """INSERT INTO package_baselines (name, ecosystem, baseline, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(name, ecosystem) DO UPDATE SET
                   baseline=excluded.baseline, updated_at=excluded.updated_at""",
            (name, ecosystem, baseline.to_json(), datetime.utcnow().isoformat()),
        )


def update_baseline_from_behavior(
    baseline: PackageBaseline,
    imports: set,
    calls: set,
    attribute_access: set,
) -> PackageBaseline:
    """
    Evolve the baseline with the FULL behavior of the current version.
    This is called AFTER analysis, so next time we won't flag the same behaviors.
    """
    from analysis.ast_analyzer import BehaviorExtractor

    net_modules = BehaviorExtractor.NETWORK_MODULES
    if imports & net_modules:
        baseline.uses_network = True
    if any(c in calls for c in ("eval", "exec", "compile")):
        baseline.uses_exec = True
    if any("environ" in a or "getenv" in a for a in attribute_access | calls):
        baseline.uses_env = True
    if any(c.startswith("subprocess.") or c in ("os.system", "os.popen") for c in calls):
        baseline.uses_subprocess = True
    if any(c in ("open", "builtins.open") for c in calls):
        baseline.uses_file_io = True
    if imports & BehaviorExtractor.CRYPTO_MODULES:
        baseline.uses_crypto = True
    if any(c in calls for c in BehaviorExtractor.OBFUSCATION_CALLS):
        baseline.uses_obfuscation = True
    if any(c in calls for c in ("getattr", "setattr", "delattr")):
        baseline.uses_dynamic_attrs = True

    baseline.known_imports |= imports
    # Only track the top-level call names to keep baseline compact
    baseline.known_calls |= {c.split(".")[0] for c in calls}
    baseline.versions_analyzed += 1

    return baseline


@dataclass
class AnomalyReport:
    """What changed relative to the baseline."""
    new_network: bool = False        # package didn't use network before
    new_exec: bool = False           # package didn't use exec/eval before
    new_env_access: bool = False     # package didn't read env vars before
    new_subprocess: bool = False     # package didn't shell out before
    new_file_io: bool = False        # package didn't do file I/O before
    new_obfuscation: bool = False    # package didn't use encoding/decoding before
    new_dynamic_attrs: bool = False  # package didn't use getattr/setattr before
    novel_imports: Set[str] = field(default_factory=set)  # imports never seen before
    anomaly_count: int = 0           # total number of anomalies

    def to_dict(self) -> Dict[str, object]:
        d = asdict(self)
        d["novel_imports"] = sorted(d["novel_imports"])
        return d


def detect_anomalies(
    baseline: PackageBaseline,
    features: "BehaviorFeatures",
    new_imports: set,
) -> AnomalyReport:
    """
    Compare extracted features against the package baseline.
    Returns anomalies — behaviors that are NEW for this package.
    """
    from analysis.feature_extractor import BehaviorFeatures

    a = AnomalyReport()

    if features.new_network_imports > 0 and not baseline.uses_network:
        a.new_network = True
        a.anomaly_count += 1

    if features.new_exec_calls > 0 and not baseline.uses_exec:
        a.new_exec = True
        a.anomaly_count += 1

    if features.new_env_access > 0 and not baseline.uses_env:
        a.new_env_access = True
        a.anomaly_count += 1

    if features.new_subprocess_calls > 0 and not baseline.uses_subprocess:
        a.new_subprocess = True
        a.anomaly_count += 1

    if features.new_file_access > 0 and not baseline.uses_file_io:
        a.new_file_io = True
        a.anomaly_count += 1

    if features.new_obfuscation_calls > 0 and not baseline.uses_obfuscation:
        a.new_obfuscation = True
        a.anomaly_count += 1

    if features.new_dynamic_attrs > 0 and not baseline.uses_dynamic_attrs:
        a.new_dynamic_attrs = True
        a.anomaly_count += 1

    # Imports the package has never used in any previous version
    a.novel_imports = new_imports - baseline.known_imports
    if a.novel_imports:
        a.anomaly_count += 1

    return a
