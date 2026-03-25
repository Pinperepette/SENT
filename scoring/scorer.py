from __future__ import annotations

"""
Priority scoring based on cascade weight.

Old formula:  score = log(downloads + 1) + alpha * downstream_count
New formula:  score = log(cascade_weight + 1)

Where cascade_weight = own_downloads + sum(cascade_weight of all dependents).

This means:
  - urllib3 (100 own dl) depended on by requests (50M dl)
    → cascade_weight ≈ 50M → score ≈ 17.7 → ANALYZE
  - random-pkg (100 own dl) depended on by nobody
    → cascade_weight = 100 → score ≈ 4.6 → SKIP

The cascade weight captures the true impact: if urllib3 is compromised,
every requests user is affected. The score reflects that.
"""

import math

from config import SCORE_THRESHOLD
from graph.dependency_graph import graph


def compute_priority_score(
    name: str,
    ecosystem: str,
    downloads: int = 0,
    downstream_override: int | None = None,
) -> float:
    """
    Compute priority score based on cascade weight.

    Falls back to own downloads if package is not in the graph yet.
    """
    # Try cascade weight first (captures transitive impact)
    cw = graph.cascade_weight(name, ecosystem)

    if cw > 0:
        # Package is in graph — use cascade weight
        score = math.log(cw + 1)
    else:
        # Not in graph — fall back to own downloads
        # (will be added to graph when we fetch its info)
        score = math.log(max(downloads, 0) + 1)

    return round(score, 2)


def should_analyze(
    name: str,
    ecosystem: str,
    downloads: int = 0,
    threshold: float | None = None,
) -> tuple:
    """
    Decide if a package release should be queued for analysis.
    Returns (should_analyze, score).
    """
    score = compute_priority_score(name, ecosystem, downloads)
    t = threshold if threshold is not None else SCORE_THRESHOLD
    return score >= t, score
