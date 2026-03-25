from __future__ import annotations

"""
Behavioral scoring system.

Replaces the old regex-based per-line scoring with a function:

    risk_score = f(features, anomalies)

Design principles:
  1. Individual features have base weights
  2. COMBINATIONS amplify non-linearly (exec + network >> exec alone)
  3. Anomalies (behavior never seen before) multiply the score
  4. Known behaviors (in baseline) get dampened

Scoring formula:

    base = sum(feature_i * weight_i)
    combo = combination_bonus(features)
    anomaly_mult = 1.0 + 0.5 * anomaly_count
    final = (base + combo) * anomaly_mult

The combination bonuses capture attacker patterns:
  - exec + network → remote code execution
  - env access + network → credential exfiltration
  - obfuscation + exec → payload delivery
  - sensitive paths + network → data theft
"""

import math
from typing import Dict

from analysis.feature_extractor import BehaviorFeatures
from analysis.baseline import AnomalyReport


# ---------------------------------------------------------------------------
# Base weights — applied to raw feature counts
# ---------------------------------------------------------------------------

FEATURE_WEIGHTS: Dict[str, float] = {
    # Network
    "new_network_imports":    6.0,
    "new_network_calls":      8.0,
    "new_external_urls":      3.0,

    # Execution
    "new_exec_calls":        15.0,
    "new_dynamic_imports":   12.0,
    "new_subprocess_calls":  10.0,

    # Sensitive access
    "new_file_access":        4.0,
    "new_env_access":        12.0,
    "new_sensitive_paths":   18.0,

    # Obfuscation
    "new_obfuscation_calls": 12.0,
    "new_encoded_strings":   10.0,
    "new_dynamic_attrs":      5.0,

    # Supply chain
    "setup_script_changed":   3.0,   # low by itself, amplified by combos
    "install_hooks_added":   20.0,
    "new_entry_points":       5.0,

    # Argument mutation (stealth attacks on existing behavior)
    "modified_network_targets": 25.0,   # URL changed to unknown domain
    "new_sensitive_data_flow":  35.0,   # sensitive source → network/subprocess
    "suspicious_argument_change": 8.0,  # any argument mutation in tracked call

    # Structural (low weight — context signal, not primary indicator)
    "new_try_except_blocks":  1.0,
    "new_imports_total":      0.5,
    "entropy_increase":       2.0,
}


# ---------------------------------------------------------------------------
# Combination bonuses — non-linear amplification for dangerous patterns
#
# Each tuple: (feature_a, feature_b, bonus_score, description)
# Bonus applies if BOTH features are nonzero.
# ---------------------------------------------------------------------------

COMBINATIONS = [
    # Remote code execution: exec + network
    ("new_exec_calls", "new_network_calls", 30.0,
     "exec/eval + network calls → possible RCE"),
    ("new_exec_calls", "new_network_imports", 25.0,
     "exec/eval + network imports → possible RCE"),

    # Credential exfiltration: env/secrets + network
    ("new_env_access", "new_network_calls", 35.0,
     "env access + network → possible credential exfiltration"),
    ("new_env_access", "new_network_imports", 25.0,
     "env access + network imports → possible credential staging"),
    ("new_sensitive_paths", "new_network_calls", 40.0,
     "sensitive paths + network → possible data theft"),

    # Payload delivery: obfuscation + exec
    ("new_obfuscation_calls", "new_exec_calls", 35.0,
     "obfuscation + exec → likely payload delivery"),
    ("new_encoded_strings", "new_exec_calls", 30.0,
     "encoded strings + exec → likely obfuscated payload"),

    # Supply chain attack: install hook + exec/network
    ("install_hooks_added", "new_exec_calls", 30.0,
     "install hook + exec → install-time code execution"),
    ("install_hooks_added", "new_network_calls", 30.0,
     "install hook + network → install-time data exfil"),
    ("install_hooks_added", "new_subprocess_calls", 25.0,
     "install hook + subprocess → install-time command execution"),

    # Stealth: obfuscation + sensitive access
    ("new_obfuscation_calls", "new_env_access", 20.0,
     "obfuscation + env access → hidden credential access"),
    ("new_obfuscation_calls", "new_sensitive_paths", 25.0,
     "obfuscation + sensitive paths → hidden file access"),

    # Subprocess + env (command injection with credentials)
    ("new_subprocess_calls", "new_env_access", 15.0,
     "subprocess + env access → potential command injection with creds"),

    # Stealth exfiltration: existing call redirected + sensitive data added
    ("modified_network_targets", "new_sensitive_data_flow", 50.0,
     "URL changed + sensitive data added → stealth exfiltration"),
    ("modified_network_targets", "new_env_access", 35.0,
     "URL changed + env access introduced → credential redirect"),
    ("new_sensitive_data_flow", "new_obfuscation_calls", 30.0,
     "sensitive data flow + obfuscation → hidden exfil"),
]


def compute_behavioral_score(
    features: BehaviorFeatures,
    anomalies: AnomalyReport,
) -> tuple[int, list[str]]:
    """
    Compute risk score from features and anomalies.

    Returns:
        (score, explanations) where explanations list the active scoring rules.
    """
    explanations = []
    fd = features.to_dict()

    # --- Step 1: Base score ---
    base = 0.0
    for feat_name, weight in FEATURE_WEIGHTS.items():
        val = fd.get(feat_name, 0)
        if isinstance(val, bool):
            val = 1.0 if val else 0.0
        contribution = float(val) * weight
        if contribution > 0:
            base += contribution
            explanations.append(f"+{contribution:.0f} {feat_name}={val}")

    # --- Step 2: Combination bonuses ---
    combo = 0.0
    for feat_a, feat_b, bonus, desc in COMBINATIONS:
        val_a = fd.get(feat_a, 0)
        val_b = fd.get(feat_b, 0)
        if isinstance(val_a, bool):
            val_a = 1 if val_a else 0
        if isinstance(val_b, bool):
            val_b = 1 if val_b else 0
        if val_a and val_b:
            combo += bonus
            explanations.append(f"+{bonus:.0f} COMBO: {desc}")

    # --- Step 3: Anomaly multiplier ---
    #
    # If the package has a baseline and these behaviors are NEW,
    # the score gets amplified. More anomalies = higher multiplier.
    #
    # For packages with no baseline (first analysis), anomaly_count will be
    # high but that's correct — we have no trust signal.
    anomaly_mult = 1.0 + 0.3 * anomalies.anomaly_count
    if anomalies.anomaly_count > 0:
        anomaly_details = []
        if anomalies.new_network:
            anomaly_details.append("new:network")
        if anomalies.new_exec:
            anomaly_details.append("new:exec")
        if anomalies.new_env_access:
            anomaly_details.append("new:env")
        if anomalies.new_subprocess:
            anomaly_details.append("new:subprocess")
        if anomalies.new_obfuscation:
            anomaly_details.append("new:obfuscation")
        if anomalies.new_file_io:
            anomaly_details.append("new:file_io")
        if anomalies.novel_imports:
            novel = ", ".join(sorted(anomalies.novel_imports)[:5])
            anomaly_details.append(f"new:imports({novel})")
        explanations.append(
            f"x{anomaly_mult:.1f} ANOMALY ({anomalies.anomaly_count}): "
            f"{', '.join(anomaly_details)}"
        )

    raw_score = (base + combo) * anomaly_mult
    final = round(raw_score)

    return final, explanations


# ---------------------------------------------------------------------------
# Thresholds for classification without AI
# ---------------------------------------------------------------------------

def classify_from_score(score: int, anomalies: AnomalyReport) -> str:
    """Quick classification from score alone."""
    if score >= 80 and anomalies.anomaly_count >= 2:
        return "malicious"
    if score >= 40:
        return "suspicious"
    return "benign"
