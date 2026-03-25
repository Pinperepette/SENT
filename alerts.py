from __future__ import annotations

"""
Alert system — notifies when a suspicious package is detected.

Supports multiple channels:
  - Console (always on, colored output)
  - Desktop notification (macOS native, no dependencies)
  - Webhook (Slack, Discord, or any URL that accepts JSON POST)
  - Log file (append-only, one JSON line per alert)

Configure via environment variables:
  SENT_ALERT_WEBHOOK=https://hooks.slack.com/services/...
  SENT_ALERT_LOG=./alerts.jsonl
  SENT_ALERT_DESKTOP=1
  SENT_ALERT_MIN_SCORE=30
"""

import json
import os
import subprocess
import time
from datetime import datetime
from typing import Dict

import httpx

ALERT_WEBHOOK = os.environ.get("SENT_ALERT_WEBHOOK", "")
ALERT_LOG = os.environ.get("SENT_ALERT_LOG", "")
ALERT_DESKTOP = os.environ.get("SENT_ALERT_DESKTOP", "1") == "1"
ALERT_MIN_SCORE = int(os.environ.get("SENT_ALERT_MIN_SCORE", "30"))


def should_alert(risk_score: int) -> bool:
    return risk_score >= ALERT_MIN_SCORE


def send_alert(
    package_name: str,
    ecosystem: str,
    version: str,
    previous_version: str,
    risk_score: int,
    summary: str,
    ai_classification: str = "",
    flags: list = None,
    features: dict = None,
):
    """Send alert through all configured channels."""
    alert = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "package": package_name,
        "ecosystem": ecosystem,
        "version": version,
        "previous_version": previous_version,
        "risk_score": risk_score,
        "ai_classification": ai_classification,
        "summary": summary,
        "flags_count": len(flags) if flags else 0,
        "top_flags": [
            {"category": f.get("category", ""), "pattern": f.get("pattern", ""),
             "snippet": f.get("snippet", "")[:100]}
            for f in (flags or [])[:5]
        ],
    }
    if features:
        alert["features"] = {k: v for k, v in features.items() if v and v != 0}

    # Console (always)
    _alert_console(alert)

    # Desktop notification
    if ALERT_DESKTOP:
        _alert_desktop(alert)

    # Webhook
    if ALERT_WEBHOOK:
        _alert_webhook(alert)

    # Log file
    if ALERT_LOG:
        _alert_logfile(alert)


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

def _alert_console(alert: dict):
    score = alert["risk_score"]
    ai = alert.get("ai_classification", "")
    color = "\033[91m" if score >= 80 else "\033[93m"
    reset = "\033[0m"
    print(f"\n{color}{'='*60}")
    print(f"  ALERT: {alert['ecosystem']}/{alert['package']} "
          f"{alert['previous_version']} -> {alert['version']}")
    print(f"  Score: {score}  AI: {ai or 'N/A'}")
    print(f"  {alert['summary'][:120]}")
    print(f"{'='*60}{reset}\n")


# ---------------------------------------------------------------------------
# Desktop notification (macOS native, no dependencies)
# ---------------------------------------------------------------------------

def _alert_desktop(alert: dict):
    title = f"SENT: {alert['package']} (score {alert['risk_score']})"
    body = f"{alert['previous_version']} -> {alert['version']}\n{alert['summary'][:80]}"
    try:
        subprocess.run(
            ["osascript", "-e",
             f'display notification "{body}" with title "{title}" sound name "Purr"'],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass  # Non-macOS or osascript unavailable


# ---------------------------------------------------------------------------
# Webhook (Slack / Discord / generic)
# ---------------------------------------------------------------------------

def _alert_webhook(alert: dict):
    score = alert["risk_score"]
    severity = "CRITICAL" if score >= 80 else "WARNING"

    # Slack-compatible payload
    payload = {
        "text": f"*[{severity}] {alert['ecosystem']}/{alert['package']}* "
                f"score={score}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity}: {alert['ecosystem']}/{alert['package']}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Score:* {score}"},
                    {"type": "mrkdwn", "text": f"*AI:* {alert.get('ai_classification', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Version:* {alert['previous_version']} -> {alert['version']}"},
                    {"type": "mrkdwn", "text": f"*Flags:* {alert['flags_count']}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```{alert['summary'][:500]}```",
                },
            },
        ],
    }

    # For Discord webhooks, wrap in a different format
    url = ALERT_WEBHOOK
    if "discord.com" in url:
        payload = {
            "content": f"**[{severity}] {alert['ecosystem']}/{alert['package']}** "
                       f"score={score}\n"
                       f"Version: {alert['previous_version']} -> {alert['version']}\n"
                       f"```{alert['summary'][:500]}```",
        }

    try:
        httpx.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"[alert] Webhook error: {e}")


# ---------------------------------------------------------------------------
# Log file (JSON lines)
# ---------------------------------------------------------------------------

def _alert_logfile(alert: dict):
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception as e:
        print(f"[alert] Log error: {e}")
