from __future__ import annotations

"""
AI classification layer — three backends:

1. claude-code: invokes `claude` CLI (no API key needed, uses your local auth)
2. api: calls Anthropic API directly (needs ANTHROPIC_API_KEY)
3. auto: tries claude-code → api → rule-based fallback

Set via SENT_AI_BACKEND env var or --ai-backend CLI flag.
"""

import json
import shutil
import subprocess

from config import AI_BACKEND, ANTHROPIC_API_KEY
from storage.models import DiffReport

CLASSIFICATION_PROMPT = """You are a supply chain security analyst.
Analyze the following diff report from a package update and classify the changes.

Package: {package} ({ecosystem})
Version: {old_version} → {new_version}
Risk Score: {risk_score}

Flagged patterns:
{flags_text}

Diff snippets (newly introduced code only):
{snippets}

Based on this analysis, classify the update as one of:
- BENIGN: Normal development activity, no security concern
- SUSPICIOUS: Warrants manual review, potentially concerning patterns
- MALICIOUS: High confidence malicious intent (credential theft, backdoor, etc.)

Respond with EXACTLY two lines in this format:
CLASSIFICATION: <benign|suspicious|malicious>
REASON: <one sentence explanation>
"""

# Rule-based fallback thresholds
SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 80


def _build_prompt(report: DiffReport) -> str:
    flags_text = "\n".join(
        f"  [{f.category}] {f.pattern} (score: {f.score}) in {f.file_path}:{f.line_number}"
        for f in report.flags[:30]
    )
    snippets = "\n".join(
        f"  {f.file_path}:{f.line_number}: {f.snippet}"
        for f in report.flags[:20]
    )
    return CLASSIFICATION_PROMPT.format(
        package=report.package_name,
        ecosystem=report.ecosystem,
        old_version=report.previous_version,
        new_version=report.version,
        risk_score=report.risk_score,
        flags_text=flags_text,
        snippets=snippets,
    )


def _parse_response(text: str) -> tuple[str, str]:
    """Parse CLASSIFICATION/REASON from LLM output."""
    classification = "suspicious"
    reason = text.strip()

    for line in text.splitlines():
        line = line.strip()
        if line.upper().startswith("CLASSIFICATION:"):
            val = line.split(":", 1)[1].strip().lower()
            if val in ("benign", "suspicious", "malicious"):
                classification = val
        elif line.upper().startswith("REASON:"):
            reason = line.split(":", 1)[1].strip()

    return classification, reason


# ---------------------------------------------------------------------------
# Backend: Claude Code CLI
# ---------------------------------------------------------------------------

def _claude_code_available() -> bool:
    return shutil.which("claude") is not None


def classify_with_claude_code(report: DiffReport) -> tuple[str, str]:
    """Classify using `claude` CLI — no API key needed."""
    prompt = _build_prompt(report)

    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--output-format", "text"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            print(f"[ai/claude-code] Error: {result.stderr[:200]}")
            return classify_rule_based(report)

        return _parse_response(result.stdout)

    except FileNotFoundError:
        print("[ai/claude-code] `claude` not found in PATH")
        return classify_rule_based(report)
    except subprocess.TimeoutExpired:
        print("[ai/claude-code] Timeout (120s)")
        return classify_rule_based(report)
    except Exception as e:
        print(f"[ai/claude-code] Error: {e}")
        return classify_rule_based(report)


# ---------------------------------------------------------------------------
# Backend: Anthropic API
# ---------------------------------------------------------------------------

def classify_with_api(report: DiffReport) -> tuple[str, str]:
    """Classify using Anthropic API directly."""
    if not ANTHROPIC_API_KEY:
        return classify_rule_based(report)

    try:
        import anthropic
    except ImportError:
        print("[ai/api] `anthropic` package not installed (pip install anthropic)")
        return classify_rule_based(report)

    prompt = _build_prompt(report)

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        return _parse_response(message.content[0].text)

    except Exception as e:
        print(f"[ai/api] Error: {e}")
        return classify_rule_based(report)


# ---------------------------------------------------------------------------
# Backend: Rule-based fallback
# ---------------------------------------------------------------------------

def classify_rule_based(report: DiffReport) -> tuple[str, str]:
    """Deterministic rule-based classification. Always available."""
    score = report.risk_score

    if score >= MALICIOUS_THRESHOLD:
        categories = {f.category for f in report.flags}
        if "sensitive" in categories and ("execution" in categories or "network" in categories):
            return "malicious", f"High risk score ({score}) with credential access + execution/network"
        return "suspicious", f"High risk score ({score}), manual review recommended"

    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious", f"Moderate risk score ({score}), patterns warrant review"

    return "benign", f"Low risk score ({score}), normal development patterns"


# ---------------------------------------------------------------------------
# Main entry point — selects backend based on config
# ---------------------------------------------------------------------------

def classify_with_ai(report: DiffReport, backend: str = "") -> tuple[str, str]:
    """
    Classify a diff report using the configured AI backend.

    backend precedence:
      1. explicit `backend` argument
      2. SENT_AI_BACKEND env var
      3. "auto" (claude-code → api → rules)
    """
    b = (backend or AI_BACKEND).lower().strip()

    if b == "claude-code":
        print("[ai] Using claude-code backend")
        return classify_with_claude_code(report)

    if b == "api":
        print("[ai] Using API backend")
        return classify_with_api(report)

    if b == "rules":
        return classify_rule_based(report)

    # auto: try claude-code first, then api, then rules
    if _claude_code_available():
        print("[ai] Auto → claude-code")
        result = classify_with_claude_code(report)
        # If it didn't fall back to rules, return it
        if result[1] and not result[1].startswith("High risk score") \
                and not result[1].startswith("Moderate risk score") \
                and not result[1].startswith("Low risk score"):
            return result

    if ANTHROPIC_API_KEY:
        print("[ai] Auto → API")
        return classify_with_api(report)

    return classify_rule_based(report)
