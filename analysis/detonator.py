from __future__ import annotations

"""
Optional dynamic analysis via dyana (https://github.com/dreadnode/dyana).

SENT does static analysis (AST diff). Dyana does dynamic analysis:
it installs the package in an eBPF-traced sandbox and records
filesystem, network, and syscall activity.

Flow:
  SENT flags a package as suspicious (static) →
  dyana detonates it (dynamic) →
  combined report

Requires: pip install dyana, Docker running.
Enable with: SENT_DYANA=1 or --dyana flag.
"""

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field


DYANA_ENABLED = os.environ.get("SENT_DYANA", "0") == "1"
DYANA_MIN_SCORE = int(os.environ.get("SENT_DYANA_MIN_SCORE", "100"))


def dyana_available() -> bool:
    """Check if dyana CLI is installed."""
    return shutil.which("dyana") is not None


def docker_running() -> bool:
    """Check if Docker daemon is running."""
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


def detonate(package_name: str, version: str, timeout: int = 300) -> DyanaReport:
    """
    Run dyana dynamic analysis on a package.

    Installs the package in a sandboxed container with eBPF tracing.
    Returns structured report of observed behaviors.
    """
    report = DyanaReport(package_name=package_name, version=version)

    if not dyana_available():
        report.error = "dyana not installed (pip install dyana)"
        return report

    if not docker_running():
        report.error = "Docker not running"
        return report

    pkg_spec = f"{package_name}=={version}" if version else package_name

    print(f"  [dyana] Detonating {pkg_spec} in sandbox...")

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
            print(f"  [dyana] Done — network={len(report.network_activity)} "
                  f"fs={len(report.filesystem_activity)} "
                  f"security={len(report.security_events)}")
        else:
            report.error = result.stderr[:500] if result.stderr else f"Exit code {result.returncode}"
            print(f"  [dyana] Failed: {report.error[:100]}")

    except subprocess.TimeoutExpired:
        report.error = f"Timeout after {timeout}s"
        print(f"  [dyana] Timeout after {timeout}s")
    except Exception as e:
        report.error = str(e)
        print(f"  [dyana] Error: {e}")

    return report


def _parse_dyana_output(report: DyanaReport, output: str):
    """Parse dyana output for key findings."""
    for line in output.splitlines():
        line_lower = line.lower()
        # Network activity indicators
        if any(kw in line_lower for kw in ("connect", "dns", "http", "socket", "tcp", "udp")):
            report.network_activity.append(line.strip())
        # Filesystem activity
        elif any(kw in line_lower for kw in ("open", "write", "read", "unlink", "mkdir", "chmod")):
            report.filesystem_activity.append(line.strip())
        # Security events
        elif any(kw in line_lower for kw in ("exec", "ptrace", "mmap", "mprotect", "shell", "suspicious")):
            report.security_events.append(line.strip())


def should_detonate(risk_score: int) -> bool:
    """Check if a package should be sent to dyana for dynamic analysis."""
    return DYANA_ENABLED and risk_score >= DYANA_MIN_SCORE
