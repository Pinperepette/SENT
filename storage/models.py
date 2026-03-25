from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Package:
    name: str
    ecosystem: str  # "pypi" or "npm"
    latest_version: str = ""
    downloads: int = 0
    direct_deps: list[str] = field(default_factory=list)
    updated_at: str = ""


@dataclass
class ReleaseEvent:
    package_name: str
    ecosystem: str
    version: str
    previous_version: str = ""
    timestamp: str = ""
    processed: bool = False


@dataclass
class DiffFlag:
    category: str       # "execution", "obfuscation", "network", "sensitive", "supply_chain"
    pattern: str         # what matched
    score: int           # risk points
    file_path: str       # which file
    line_number: int     # where
    snippet: str         # the actual line


@dataclass
class DiffReport:
    package_name: str
    ecosystem: str
    version: str
    previous_version: str
    risk_score: int = 0
    flags: list[DiffFlag] = field(default_factory=list)
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    summary: str = ""
    ai_classification: str = ""  # benign / suspicious / malicious
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = {
            "package": self.package_name,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "previous_version": self.previous_version,
            "risk_score": self.risk_score,
            "flags": [
                {
                    "category": f.category,
                    "pattern": f.pattern,
                    "score": f.score,
                    "file": f.file_path,
                    "line": f.line_number,
                    "snippet": f.snippet,
                }
                for f in self.flags
            ],
            "files_added": self.files_added,
            "files_removed": self.files_removed,
            "files_modified": self.files_modified,
            "summary": self.summary,
            "ai_classification": self.ai_classification,
            "diff_snippets": [f.snippet for f in self.flags[:20]],
            "timestamp": self.timestamp,
        }
        # Attach behavioral analysis data if present
        if hasattr(self, "_features") and self._features:
            d["features"] = self._features.to_dict()
        if hasattr(self, "_anomalies") and self._anomalies:
            d["anomalies"] = self._anomalies.to_dict()
        if hasattr(self, "_explanations") and self._explanations:
            d["scoring_explanations"] = self._explanations
        return d
