from __future__ import annotations

"""
Package download cache.

Stores downloaded archives on disk by (ecosystem, name, version).
Avoids re-downloading the same version across runs and workers.
Thread-safe via filesystem atomicity (write-to-temp then rename).
"""

import hashlib
import os
import tempfile
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path

from config import PACKAGE_CACHE_DIR


def _cache_path(ecosystem: str, name: str, version: str) -> Path:
    safe_name = name.replace("/", "_").replace("@", "_")
    return PACKAGE_CACHE_DIR / ecosystem / safe_name / f"{version}.tar"


def get_cached(ecosystem: str, name: str, version: str) -> bytes | None:
    """Return cached archive bytes, or None if not cached."""
    path = _cache_path(ecosystem, name, version)
    if path.exists():
        try:
            return path.read_bytes()
        except Exception:
            return None
    return None


def put_cached(ecosystem: str, name: str, version: str, data: bytes):
    """Store archive bytes in cache. Atomic write."""
    path = _cache_path(ecosystem, name, version)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write to temp file then rename for atomicity across threads
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        os.write(fd, data)
        os.close(fd)
        os.replace(tmp, str(path))
    except Exception:
        os.close(fd) if not os.get_inheritable(fd) else None
        try:
            os.unlink(tmp)
        except OSError:
            pass


def is_cached(ecosystem: str, name: str, version: str) -> bool:
    return _cache_path(ecosystem, name, version).exists()


@dataclass
class CacheMetrics:
    hits: int = 0
    misses: int = 0
    bytes_saved: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def hit(self, size: int = 0):
        with self._lock:
            self.hits += 1
            self.bytes_saved += size

    def miss(self):
        with self._lock:
            self.misses += 1

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0


# Global metrics
cache_metrics = CacheMetrics()
