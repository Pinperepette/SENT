from __future__ import annotations

"""
PyPI ingestion — polls the RSS feed for recent releases.

PyPI provides an XML RSS feed at https://pypi.org/rss/updates.xml
with the most recent ~40 package updates.
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime

import httpx

from storage.models import Package, ReleaseEvent

PYPI_RSS_URL = "https://pypi.org/rss/updates.xml"
PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
PYPISTATS_URL = "https://pypistats.org/api/packages/{name}/recent"

# In-memory cache for download counts (avoid hammering pypistats)
_dl_cache: dict = {}  # name → (downloads, timestamp)
_DL_CACHE_TTL = 3600  # 1 hour


def fetch_recent_releases() -> list[ReleaseEvent]:
    """Fetch recent releases from PyPI RSS feed."""
    events = []
    try:
        resp = httpx.get(PYPI_RSS_URL, timeout=15, follow_redirects=True)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)

        for item in root.findall(".//item"):
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            pub_date = item.findtext("pubDate", "")

            # Title format: "package-name 1.2.3"
            parts = title.rsplit(" ", 1)
            if len(parts) != 2:
                continue

            name, version = parts[0].strip(), parts[1].strip()
            events.append(ReleaseEvent(
                package_name=name,
                ecosystem="pypi",
                version=version,
                timestamp=pub_date or datetime.utcnow().isoformat(),
            ))
    except Exception as e:
        print(f"[pypi] RSS fetch error: {e}")

    return events


def fetch_downloads(name: str) -> int:
    """Fetch real download count from pypistats.org (last month). Cached 1h."""
    import time as _time

    # Check cache
    cached = _dl_cache.get(name)
    if cached:
        dl, ts = cached
        if _time.time() - ts < _DL_CACHE_TTL:
            return dl

    try:
        resp = httpx.get(
            PYPISTATS_URL.format(name=name),
            timeout=5, follow_redirects=True,
        )
        if resp.status_code == 200:
            dl = resp.json().get("data", {}).get("last_month", 0)
            _dl_cache[name] = (dl, _time.time())
            return dl
        if resp.status_code == 429:
            # Rate limited — return cached or 0, don't spam
            return cached[0] if cached else 0
    except Exception:
        pass
    return cached[0] if cached else 0


def fetch_package_info(name: str) -> Package | None:
    """Fetch package metadata from PyPI JSON API + real download stats."""
    try:
        resp = httpx.get(
            PYPI_JSON_URL.format(name=name),
            timeout=15, follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})

        # Real download count from pypistats.org
        downloads = fetch_downloads(name)

        # Fallback: estimate from release count if pypistats fails
        if downloads <= 0:
            releases = list(data.get("releases", {}).keys())
            downloads = len(releases) * 100

        # Parse dependencies
        deps = []
        requires = info.get("requires_dist") or []
        for req in requires:
            dep_name = re.split(r'[><=!;\s\[]', req)[0].strip()
            if dep_name:
                deps.append(dep_name.lower())

        return Package(
            name=name,
            ecosystem="pypi",
            latest_version=info.get("version", ""),
            downloads=downloads,
            direct_deps=deps,
            updated_at=datetime.utcnow().isoformat(),
        )
    except Exception as e:
        print(f"[pypi] Info fetch error for {name}: {e}")
        return None


def get_previous_version(name: str, current_version: str) -> str:
    """Get the version released just before current_version."""
    try:
        resp = httpx.get(
            PYPI_JSON_URL.format(name=name),
            timeout=15, follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()
        releases = data.get("releases", {})

        # Filter versions that actually have files
        valid_versions = [
            v for v, files in releases.items()
            if files and v != current_version
        ]

        if not valid_versions:
            return ""

        # Sort by upload time of first file
        def upload_time(v):
            files = releases[v]
            if files:
                return files[0].get("upload_time_iso_8601", "")
            return ""

        valid_versions.sort(key=upload_time)

        # Find the one just before current
        current_time = ""
        for f in releases.get(current_version, []):
            t = f.get("upload_time_iso_8601", "")
            if t:
                current_time = t
                break

        if current_time:
            # Get the latest version uploaded before current
            prev = [v for v in valid_versions if upload_time(v) < current_time]
            if prev:
                return prev[-1]

        # Fallback: just return the second-to-last
        return valid_versions[-1] if valid_versions else ""

    except Exception:
        return ""
