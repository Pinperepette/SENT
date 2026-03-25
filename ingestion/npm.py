from __future__ import annotations

"""
npm ingestion — polls the npm registry changes feed.

npm uses a CouchDB-based registry. We poll the /-/all/since endpoint
for recent updates, or use the replicate.npmjs.com changes feed.
For MVP, we poll the npm search API for recently updated packages.
"""

import re
from datetime import datetime

import httpx

from storage.models import Package, ReleaseEvent

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"


def fetch_recent_releases(count: int = 25) -> list[ReleaseEvent]:
    """Fetch recently updated npm packages."""
    events = []
    try:
        # Search for recently published packages
        # npm search sorts by "optimal" by default; we use quality+maintenance
        resp = httpx.get(
            NPM_SEARCH_URL,
            params={"text": "not:unstable", "size": count},
            timeout=15,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()

        for obj in data.get("objects", []):
            pkg = obj.get("package", {})
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            date = pkg.get("date", "")

            if name and version:
                events.append(ReleaseEvent(
                    package_name=name,
                    ecosystem="npm",
                    version=version,
                    timestamp=date or datetime.utcnow().isoformat(),
                ))
    except Exception as e:
        print(f"[npm] Search fetch error: {e}")

    return events


def fetch_package_info(name: str) -> Package | None:
    """Fetch package metadata from npm registry."""
    try:
        resp = httpx.get(
            f"{NPM_REGISTRY}/{name}",
            timeout=15,
            follow_redirects=True,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()

        latest_tag = data.get("dist-tags", {}).get("latest", "")
        latest_info = data.get("versions", {}).get(latest_tag, {})

        # Dependencies
        deps = list((latest_info.get("dependencies") or {}).keys())

        # Downloads — npm doesn't include this in registry data.
        # Would need api.npmjs.org/downloads/point/last-week/{name}
        # For MVP, estimate from number of versions
        versions_count = len(data.get("versions", {}))
        downloads = versions_count * 200  # rough proxy

        return Package(
            name=name,
            ecosystem="npm",
            latest_version=latest_tag,
            downloads=downloads,
            direct_deps=deps,
            updated_at=datetime.utcnow().isoformat(),
        )
    except Exception as e:
        print(f"[npm] Info fetch error for {name}: {e}")
        return None


def get_previous_version(name: str, current_version: str) -> str:
    """Get the version released just before current_version."""
    try:
        resp = httpx.get(
            f"{NPM_REGISTRY}/{name}",
            timeout=15,
            follow_redirects=True,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()

        time_data = data.get("time", {})
        versions = [
            v for v in data.get("versions", {}).keys()
            if v != current_version and v in time_data
        ]

        if not versions:
            return ""

        current_time = time_data.get(current_version, "")
        if current_time:
            prev = [v for v in versions if time_data.get(v, "") < current_time]
            prev.sort(key=lambda v: time_data.get(v, ""))
            if prev:
                return prev[-1]

        # Fallback
        versions.sort(key=lambda v: time_data.get(v, ""))
        return versions[-1] if versions else ""

    except Exception:
        return ""
