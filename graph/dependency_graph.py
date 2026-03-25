from __future__ import annotations

"""
Weighted dependency graph with cascade weight propagation.

Edge A → B means "A depends on B".

Cascade weight of B = B's own downloads + sum(cascade_weight of all A that depend on B).

This means: a library with 10 downloads that is depended on by requests (50M dl)
gets cascade_weight ≈ 50M. A new release of that library is critical.

Weight propagation uses reverse topological order — computed once, cached,
invalidated when graph structure changes.
"""

import json
import sqlite3
import threading
import time
from collections import deque
from typing import Dict, Set, Tuple

import networkx as nx

from config import DB_PATH


class DependencyGraph:
    def __init__(self):
        self.g = nx.DiGraph()
        self._downloads: Dict[str, int] = {}       # node → own downloads
        self._cascade: Dict[str, int] = {}          # node → cascade weight (cached)
        self._cascade_dirty = True                   # True = needs recomputation
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Graph mutations
    # ------------------------------------------------------------------

    def add_package(self, name: str, ecosystem: str, dependencies: list,
                    downloads: int = 0):
        """Register a package, its deps, and its download count."""
        node = f"{ecosystem}/{name}"
        with self._lock:
            is_new_node = node not in self.g
            self.g.add_node(node)
            if downloads > 0:
                self._downloads[node] = max(self._downloads.get(node, 0), downloads)

            old_deps = set(self.g.successors(node)) if not is_new_node else set()
            new_deps = set()
            for dep in dependencies:
                dep_node = f"{ecosystem}/{dep}"
                new_deps.add(dep_node)
                self.g.add_node(dep_node)

            # Only update edges if they changed
            if new_deps != old_deps:
                for removed in old_deps - new_deps:
                    self.g.remove_edge(node, removed)
                for added in new_deps - old_deps:
                    self.g.add_edge(node, added)
                self._cascade_dirty = True

            if is_new_node:
                self._cascade_dirty = True

    def set_downloads(self, name: str, ecosystem: str, downloads: int):
        """Update download count for a package."""
        node = f"{ecosystem}/{name}"
        with self._lock:
            old = self._downloads.get(node, 0)
            if downloads != old:
                self._downloads[node] = max(downloads, 0)
                self._cascade_dirty = True

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_upstream(self, name: str, ecosystem: str) -> list:
        """What does this package depend on?"""
        node = f"{ecosystem}/{name}"
        if node not in self.g:
            return []
        return [n.split("/", 1)[1] for n in self.g.successors(node)]

    def get_downstream(self, name: str, ecosystem: str) -> list:
        """What packages depend on this one?"""
        node = f"{ecosystem}/{name}"
        if node not in self.g:
            return []
        return [n.split("/", 1)[1] for n in self.g.predecessors(node)]

    def downstream_count(self, name: str, ecosystem: str) -> int:
        node = f"{ecosystem}/{name}"
        if node not in self.g:
            return 0
        return self.g.in_degree(node)

    def own_downloads(self, name: str, ecosystem: str) -> int:
        node = f"{ecosystem}/{name}"
        return self._downloads.get(node, 0)

    def total_packages(self) -> int:
        return self.g.number_of_nodes()

    def total_edges(self) -> int:
        return self.g.number_of_edges()

    # ------------------------------------------------------------------
    # Cascade weight — the core of the prioritization
    # ------------------------------------------------------------------

    def cascade_weight(self, name: str, ecosystem: str) -> int:
        """
        Cascade weight = own downloads + cumulative downloads of all
        transitive dependents.

        If requests (5M dl) depends on urllib3, then:
          cascade_weight(urllib3) = urllib3_dl + requests_dl + ...

        Cached. Recomputed only when graph structure changes.
        """
        self._ensure_cascade()
        node = f"{ecosystem}/{name}"
        return self._cascade.get(node, self._downloads.get(node, 0))

    def _ensure_cascade(self):
        """Recompute cascade weights if dirty."""
        with self._lock:
            if not self._cascade_dirty:
                return
            self._recompute_cascade()
            self._cascade_dirty = False

    def _recompute_cascade(self):
        """
        Compute cascade weights via reverse topological BFS.

        For a DAG with edges A → B ("A depends on B"):
          cascade(B) = downloads(B) + sum(cascade(A) for A in dependents_of(B))

        We process in topological order (leaves first), so when we process B,
        all A's that depend on B have already been computed.

        For cycles (rare but possible), we break them by treating back-edges
        as zero contribution.
        """
        g = self.g
        cascade: Dict[str, int] = {}

        # Initialize with own downloads
        for node in g.nodes():
            cascade[node] = self._downloads.get(node, 0)

        # Topological sort — if cycles exist, use a fallback
        try:
            topo_order = list(nx.topological_sort(g))
        except nx.NetworkXUnfeasible:
            # Graph has cycles — use strongly connected components
            topo_order = []
            for scc in nx.kosaraju_strongly_connected_components(g):
                topo_order.extend(scc)

        # Process in topological order:
        # For each node A, propagate A's cascade weight to all B that A depends on.
        # Since we go in topo order, dependents (A) are processed before
        # their dependencies (B) — wait, that's wrong. Topo order puts
        # dependencies before dependents. We need REVERSE topo order.
        #
        # Actually: edge A → B means "A depends on B".
        # Topological sort: B comes before A (dependency before dependent).
        # We want to propagate FROM dependents TO dependencies.
        # So we process in REVERSE topological order (A before B).

        for node in reversed(topo_order):
            # node's cascade weight includes its own downloads
            # Propagate it to everything node depends on
            node_weight = cascade[node]
            for dep in g.successors(node):
                cascade[dep] = cascade.get(dep, 0) + node_weight

        self._cascade = cascade

    def top_by_cascade(self, n: int = 50) -> list:
        """Return top N packages by cascade weight."""
        self._ensure_cascade()
        items = sorted(self._cascade.items(), key=lambda x: x[1], reverse=True)
        result = []
        for node, weight in items[:n]:
            eco, name = node.split("/", 1)
            own = self._downloads.get(node, 0)
            deps = self.g.in_degree(node)
            result.append({
                "name": name,
                "ecosystem": eco,
                "cascade_weight": weight,
                "own_downloads": own,
                "direct_dependents": deps,
            })
        return result

    # ------------------------------------------------------------------
    # Persistence — save/load to SQLite
    # ------------------------------------------------------------------

    def save_to_db(self):
        """Persist graph to SQLite."""
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS dep_graph (
                key TEXT PRIMARY KEY,
                data TEXT
            )""")
            # Serialize edges + downloads
            edges = list(self.g.edges())
            nodes = list(self.g.nodes())
            payload = json.dumps({
                "nodes": nodes,
                "edges": edges,
                "downloads": self._downloads,
            })
            conn.execute(
                "INSERT OR REPLACE INTO dep_graph (key, data) VALUES ('graph', ?)",
                (payload,)
            )
            conn.commit()
        finally:
            conn.close()

    def load_from_db(self) -> bool:
        """Load graph from SQLite. Returns True if loaded."""
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS dep_graph (
                key TEXT PRIMARY KEY,
                data TEXT
            )""")
            row = conn.execute(
                "SELECT data FROM dep_graph WHERE key='graph'"
            ).fetchone()
            if not row:
                return False
            data = json.loads(row[0])
            self.g = nx.DiGraph()
            self.g.add_nodes_from(data.get("nodes", []))
            self.g.add_edges_from(data.get("edges", []))
            self._downloads = data.get("downloads", {})
            self._cascade_dirty = True
            return True
        except Exception:
            return False
        finally:
            conn.close()


# Global singleton
graph = DependencyGraph()
