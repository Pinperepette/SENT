from __future__ import annotations

"""
Lightweight argument-level diff for existing function calls.

Detects semantic changes that the behavioral diff misses:
  - same function called, but URL argument points to new domain
  - same function called, but data argument is now os.environ
  - same subprocess call, but command string changed

Strategy: extract (func_name → string_args, sensitive_args) from old/new AST,
then diff. No cross-function tracking, no recursion, no taint analysis.
Single-pass AST walk per file.
"""

import ast
import re
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# What we track
# ---------------------------------------------------------------------------

NETWORK_FUNCS = frozenset({
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.request",
    "urllib.request.urlopen", "httpx.get", "httpx.post",
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
})

SUBPROCESS_FUNCS = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "os.system", "os.popen",
})

SENSITIVE_NAMES = re.compile(
    r'^(os\.environ|os\.getenv|os\.environ\.get|getenv)$'
)

TRUSTED_DOMAINS = frozenset({
    "localhost", "127.0.0.1", "example.com", "example.org",
})


@dataclass(frozen=True)
class CallFingerprint:
    """Lightweight representation of a call site's arguments."""
    func_name: str
    line: int
    url_domains: Tuple[str, ...]     # extracted domains from URL string args
    string_args: Tuple[str, ...]     # all string constants
    has_sensitive_arg: bool          # os.environ / getenv in any argument


@dataclass
class CallMutation:
    """A detected suspicious argument change."""
    kind: str          # "url_changed" | "sensitive_added" | "cmd_changed"
    func_name: str
    file_path: str
    line: int
    old_value: str
    new_value: str
    description: str


# ---------------------------------------------------------------------------
# Single-pass AST extractor — one walk, collect all call fingerprints
# ---------------------------------------------------------------------------

class _CallExtractor(ast.NodeVisitor):
    def __init__(self):
        self.calls: List[CallFingerprint] = []
        self._str_vars: Dict[str, str] = {}  # name → string value (simple assignments)

    def visit_Assign(self, node: ast.Assign):
        """Track name = "string" assignments for variable resolution."""
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._str_vars[target.id] = node.value.value
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = _resolve_name(node.func)
        if not name:
            self.generic_visit(node)
            return

        urls = []
        strings = []
        sensitive = False

        # Scan all args + kwargs in one pass
        for arg_node in _iter_args(node):
            # String constant
            if isinstance(arg_node, ast.Constant) and isinstance(arg_node.value, str):
                s = arg_node.value
                strings.append(s)
                domain = _extract_domain(s)
                if domain:
                    urls.append(domain)

            # Name reference — resolve to string if tracked
            elif isinstance(arg_node, ast.Name) and arg_node.id in self._str_vars:
                s = self._str_vars[arg_node.id]
                strings.append(s)
                domain = _extract_domain(s)
                if domain:
                    urls.append(domain)

            # Sensitive source check (works for direct ref AND wrapped in calls)
            if _is_sensitive_node(arg_node):
                sensitive = True

        self.calls.append(CallFingerprint(
            func_name=name,
            line=getattr(node, "lineno", 0),
            url_domains=tuple(urls),
            string_args=tuple(strings),
            has_sensitive_arg=sensitive,
        ))
        self.generic_visit(node)


def extract_call_fingerprints(source: str) -> List[CallFingerprint]:
    """Single-pass extraction of call fingerprints from Python source."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    ext = _CallExtractor()
    ext.visit(tree)
    return ext.calls


# ---------------------------------------------------------------------------
# Diff — compare old fingerprints vs new fingerprints for the SAME function
# ---------------------------------------------------------------------------

def diff_call_arguments(
    old_source: str,
    new_source: str,
    filepath: str,
) -> List[CallMutation]:
    """
    Compare call arguments between two versions of a file.
    Returns mutations for existing functions whose arguments changed dangerously.
    """
    old_fps = extract_call_fingerprints(old_source)
    new_fps = extract_call_fingerprints(new_source)

    # Group by func_name
    old_by_func: Dict[str, List[CallFingerprint]] = {}
    for fp in old_fps:
        old_by_func.setdefault(fp.func_name, []).append(fp)

    mutations: List[CallMutation] = []
    seen: Set[Tuple[str, str, str]] = set()  # dedup key

    for new_fp in new_fps:
        old_list = old_by_func.get(new_fp.func_name)
        if not old_list:
            continue  # new call — handled by behavioral diff

        # Compare against all old occurrences of the same function
        old_domains = set()
        old_sensitive = False
        old_strings = set()
        for ofp in old_list:
            old_domains.update(ofp.url_domains)
            old_strings.update(ofp.string_args)
            if ofp.has_sensitive_arg:
                old_sensitive = True

        # --- URL domain changed ---
        if new_fp.func_name in NETWORK_FUNCS or any(d for d in new_fp.url_domains):
            for domain in new_fp.url_domains:
                if domain not in old_domains and domain not in TRUSTED_DOMAINS \
                        and not domain.endswith((".test", ".local", ".internal")):
                    key = ("url", new_fp.func_name, domain)
                    if key not in seen:
                        seen.add(key)
                        mutations.append(CallMutation(
                            kind="url_changed",
                            func_name=new_fp.func_name,
                            file_path=filepath,
                            line=new_fp.line,
                            old_value=", ".join(sorted(old_domains)[:3]) or "(none)",
                            new_value=domain,
                            description=f"Network target changed → {domain}",
                        ))

        # --- Sensitive source added to existing call ---
        if new_fp.has_sensitive_arg and not old_sensitive:
            is_sink = new_fp.func_name in NETWORK_FUNCS or new_fp.func_name in SUBPROCESS_FUNCS
            if is_sink:
                key = ("sensitive", new_fp.func_name, filepath)
                if key not in seen:
                    seen.add(key)
                    mutations.append(CallMutation(
                        kind="sensitive_added",
                        func_name=new_fp.func_name,
                        file_path=filepath,
                        line=new_fp.line,
                        old_value="(no sensitive args)",
                        new_value="os.environ / getenv",
                        description=f"Sensitive data now flows into {new_fp.func_name}",
                    ))

        # --- Subprocess command changed ---
        if new_fp.func_name in SUBPROCESS_FUNCS:
            new_strs = set(new_fp.string_args) - old_strings
            for s in new_strs:
                if len(s) > 2:  # skip trivial strings
                    key = ("cmd", new_fp.func_name, s[:50])
                    if key not in seen:
                        seen.add(key)
                        mutations.append(CallMutation(
                            kind="cmd_changed",
                            func_name=new_fp.func_name,
                            file_path=filepath,
                            line=new_fp.line,
                            old_value="(different command)",
                            new_value=s[:120],
                            description=f"Subprocess command changed: {s[:80]}",
                        ))

    return mutations


# ---------------------------------------------------------------------------
# Helpers (kept minimal for speed)
# ---------------------------------------------------------------------------

def _resolve_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _resolve_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _iter_args(call_node: ast.Call):
    """Yield all argument nodes (positional + keyword values), flat.
    Unwraps one level of Dict/List/Tuple/Set to catch nested values."""
    for a in call_node.args:
        yield a
        yield from _unwrap_container(a)
    for kw in call_node.keywords:
        yield kw.value
        yield from _unwrap_container(kw.value)


def _unwrap_container(node):
    """Yield values inside a Dict/List/Tuple literal (one level)."""
    if isinstance(node, ast.Dict):
        for v in node.values:
            if v is not None:
                yield v
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            yield elt


def _is_sensitive_node(node) -> bool:
    """Check if node references os.environ or getenv. One level of depth."""
    name = _resolve_name(node)
    if name and SENSITIVE_NAMES.match(name):
        return True
    # os.environ["X"]
    if isinstance(node, ast.Subscript):
        val_name = _resolve_name(node.value)
        if val_name and SENSITIVE_NAMES.match(val_name):
            return True
    # os.environ.get("X") or getenv("X")
    if isinstance(node, ast.Call):
        func_name = _resolve_name(node.func)
        if func_name and SENSITIVE_NAMES.match(func_name):
            return True
        # Wrapping call: str(os.environ), json.dumps(os.environ), etc.
        for arg in node.args:
            inner = _resolve_name(arg)
            if inner and SENSITIVE_NAMES.match(inner):
                return True
            if isinstance(arg, ast.Subscript):
                val_name = _resolve_name(arg.value)
                if val_name and SENSITIVE_NAMES.match(val_name):
                    return True
    return False


def _extract_domain(s: str) -> str:
    """Extract domain from a URL string, or empty string."""
    if not s.startswith(("http://", "https://", "ftp://")):
        return ""
    try:
        return urlparse(s).hostname or ""
    except Exception:
        return ""
