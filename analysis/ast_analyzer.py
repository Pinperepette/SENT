from __future__ import annotations

"""
AST-based behavioral extraction for Python files.

Instead of matching regex on text, we parse Python source into an AST
and extract *structural behaviors*:
  - what gets imported
  - what functions/methods are called
  - what attributes are accessed
  - what names are read (env vars, file paths, etc.)

This runs on TWO trees: old version and new version.
The diff is computed at the behavior level, not the text level.
Only NEWLY INTRODUCED behaviors are returned.
"""

import ast
from dataclasses import dataclass, field
from typing import Set


@dataclass
class FileBehavior:
    """Behavioral fingerprint of a single Python file."""
    imports: Set[str] = field(default_factory=set)         # "os", "requests", "base64"
    from_imports: Set[str] = field(default_factory=set)    # "from os import environ"
    calls: Set[str] = field(default_factory=set)           # "eval", "exec", "requests.get"
    attribute_access: Set[str] = field(default_factory=set) # "os.environ", "sys.path"
    string_literals: Set[str] = field(default_factory=set)  # interesting strings only
    exec_nodes: int = 0      # count of eval/exec/compile AST nodes
    try_except: int = 0      # count of try/except blocks
    dynamic_attrs: int = 0   # getattr/setattr/delattr calls
    comprehensions: int = 0  # comprehensions used (low signal, used for entropy)


class BehaviorExtractor(ast.NodeVisitor):
    """Walk an AST and extract behavioral features."""

    # Modules that indicate specific behavior categories
    NETWORK_MODULES = frozenset({
        "requests", "urllib", "urllib3", "httpx", "aiohttp",
        "http", "http.client", "http.server",
        "socket", "socketserver", "ssl",
        "xmlrpc", "ftplib", "smtplib", "poplib", "imaplib",
    })
    EXEC_FUNCTIONS = frozenset({
        "eval", "exec", "compile", "__import__", "execfile",
    })
    SENSITIVE_ATTRS = frozenset({
        "os.environ", "os.getenv", "os.putenv",
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "os.system", "os.popen", "os.exec", "os.execvp",
        "os.spawn", "os.spawnl", "os.spawnle",
    })
    OBFUSCATION_CALLS = frozenset({
        "base64.b64decode", "base64.decodebytes", "base64.urlsafe_b64decode",
        "codecs.decode", "zlib.decompress", "gzip.decompress",
        "bytes.fromhex", "bytearray.fromhex",
        "marshal.loads", "pickle.loads",
    })
    CRYPTO_MODULES = frozenset({
        "Crypto", "Cryptodome", "cryptography", "hashlib", "hmac",
    })

    def __init__(self):
        self.behavior = FileBehavior()
        self._scope_stack: list[str] = []

    def extract(self, source: str) -> FileBehavior:
        """Parse source and extract behaviors. Returns empty on parse failure."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return self.behavior
        self.visit(tree)
        return self.behavior

    # --- Imports ---

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.behavior.imports.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            top = node.module.split(".")[0]
            self.behavior.imports.add(top)
            for alias in (node.names or []):
                self.behavior.from_imports.add(f"{node.module}.{alias.name}")
        self.generic_visit(node)

    # --- Calls ---

    def visit_Call(self, node: ast.Call):
        name = self._resolve_call_name(node.func)
        if name:
            self.behavior.calls.add(name)
            if name in self.EXEC_FUNCTIONS or name.split(".")[-1] in self.EXEC_FUNCTIONS:
                self.behavior.exec_nodes += 1
            if name in ("getattr", "setattr", "delattr"):
                self.behavior.dynamic_attrs += 1
        self.generic_visit(node)

    # --- Attribute access ---

    def visit_Attribute(self, node: ast.Attribute):
        chain = self._resolve_attr_chain(node)
        if chain:
            self.behavior.attribute_access.add(chain)
        self.generic_visit(node)

    # --- String literals (only capture interesting ones) ---

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str) and len(node.value) > 10:
            s = node.value
            # Capture URLs, file paths, env var names, long encoded strings
            if any(marker in s for marker in (
                "http://", "https://", "/etc/", "/.ssh/", "/.aws/",
                "HOME", "PATH", "TOKEN", "SECRET", "KEY", "PASS",
            )):
                self.behavior.string_literals.add(s[:200])
            # Long base64-looking strings
            elif len(s) > 80 and s.replace("+", "").replace("/", "").replace("=", "").isalnum():
                self.behavior.string_literals.add(f"[encoded:{len(s)}chars]")
        self.generic_visit(node)

    # Python 3.7 compat — Str nodes
    def visit_Str(self, node: ast.Str):
        if hasattr(node, "value"):
            # Reuse Constant logic
            fake = ast.Constant(value=node.s)
            self.visit_Constant(fake)
        self.generic_visit(node)

    # --- Control flow ---

    def visit_Try(self, node: ast.Try):
        self.behavior.try_except += 1
        self.generic_visit(node)

    # --- Comprehensions (entropy signal) ---

    def visit_ListComp(self, node: ast.ListComp):
        self.behavior.comprehensions += 1
        self.generic_visit(node)

    def visit_SetComp(self, node: ast.SetComp):
        self.behavior.comprehensions += 1
        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp):
        self.behavior.comprehensions += 1
        self.generic_visit(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        self.behavior.comprehensions += 1
        self.generic_visit(node)

    # --- Helpers ---

    def _resolve_call_name(self, node: ast.expr) -> str:
        """Resolve a call target to a dotted name string."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._resolve_call_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
            return node.attr
        return ""

    def _resolve_attr_chain(self, node: ast.Attribute) -> str:
        """Resolve chained attribute access: os.environ.get → 'os.environ.get'"""
        parts = [node.attr]
        current = node.value
        depth = 0
        while isinstance(current, ast.Attribute) and depth < 5:
            parts.append(current.attr)
            current = current.value
            depth += 1
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return ".".join(parts)


def extract_behavior(source: str) -> FileBehavior:
    """Extract behavioral fingerprint from Python source code."""
    return BehaviorExtractor().extract(source)


def diff_behaviors(old: FileBehavior, new: FileBehavior) -> FileBehavior:
    """
    Compute the behavioral DELTA between two versions.
    Returns a FileBehavior containing ONLY newly introduced behaviors.
    """
    return FileBehavior(
        imports=new.imports - old.imports,
        from_imports=new.from_imports - old.from_imports,
        calls=new.calls - old.calls,
        attribute_access=new.attribute_access - old.attribute_access,
        string_literals=new.string_literals - old.string_literals,
        exec_nodes=max(0, new.exec_nodes - old.exec_nodes),
        try_except=max(0, new.try_except - old.try_except),
        dynamic_attrs=max(0, new.dynamic_attrs - old.dynamic_attrs),
        comprehensions=max(0, new.comprehensions - old.comprehensions),
    )


def merge_behaviors(behaviors: list[FileBehavior]) -> FileBehavior:
    """Merge multiple file behaviors into a single package-level fingerprint."""
    merged = FileBehavior()
    for b in behaviors:
        merged.imports |= b.imports
        merged.from_imports |= b.from_imports
        merged.calls |= b.calls
        merged.attribute_access |= b.attribute_access
        merged.string_literals |= b.string_literals
        merged.exec_nodes += b.exec_nodes
        merged.try_except += b.try_except
        merged.dynamic_attrs += b.dynamic_attrs
        merged.comprehensions += b.comprehensions
    return merged
