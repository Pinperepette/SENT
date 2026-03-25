from __future__ import annotations

"""
Feature extraction layer.

Transforms AST-level behavioral diffs into a flat numerical feature vector.
This is the bridge between structural analysis and scoring.

Each feature is a count or boolean that captures ONE type of suspicious
behavior introduced in the new version.
"""

import math
from dataclasses import dataclass, field, asdict
from typing import Dict

from analysis.ast_analyzer import (
    BehaviorExtractor,
    FileBehavior,
)


@dataclass
class BehaviorFeatures:
    """
    Flat feature vector extracted from behavioral diff.
    Every field is a number — ready for scoring.
    """
    # Network behavior
    new_network_imports: int = 0       # new imports of network libraries
    new_network_calls: int = 0         # new calls to network functions
    new_external_urls: int = 0         # new URL string literals

    # Code execution
    new_exec_calls: int = 0            # new eval/exec/compile calls
    new_dynamic_imports: int = 0       # new __import__/importlib usage
    new_subprocess_calls: int = 0      # new subprocess/os.system calls

    # File system / sensitive access
    new_file_access: int = 0           # new open/read/write file calls
    new_env_access: int = 0            # new os.environ/getenv access
    new_sensitive_paths: int = 0       # new references to ~/.ssh, ~/.aws, etc.

    # Obfuscation
    new_obfuscation_calls: int = 0     # new base64/zlib/marshal decoding
    new_encoded_strings: int = 0       # new long encoded string literals
    new_dynamic_attrs: int = 0         # new getattr/setattr usage

    # Supply chain
    setup_script_changed: bool = False  # setup.py/pyproject.toml modified
    install_hooks_added: bool = False   # new install/postinstall commands
    new_entry_points: bool = False      # new console_scripts/entry_points

    # Structural complexity
    new_try_except_blocks: int = 0     # new try/except (error suppression)
    new_imports_total: int = 0         # total new imports

    # Argument mutation (existing behavior, changed arguments)
    modified_network_targets: int = 0   # URL arguments changed to new domains
    new_sensitive_data_flow: int = 0    # sensitive source now flows into sink
    suspicious_argument_change: int = 0 # any suspicious argument mutation

    # Entropy signal
    entropy_increase: float = 0.0      # rough measure of code complexity change

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    def nonzero_features(self) -> Dict[str, object]:
        """Return only features with non-zero/True values."""
        return {k: v for k, v in self.to_dict().items()
                if v and v != 0 and v != 0.0}


def extract_features(
    delta: FileBehavior,
    files_added: list[str],
    files_modified: list[str],
) -> BehaviorFeatures:
    """
    Transform a behavioral delta into a flat feature vector.

    Args:
        delta: merged FileBehavior representing ONLY new behaviors
        files_added: list of new file paths
        files_modified: list of changed file paths
    """
    f = BehaviorFeatures()

    # --- Network ---
    net_modules = BehaviorExtractor.NETWORK_MODULES
    f.new_network_imports = len(delta.imports & net_modules)
    f.new_network_calls = sum(
        1 for c in delta.calls
        if any(c.startswith(m) for m in net_modules)
        or c in ("urlopen", "urlretrieve")
    )
    f.new_external_urls = sum(
        1 for s in delta.string_literals
        if "http://" in s or "https://" in s
    )

    # --- Execution ---
    f.new_exec_calls = delta.exec_nodes
    f.new_dynamic_imports = sum(
        1 for c in delta.calls
        if c in ("__import__",) or "importlib" in c
    )
    f.new_subprocess_calls = sum(
        1 for c in delta.calls
        if any(c.startswith(p) for p in ("subprocess.", "os.system", "os.popen", "os.exec"))
    )

    # --- File / sensitive access ---
    f.new_file_access = sum(
        1 for c in delta.calls
        if c in ("open", "builtins.open") or c.startswith("io.")
        or c.startswith("pathlib.") and any(w in c for w in ("read", "write", "open"))
    )
    f.new_env_access = sum(
        1 for a in delta.attribute_access
        if "environ" in a or "getenv" in a or "putenv" in a
    ) + sum(
        1 for c in delta.calls
        if "getenv" in c or "environ" in c
    )
    f.new_sensitive_paths = sum(
        1 for s in delta.string_literals
        if any(p in s for p in ("/.ssh/", "/.aws/", "/etc/passwd", "/etc/shadow", ".env"))
    )

    # --- Obfuscation ---
    obf_calls = BehaviorExtractor.OBFUSCATION_CALLS
    f.new_obfuscation_calls = sum(1 for c in delta.calls if c in obf_calls)
    f.new_encoded_strings = sum(
        1 for s in delta.string_literals if s.startswith("[encoded:")
    )
    f.new_dynamic_attrs = delta.dynamic_attrs

    # --- Supply chain ---
    supply_chain_files = {"setup.py", "setup.cfg", "pyproject.toml", "package.json"}
    f.setup_script_changed = any(
        any(f_name.endswith(sc) for sc in supply_chain_files)
        for f_name in files_modified + files_added
    )
    f.install_hooks_added = any(
        "install" in c.lower() for c in delta.calls
        if "cmdclass" in c or "install" in c.lower()
    )
    f.new_entry_points = any(
        "entry_points" in a or "console_scripts" in a
        for a in delta.attribute_access | delta.string_literals
    )

    # --- Structural ---
    f.new_try_except_blocks = delta.try_except
    f.new_imports_total = len(delta.imports) + len(delta.from_imports)

    # --- Entropy ---
    # Rough measure: more new behaviors = higher entropy increase
    behavior_count = (
        len(delta.imports) + len(delta.calls) +
        len(delta.attribute_access) + len(delta.string_literals) +
        delta.exec_nodes + delta.dynamic_attrs
    )
    f.entropy_increase = round(math.log(behavior_count + 1) / 5.0, 3)

    return f


def apply_call_mutations(features: BehaviorFeatures, mutations: list) -> BehaviorFeatures:
    """
    Populate the argument-mutation fields from call_diff results.
    Accepts list of CallMutation objects.
    """
    for m in mutations:
        features.suspicious_argument_change += 1
        if m.kind == "url_changed":
            features.modified_network_targets += 1
        elif m.kind == "sensitive_added":
            features.new_sensitive_data_flow += 1
    return features
