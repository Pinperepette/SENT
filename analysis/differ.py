from __future__ import annotations

"""
Core diff engine.

Pipeline:
  1. Download old + new package versions
  2. Extract archives
  3. Compute file-level diff (added / removed / modified)
  4. For Python files → AST behavioral analysis (new pipeline)
  5. For non-Python files → regex pattern scan (legacy fallback)
  6. Extract features, compare to baseline, compute behavioral score
  7. Return structured DiffReport
"""

import difflib
import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterator

import httpx

from analysis.ast_analyzer import (
    FileBehavior,
    diff_behaviors,
    extract_behavior,
    merge_behaviors,
)
from analysis.baseline import (
    AnomalyReport,
    detect_anomalies,
    init_baseline_table,
    load_baseline,
    save_baseline,
    update_baseline_from_behavior,
)
from analysis.behavioral_scorer import (
    classify_from_score,
    compute_behavioral_score,
)
from analysis.call_diff import CallMutation, diff_call_arguments
from analysis.feature_extractor import (
    BehaviorFeatures,
    apply_call_mutations,
    extract_features,
)
from analysis.patterns import is_high_risk_new_file, is_scannable, scan_line
from config import PACKAGE_CACHE_DIR
from storage.models import DiffFlag, DiffReport


# ---------------------------------------------------------------------------
# Package downloading
# ---------------------------------------------------------------------------

def _pypi_sdist_url(name: str, version: str) -> str | None:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        resp = httpx.get(url, timeout=30, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        for u in data.get("urls", []):
            if u.get("packagetype") == "sdist":
                return u["url"]
        urls = data.get("urls", [])
        return urls[0]["url"] if urls else None
    except Exception:
        return None


def _npm_tarball_url(name: str, version: str) -> str | None:
    url = f"https://registry.npmjs.org/{name}/{version}"
    try:
        resp = httpx.get(url, timeout=30, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        return data.get("dist", {}).get("tarball")
    except Exception:
        return None


def _download(url: str) -> bytes:
    resp = httpx.get(url, timeout=60, follow_redirects=True)
    resp.raise_for_status()
    return resp.content


def _download_cached(ecosystem: str, name: str, version: str, url: str) -> bytes:
    """Download with cache. Returns archive bytes."""
    from analysis.download_cache import get_cached, put_cached, cache_metrics
    cached = get_cached(ecosystem, name, version)
    if cached is not None:
        cache_metrics.hit(len(cached))
        return cached
    cache_metrics.miss()
    data = _download(url)
    put_cached(ecosystem, name, version, data)
    return data


# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------

def _extract_tar(data: bytes) -> dict[str, str]:
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            parts = PurePosixPath(member.name).parts
            rel = str(PurePosixPath(*parts[1:])) if len(parts) > 1 else member.name
            try:
                files[rel] = f.read().decode("utf-8", errors="replace")
            except Exception:
                pass
    return files


def _extract_zip(data: bytes) -> dict[str, str]:
    files = {}
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            parts = PurePosixPath(info.filename).parts
            rel = str(PurePosixPath(*parts[1:])) if len(parts) > 1 else info.filename
            try:
                files[rel] = zf.read(info).decode("utf-8", errors="replace")
            except Exception:
                pass
    return files


def _extract(data: bytes, filename: str = "") -> dict[str, str]:
    try:
        return _extract_tar(data)
    except Exception:
        pass
    try:
        return _extract_zip(data)
    except Exception:
        pass
    raise ValueError(f"Cannot extract archive: {filename}")


# ---------------------------------------------------------------------------
# File-level diff
# ---------------------------------------------------------------------------

def compute_file_diff(
    old_files: dict[str, str],
    new_files: dict[str, str],
) -> tuple[list[str], list[str], list[str]]:
    old_set = set(old_files.keys())
    new_set = set(new_files.keys())
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    modified = sorted(
        f for f in (old_set & new_set)
        if old_files[f] != new_files[f]
    )
    return added, removed, modified


# ---------------------------------------------------------------------------
# Line-level diff helpers
# ---------------------------------------------------------------------------

def added_lines(old_content: str, new_content: str) -> Iterator[tuple[int, str]]:
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    sm = difflib.SequenceMatcher(None, old_lines, new_lines)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):
            for idx in range(j1, j2):
                yield (idx + 1, new_lines[idx].rstrip("\n\r"))


def all_lines(content: str) -> Iterator[tuple[int, str]]:
    for i, line in enumerate(content.splitlines(), 1):
        yield (i, line)


def _is_python(filepath: str) -> bool:
    return filepath.endswith(".py")


# ---------------------------------------------------------------------------
# AST behavioral pipeline (Python files)
# ---------------------------------------------------------------------------

def _analyze_python_behavioral(
    old_files: dict[str, str],
    new_files: dict[str, str],
    added_f: list[str],
    modified_f: list[str],
) -> tuple[list[FileBehavior], list[DiffFlag], list[CallMutation]]:
    """
    Run AST analysis on Python files.

    Returns:
        (behavioral deltas, DiffFlags, CallMutations for argument-level changes)
    """
    deltas = []
    flags = []
    all_mutations: list[CallMutation] = []

    # New Python files — full behavior is the delta
    for filepath in added_f:
        if not _is_python(filepath):
            continue
        content = new_files.get(filepath, "")
        new_behavior = extract_behavior(content)
        deltas.append(new_behavior)

        for call in new_behavior.calls:
            flags.append(DiffFlag(
                category=_categorize_call(call),
                pattern=f"ast:call:{call}",
                score=0,
                file_path=filepath,
                line_number=0,
                snippet=f"New call: {call}",
            ))
        for imp in new_behavior.imports:
            flags.append(DiffFlag(
                category=_categorize_import(imp),
                pattern=f"ast:import:{imp}",
                score=0,
                file_path=filepath,
                line_number=0,
                snippet=f"New import: {imp}",
            ))

    # Modified Python files — behavioral diff + argument-level diff
    for filepath in modified_f:
        if not _is_python(filepath):
            continue
        old_content = old_files.get(filepath, "")
        new_content = new_files.get(filepath, "")

        # Behavioral diff (new calls/imports/attrs)
        old_behavior = extract_behavior(old_content)
        new_behavior = extract_behavior(new_content)
        delta = diff_behaviors(old_behavior, new_behavior)
        deltas.append(delta)

        for call in delta.calls:
            flags.append(DiffFlag(
                category=_categorize_call(call),
                pattern=f"ast:new_call:{call}",
                score=0,
                file_path=filepath,
                line_number=0,
                snippet=f"Newly introduced call: {call}",
            ))
        for imp in delta.imports:
            flags.append(DiffFlag(
                category=_categorize_import(imp),
                pattern=f"ast:new_import:{imp}",
                score=0,
                file_path=filepath,
                line_number=0,
                snippet=f"Newly introduced import: {imp}",
            ))
        for attr in delta.attribute_access:
            cat = "sensitive" if any(s in attr for s in ("environ", "ssh", "aws")) else "execution"
            flags.append(DiffFlag(
                category=cat,
                pattern=f"ast:new_attr:{attr}",
                score=0,
                file_path=filepath,
                line_number=0,
                snippet=f"Newly introduced access: {attr}",
            ))

        # Argument-level diff (changed URLs, added sensitive args, etc.)
        mutations = diff_call_arguments(old_content, new_content, filepath)
        all_mutations.extend(mutations)

        for m in mutations:
            cat = "sensitive" if m.kind == "sensitive_added" else "network" if m.kind == "url_changed" else "execution"
            flags.append(DiffFlag(
                category=cat,
                pattern=f"mutation:{m.kind}",
                score=0,
                file_path=m.file_path,
                line_number=m.line,
                snippet=f"{m.description} [{m.old_value} → {m.new_value}]",
            ))

    return deltas, flags, all_mutations


def _categorize_call(call: str) -> str:
    from analysis.ast_analyzer import BehaviorExtractor
    if call in BehaviorExtractor.EXEC_FUNCTIONS or call in ("eval", "exec", "compile"):
        return "execution"
    if any(call.startswith(m) for m in BehaviorExtractor.NETWORK_MODULES):
        return "network"
    if any(call.startswith(p) for p in ("subprocess.", "os.system", "os.popen")):
        return "execution"
    if call in BehaviorExtractor.OBFUSCATION_CALLS:
        return "obfuscation"
    if "environ" in call or "getenv" in call:
        return "sensitive"
    return "execution"


def _categorize_import(imp: str) -> str:
    from analysis.ast_analyzer import BehaviorExtractor
    if imp in BehaviorExtractor.NETWORK_MODULES:
        return "network"
    if imp in BehaviorExtractor.CRYPTO_MODULES:
        return "sensitive"
    if imp in ("subprocess", "os", "sys", "ctypes"):
        return "execution"
    return "execution"


# ---------------------------------------------------------------------------
# Regex fallback (non-Python files)
# ---------------------------------------------------------------------------

def _analyze_regex_fallback(
    old_files: dict[str, str],
    new_files: dict[str, str],
    added_f: list[str],
    modified_f: list[str],
) -> list[DiffFlag]:
    """Regex scan for non-Python files (JS, config, shell, etc.)."""
    flags = []

    for filepath in added_f:
        if _is_python(filepath) or not is_scannable(filepath):
            continue
        if is_high_risk_new_file(filepath):
            flags.append(DiffFlag(
                category="supply_chain", pattern="new_high_risk_file",
                score=10, file_path=filepath, line_number=0,
                snippet=f"New file: {filepath}",
            ))
        content = new_files.get(filepath, "")
        for line_num, line in all_lines(content):
            for rule, matched in scan_line(line):
                flags.append(DiffFlag(
                    category=rule.category, pattern=rule.name,
                    score=rule.score, file_path=filepath,
                    line_number=line_num, snippet=line.strip()[:200],
                ))

    for filepath in modified_f:
        if _is_python(filepath) or not is_scannable(filepath):
            continue
        if is_high_risk_new_file(filepath):
            flags.append(DiffFlag(
                category="supply_chain", pattern="modified_high_risk_file",
                score=5, file_path=filepath, line_number=0,
                snippet=f"Modified: {filepath}",
            ))
        old_content = old_files.get(filepath, "")
        new_content = new_files.get(filepath, "")
        for line_num, line in added_lines(old_content, new_content):
            for rule, matched in scan_line(line):
                flags.append(DiffFlag(
                    category=rule.category, pattern=rule.name,
                    score=rule.score, file_path=filepath,
                    line_number=line_num, snippet=line.strip()[:200],
                ))

    # Apply context filter to regex flags
    from analysis.context_filter import apply_context_filter
    return apply_context_filter(flags)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_package(
    name: str,
    ecosystem: str,
    new_version: str,
    old_version: str,
) -> DiffReport:
    """
    Full analysis pipeline:
      1. Download + extract both versions
      2. File-level diff
      3. Python files → AST behavioral analysis
      4. Non-Python files → regex fallback
      5. Feature extraction → baseline comparison → behavioral scoring
      6. Return DiffReport
    """
    init_baseline_table()

    report = DiffReport(
        package_name=name,
        ecosystem=ecosystem,
        version=new_version,
        previous_version=old_version,
    )

    # --- Download ---
    if ecosystem == "pypi":
        old_url = _pypi_sdist_url(name, old_version)
        new_url = _pypi_sdist_url(name, new_version)
    else:
        old_url = _npm_tarball_url(name, old_version)
        new_url = _npm_tarball_url(name, new_version)

    if not new_url:
        report.summary = f"Could not find download URL for {name}@{new_version}"
        return report

    new_data = _download_cached(ecosystem, name, new_version, new_url)
    new_files = _extract(new_data)

    if not old_url or not old_version:
        old_files: dict[str, str] = {}
    else:
        try:
            old_data = _download_cached(ecosystem, name, old_version, old_url)
            old_files = _extract(old_data)
        except Exception:
            old_files = {}

    # --- File diff ---
    added_f, removed_f, modified_f = compute_file_diff(old_files, new_files)
    report.files_added = added_f
    report.files_removed = removed_f
    report.files_modified = modified_f

    # --- AST behavioral analysis (Python files) ---
    deltas, ast_flags, mutations = _analyze_python_behavioral(
        old_files, new_files, added_f, modified_f,
    )

    # Merge all per-file deltas into a single package-level delta
    merged_delta = merge_behaviors(deltas)

    # Also extract FULL behavior of new version (for baseline update)
    all_py_files = [f for f in new_files if _is_python(f)]
    full_behaviors = [extract_behavior(new_files[f]) for f in all_py_files]
    full_merged = merge_behaviors(full_behaviors) if full_behaviors else FileBehavior()

    # --- Feature extraction ---
    features = extract_features(merged_delta, added_f, modified_f)

    # --- Apply argument-level mutations to features ---
    features = apply_call_mutations(features, mutations)

    # --- Baseline comparison ---
    baseline = load_baseline(name, ecosystem)
    anomalies = detect_anomalies(baseline, features, merged_delta.imports)

    # --- Behavioral scoring ---
    behavioral_score, explanations = compute_behavioral_score(features, anomalies)

    # --- Regex fallback for non-Python files ---
    regex_flags = _analyze_regex_fallback(old_files, new_files, added_f, modified_f)
    regex_score = sum(f.score for f in regex_flags)

    # --- Combine scores ---
    # Behavioral score dominates for Python; regex adds signal for non-Python
    total_score = behavioral_score + regex_score

    # Set all AST flag scores proportionally now that we have a total
    if ast_flags and behavioral_score > 0:
        per_flag = max(1, behavioral_score // len(ast_flags))
        for flag in ast_flags:
            flag.score = per_flag

    all_flags = ast_flags + regex_flags
    report.flags = all_flags
    report.risk_score = total_score

    # --- Build summary ---
    summary_parts = []
    if behavioral_score > 0:
        nz = features.nonzero_features()
        feat_str = ", ".join(f"{k}={v}" for k, v in sorted(nz.items())[:6])
        summary_parts.append(f"Behavioral: {behavioral_score} [{feat_str}]")
    if regex_score > 0:
        summary_parts.append(f"Regex(non-py): {regex_score}")
    if anomalies.anomaly_count > 0:
        summary_parts.append(f"Anomalies: {anomalies.anomaly_count}")
    summary_parts.append(
        f"Files: +{len(added_f)} -{len(removed_f)} ~{len(modified_f)}"
    )
    report.summary = " | ".join(summary_parts) if summary_parts else "Clean diff"

    # Attach features + anomalies + explanations to report for downstream use
    report._features = features
    report._anomalies = anomalies
    report._explanations = explanations

    # --- Update baseline for next time ---
    updated_baseline = update_baseline_from_behavior(
        baseline,
        full_merged.imports,
        full_merged.calls,
        full_merged.attribute_access,
    )
    save_baseline(name, ecosystem, updated_baseline)

    return report


def analyze_local(
    old_dir: str | Path,
    new_dir: str | Path,
    name: str = "local",
    ecosystem: str = "local",
) -> DiffReport:
    """Analyze two local directories (for testing)."""
    old_path = Path(old_dir)
    new_path = Path(new_dir)

    def read_tree(root: Path) -> dict[str, str]:
        files = {}
        for p in root.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(root))
                try:
                    files[rel] = p.read_text(errors="replace")
                except Exception:
                    pass
        return files

    old_files = read_tree(old_path) if old_path.exists() else {}
    new_files = read_tree(new_path)
    added_f, removed_f, modified_f = compute_file_diff(old_files, new_files)

    from analysis.baseline import PackageBaseline

    deltas, ast_flags, mutations = _analyze_python_behavioral(
        old_files, new_files, added_f, modified_f,
    )
    merged_delta = merge_behaviors(deltas)
    features = extract_features(merged_delta, added_f, modified_f)
    features = apply_call_mutations(features, mutations)
    baseline = PackageBaseline()
    anomalies = detect_anomalies(baseline, features, merged_delta.imports)
    score, explanations = compute_behavioral_score(features, anomalies)

    regex_flags = _analyze_regex_fallback(old_files, new_files, added_f, modified_f)

    report = DiffReport(
        package_name=name, ecosystem=ecosystem,
        version="new", previous_version="old",
        files_added=added_f, files_removed=removed_f, files_modified=modified_f,
        flags=ast_flags + regex_flags,
        risk_score=score + sum(f.score for f in regex_flags),
    )
    report._features = features
    report._anomalies = anomalies
    report._explanations = explanations
    return report
