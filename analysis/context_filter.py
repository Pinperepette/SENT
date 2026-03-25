from __future__ import annotations

"""
Context-aware false positive reduction.

The raw pattern scanner flags everything — this module applies
contextual filters to suppress noise:

1. Test files: URLs in tests are almost always benign
2. Documentation: URLs in docs/comments are informational
3. Minified files: bundled JS is inherently noisy
4. Known safe patterns: re.compile != exec, TypeScript type defs, etc.
5. Self-referential code: a package manager using subprocess is expected
"""

import re
from pathlib import PurePosixPath
from storage.models import DiffFlag


# Paths that are inherently lower risk
TEST_PATTERNS = re.compile(
    r'(^|/)tests?/|_test\.py$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|test_.*\.py$|conftest\.py$'
)

DOC_PATTERNS = re.compile(
    r'(^|/)docs?/|\.rst$|\.md$|CHANGES|CHANGELOG|HISTORY|NEWS|AUTHORS|README'
)

MINIFIED_PATTERNS = re.compile(
    r'\.min\.[jt]s$|\.min\.css$|dist/.*\.[jt]s$|bundle\.[jt]s$'
)

TYPE_DEF_PATTERNS = re.compile(
    r'\.d\.[cm]?ts$|\.pyi$'
)

# Patterns that are almost never malicious in certain contexts
SAFE_PATTERN_IN_CONTEXT = {
    # re.compile() is not code execution
    "compile_call": re.compile(r're\.compile\s*\('),
    # token as a variable name in parsers/lexers
    "token_pattern": re.compile(r'\btoken\b\s*[=!<>]|\btoken\s+in\b|CancelToken|token_type|token\['),
}


def classify_file_risk(filepath: str) -> str:
    """Classify a file path into risk tiers: 'high', 'medium', 'low'."""
    if MINIFIED_PATTERNS.search(filepath):
        return "low"
    if TYPE_DEF_PATTERNS.search(filepath):
        return "low"
    if TEST_PATTERNS.search(filepath):
        return "low"
    if DOC_PATTERNS.search(filepath):
        return "low"
    return "high"


def apply_context_filter(flags: list[DiffFlag]) -> list[DiffFlag]:
    """
    Filter and re-score flags based on file context.

    - Flags in test/doc/minified files get score reduced by 80%
    - Safe patterns in context get score reduced by 90%
    - Flags in type definition files are dropped entirely
    """
    filtered = []

    for flag in flags:
        file_risk = classify_file_risk(flag.file_path)

        # Drop type definition file flags entirely
        if TYPE_DEF_PATTERNS.search(flag.file_path):
            continue

        new_score = flag.score

        # Reduce score for low-risk file contexts
        if file_risk == "low":
            new_score = max(1, flag.score // 5)  # 80% reduction, minimum 1

        # Check for safe pattern in context
        safe_re = SAFE_PATTERN_IN_CONTEXT.get(flag.pattern)
        if safe_re and safe_re.search(flag.snippet):
            new_score = max(1, new_score // 10)  # 90% reduction

        # External URLs in comments/docs are informational
        if flag.pattern == "external_url" and file_risk == "low":
            new_score = 1

        # Create adjusted flag
        filtered.append(DiffFlag(
            category=flag.category,
            pattern=flag.pattern,
            score=new_score,
            file_path=flag.file_path,
            line_number=flag.line_number,
            snippet=flag.snippet,
        ))

    return filtered
