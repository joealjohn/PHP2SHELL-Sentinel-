from __future__ import annotations

from packaging.version import InvalidVersion, Version


def parse_version(value: str) -> Version | None:
    try:
        return Version(value.strip())
    except (InvalidVersion, AttributeError, TypeError):
        return None


def compare_versions(a: str, b: str) -> int:
    """Semantic/permissive version comparison. Correct for 8.4.9 < 8.4.27."""
    va, vb = parse_version(a), parse_version(b)
    if va is None or vb is None:
        return 0
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def is_below(detected: str, fixed: str) -> bool:
    return compare_versions(detected, fixed) == -1


def is_at_least(detected: str, minimum: str) -> bool:
    return compare_versions(detected, minimum) >= 0
