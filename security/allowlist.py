"""
Target allowlist helpers. The actual enforcement logic lives in
authorization.py (assert_target_authorized is the single choke point every
execution must pass through) — this module exists as the clearly-named,
easy-to-find place for allowlist *management* concerns: normalizing entries,
checking membership without raising, and exposing the platform-wide default
allowlist to the UI layer so Settings can show what's globally trusted
(localhost/loopback) versus what's project-specific.
"""
from __future__ import annotations

from config import get_settings
from security.authorization import _host_matches_allowlist  # noqa: F401 (re-exported for callers)


def platform_default_allowlist() -> list[str]:
    """The hosts that are always safe regardless of project (localhost, loopback, demo-app)."""
    return list(get_settings().execution_target_allowlist)


def is_host_allowlisted(host: str, project_allowlist: list[str]) -> bool:
    """Non-raising membership check — used by the UI to show a status badge, not to gate execution."""
    combined = list(project_allowlist or []) + platform_default_allowlist()
    return _host_matches_allowlist(host, combined)
