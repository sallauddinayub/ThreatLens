"""
This module is the single choke point through which every active test
request must pass before it is allowed to touch a network socket
No pipeline step or API route should call
requests/httpx directly against a target — everything routes through
`assert_target_authorized()` first, and the execution engine re-checks it
immediately before every single HTTP call, not just once per test run.

Design intent: even if an LLM-generated test case tries to point at
"api.some-random-company.com", this module refuses to execute it. Prompting
alone is not treated as a security control here — enforcement is in code.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

from config import get_settings


class AuthorizationError(Exception):
    """Raised when a target/project is not cleared for active testing."""


@dataclass
class Project:
    """Minimal shape the checker needs; pass in the real ORM Project object."""
    authorized_for_active_testing: bool
    allowlisted_targets: list[str]


def _host_matches_allowlist(host: str, allowlist: list[str]) -> bool:
    host = host.lower().strip()
    for entry in allowlist:
        entry = entry.lower().strip()
        if host == entry:
            return True
        # allow simple subdomain wildcards like *.internal-staging.example.com
        if entry.startswith("*.") and host.endswith(entry[1:]):
            return True
    # Loopback IPs are always implicitly local, regardless of allowlist text
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return True
    except ValueError:
        pass
    return False


def assert_target_authorized(url: str, project: Project) -> None:
    """
    Raise AuthorizationError unless:
      1. The project has been explicitly marked authorized_for_active_testing
         (this requires the user to have submitted the confirmation statement
         from Section 30 — enforced at the API layer when authorization is set).
      2. The URL's host is present in BOTH the project's own allowlisted_targets
         AND the platform-wide execution_target_allowlist is not violated
         (project allowlist is the authority; the global list only supplies
         universal safe defaults like localhost).
    """
    settings = get_settings()

    if settings.execution_require_explicit_authorization and not project.authorized_for_active_testing:
        raise AuthorizationError(
            "This project has not been explicitly authorized for active testing. "
            "A user with appropriate rights must submit the authorization "
            "confirmation before any test can be executed."
        )

    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname
    if not host:
        raise AuthorizationError(f"Could not parse a host from target URL: {url!r}")

    combined_allowlist = list(project.allowlisted_targets) + list(settings.execution_target_allowlist)
    if not _host_matches_allowlist(host, combined_allowlist):
        raise AuthorizationError(
            f"Target host '{host}' is not on the authorized allowlist for this "
            f"project. Add it explicitly to the project's allowlisted_targets "
            f"before it can be tested. Refusing to execute."
        )
