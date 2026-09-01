"""
datetime.utcnow() is deprecated (it returns a naive datetime with no
timezone info, which is easy to misuse). The modern replacement is
datetime.now(timezone.utc) — but that returns a timezone-AWARE datetime,
and this project's database columns and existing comparisons
(e.g. `execution.finished_at or execution.started_at or datetime.min`)
all use naive datetimes. Mixing aware and naive datetimes in the same
comparison raises a TypeError.

now_utc() gets the deprecation fix without changing that storage
convention: it takes the correct timezone-aware "now," then strips the
tzinfo before returning, so every existing comparison/sort in the
codebase keeps working exactly as before.
"""
from __future__ import annotations

from datetime import datetime, timezone


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
