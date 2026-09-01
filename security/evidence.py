"""
Evidence collection. Split out from the execution engine so evidence
formatting/redaction rules live in one obvious place (Section 22) rather
than being buried inside the execution loop.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from database.models import Evidence, TestExecution

SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key"}


def redact_headers(headers: dict) -> dict:
    """Never persist raw Authorization/cookie/API-key headers into evidence."""
    redacted = {}
    for k, v in (headers or {}).items():
        redacted[k] = "***REDACTED***" if k.lower() in SENSITIVE_HEADER_NAMES else v
    return redacted


def collect_evidence(db: Session, execution: TestExecution, request_log: list[dict]) -> None:
    """
    Persists the evidence trail for a single test execution (Section 22):
    the request log (already redacted before it gets here) and an outcome
    note summarizing the final status. Kept intentionally simple — this is
    audit evidence for a human reviewer, not a full HAR capture.
    """
    db.add(Evidence(execution_id=execution.id, kind="request_log", content=str(request_log)))
    db.add(Evidence(
        execution_id=execution.id, kind="outcome_note",
        content=f"status={execution.status.value}; actual_result={execution.actual_result or ''}",
    ))
    db.commit()
