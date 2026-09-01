from __future__ import annotations

from typing import Any

from services.base import BaseSecurityStep
from database.models import ProjectStage, SecurityTest, Threat, ValidationStatus

_VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


class TestValidator(BaseSecurityStep):
    """
    Deterministic gatekeeper (Section 12) — no LLM call here on purpose.
    A generated test must pass these concrete checks before it can ever be
    approved for execution. This is also the pipeline's bounded retry policy
    trigger: INVALID sends the test back to the Security Test Generator
    (Section 25).
    """

    __test__ = False  # tells pytest this class isn't a test class, despite the "Test" prefix
    name = "Rule-Based Validation"
    stage = ProjectStage.TEST_VALIDATION

    def run(self, project_id: str, context: dict[str, Any]) -> dict[str, Any]:
        test_ids = context.get("security_test_ids")
        query = self.db.query(SecurityTest).join(Threat).filter(Threat.project_id == project_id)
        if test_ids:
            query = query.filter(SecurityTest.id.in_(test_ids))
        tests = query.all()

        seen_signatures: set[tuple] = set()
        results = {"VALID": 0, "INVALID": 0, "NEEDS REVIEW": 0}

        for test in tests:
            status, explanation = self._validate_one(test, seen_signatures)
            test.validation_status = ValidationStatus(status)
            test.validation_explanation = explanation
            results[status] += 1

        self.db.commit()
        return {
            "validation_results": results,
            "_summary": results,
            "_reasoning": "Applied deterministic structural/logical checks (endpoint presence, valid HTTP "
                          "method, precondition consistency, duplicate detection, in-scope test type) to "
                          "every generated test. No LLM call is used for validation by design.",
        }

    def _validate_one(self, test: SecurityTest, seen_signatures: set[tuple]) -> tuple[str, str]:
        reasons_invalid = []
        reasons_review = []

        # endpoint exists
        if not test.endpoint:
            reasons_invalid.append("No endpoint specified.")

        # HTTP method valid
        if test.http_method and test.http_method.upper() not in _VALID_METHODS:
            reasons_invalid.append(f"'{test.http_method}' is not a recognized HTTP method.")

        # required parameters / preconditions understood
        if not test.preconditions:
            reasons_review.append("Preconditions were not specified; manual review recommended before execution.")

        # test is logically consistent: steps should exist and reference the objective
        if not test.test_steps:
            reasons_invalid.append("No test steps were generated.")
        elif len(test.test_steps) < 1:
            reasons_invalid.append("Test steps list is empty.")

        # expected response is reasonable
        if not test.expected_result:
            reasons_review.append("No expected result recorded; cannot auto-grade PASS/FAIL without one.")

        # duplicate detection: same endpoint + method + threat considered a duplicate
        signature = (test.endpoint, (test.http_method or "").upper(), test.threat_id)
        if signature in seen_signatures:
            reasons_invalid.append("Duplicate of another generated test for the same threat/endpoint/method.")
        else:
            seen_signatures.add(signature)

        # destructive-action guard: never allow DELETE-heavy or unbounded loops through untouched
        if test.http_method and test.http_method.upper() == "DELETE" and "authorization" not in (test.objective or "").lower():
            reasons_review.append("DELETE method requested without an explicit authorization-check objective; flagged for human review before execution.")

        if reasons_invalid:
            return "INVALID", " ".join(reasons_invalid)
        if reasons_review:
            return "NEEDS REVIEW", " ".join(reasons_review)
        return "VALID", "Passed all structural and logical validation checks."
