from __future__ import annotations

from typing import Any

from services.base import BaseSecurityStep
from ai.prompts import SECURITY_TEST_GENERATION_PROMPT
from database.models import (
    AttackScenario,
    ProjectStage,
    RiskLevel,
    SecurityTest,
    Threat,
    ValidationStatus,
)

class SecurityTestGenerator(BaseSecurityStep):
    name = "Security Test Generation"
    stage = ProjectStage.TEST_GENERATION

    def run(self, project_id: str, context: dict[str, Any]) -> dict[str, Any]:
        scenario_ids = context.get("attack_scenario_ids")
        query = self.db.query(AttackScenario)
        if scenario_ids:
            query = query.filter(AttackScenario.id.in_(scenario_ids))
        else:
            query = query.join(Threat).filter(Threat.project_id == project_id)
        scenarios = query.all()

        created = []
        counter = self.db.query(SecurityTest).join(Threat).filter(Threat.project_id == project_id).count() + 1

        for scenario in scenarios:
            threat = scenario.threat
            if self.llm.settings.llm_provider == "mock":
                data = self._deterministic(threat, scenario)
            else:
                user_prompt = (
                    f"THREAT: {threat.title} — {threat.description}\n"
                    f"STRIDE: {threat.stride_category.value}\n"
                    f"ATTACK SCENARIO: attacker={scenario.attacker_profile}; target={scenario.target}; "
                    f"objective={scenario.objective}; narrative={scenario.scenario_narrative}\n"
                    f"EXPECTED SECURE BEHAVIOR: {scenario.expected_secure_behavior}"
                )
                resp = self.llm.complete(SECURITY_TEST_GENERATION_PROMPT, user_prompt)
                data = resp.json()

            test = SecurityTest(
                display_id=f"TC-{counter:03d}",
                threat_id=threat.id,
                attack_scenario_id=scenario.id,
                objective=data["objective"],
                preconditions=data.get("preconditions"),
                endpoint=data.get("endpoint"),
                http_method=data.get("http_method"),
                required_role=data.get("required_role"),
                test_steps=data.get("test_steps", []),
                expected_result=data.get("expected_result"),
                validation_criteria=data.get("validation_criteria"),
                risk_level=RiskLevel(data.get("risk_level", "Medium")),
                validation_status=ValidationStatus.PENDING,
            )
            counter += 1
            self.db.add(test)
            created.append(test)

        self.db.commit()
        return {
            "security_test_ids": [t.id for t in created],
            "_summary": {"tests_created": len(created)},
            "_reasoning": f"Generated {len(created)} security tests, each traceable to exactly one threat and attack scenario.",
        }

    def _deterministic(self, threat: Threat, scenario: AttackScenario) -> dict:
        asset = threat.affected_asset
        endpoint_guess = f"/{(asset.name.lower().replace(' ', '-') if asset else 'resource')}/{{id}}"
        stride = threat.stride_category.value

        steps_by_category = {
            "Elevation of Privilege": [
                "Authenticate as a low-privilege user in the authorized test environment.",
                f"Send a request to {endpoint_guess} for a resource owned by a DIFFERENT user/role.",
                "Record the HTTP status code and response body.",
                "Repeat once against an admin-only endpoint using the same low-privilege session.",
            ],
            "Tampering": [
                "Authenticate as a normal user.",
                f"Submit a request to {endpoint_guess} with a modified identifier or an unexpected field "
                "(e.g. a role/price field) included in the payload.",
                "Record whether the modification was accepted or rejected.",
            ],
            "Information Disclosure": [
                f"Send an unauthenticated or low-privilege request to {endpoint_guess}.",
                "Inspect the response for fields, stack traces, or existence signals beyond what the "
                "requester's role should see.",
            ],
            "Spoofing": [
                "Attempt authentication with invalid, expired, or malformed credentials/tokens.",
                "Observe whether the system enforces rate limiting/lockout after repeated attempts.",
            ],
            "Denial of Service": [
                f"Send a bounded burst of {8} requests to {endpoint_guess} within a short window "
                "(capped well under the platform's execution_max_requests_per_test limit).",
                "Observe response latency/status for signs of missing rate limiting.",
            ],
            "Repudiation": [
                "Perform a sensitive action (e.g. state-changing request) as an authenticated user.",
                "Verify whether a corresponding audit log entry can be independently confirmed to exist.",
            ],
        }

        return {
            "objective": f"Verify whether '{threat.title}' is exploitable on {asset.name if asset else 'the target asset'}.",
            "preconditions": scenario.precondition,
            "endpoint": endpoint_guess,
            "http_method": "GET" if stride in {"Information Disclosure", "Spoofing"} else "POST",
            "required_role": "authenticated user (non-privileged)",
            "test_steps": steps_by_category.get(stride, [
                "Send a bounded set of requests matching the attack scenario's narrative.",
                "Record actual vs. expected secure behavior.",
            ]),
            "expected_result": scenario.expected_secure_behavior,
            "validation_criteria": "PASS if the server enforces the expected secure behavior "
                                    "(e.g. 401/403, no data disclosed, no state change accepted); "
                                    "FAIL if the unauthorized action succeeds.",
            "risk_level": threat.impact if threat.impact in {"Critical", "High", "Medium", "Low"} else "Medium",
        }
