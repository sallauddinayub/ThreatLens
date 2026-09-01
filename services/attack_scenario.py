from __future__ import annotations

from typing import Any

from services.base import BaseSecurityStep
from ai.prompts import ATTACK_SCENARIO_PROMPT
from database.models import AttackScenario, ProjectStage, Threat

_STRIDE_ATTACKER_DEFAULTS = {
    "Spoofing": "Unauthenticated or credential-stuffing attacker",
    "Tampering": "Authenticated normal user attempting to modify data outside their scope",
    "Repudiation": "Authenticated user attempting to perform an action without an audit trail",
    "Information Disclosure": "Authenticated normal user probing for over-exposed data",
    "Denial of Service": "Unauthenticated client issuing high-volume requests",
    "Elevation of Privilege": "Authenticated normal user attempting to reach admin-only functionality",
}

class AttackScenarioService(BaseSecurityStep):
    name = "Attack Scenario Generation"
    stage = ProjectStage.ATTACK_SCENARIO_GENERATION

    def run(self, project_id: str, context: dict[str, Any]) -> dict[str, Any]:
        threat_ids = context.get("threat_ids")
        query = self.db.query(Threat).filter(Threat.project_id == project_id)
        if threat_ids:
            query = query.filter(Threat.id.in_(threat_ids))
        threats = query.all()

        created = []
        for threat in threats:
            if self.llm.settings.llm_provider == "mock":
                data = self._deterministic(threat)
            else:
                asset_name = threat.affected_asset.name if threat.affected_asset else "the affected asset"
                user_prompt = (
                    f"THREAT:\ntitle={threat.title}\ndescription={threat.description}\n"
                    f"stride_category={threat.stride_category.value}\naffected_asset={asset_name}\n"
                    f"mitigation={threat.recommended_mitigation}"
                )
                resp = self.llm.complete(ATTACK_SCENARIO_PROMPT, user_prompt)
                data = resp.json()

            scenario = AttackScenario(
                threat_id=threat.id,
                attacker_profile=data["attacker_profile"],
                target=data["target"],
                objective=data["objective"],
                precondition=data["precondition"],
                scenario_narrative=data["scenario_narrative"],
                expected_secure_behavior=data["expected_secure_behavior"],
            )
            self.db.add(scenario)
            created.append(scenario)

        self.db.commit()
        return {
            "attack_scenario_ids": [s.id for s in created],
            "_summary": {"scenarios_created": len(created)},
            "_reasoning": f"Generated {len(created)} attack scenarios, one per threat, scoped for the authorized test environment only.",
        }

    def _deterministic(self, threat: Threat) -> dict:
        asset_name = threat.affected_asset.name if threat.affected_asset else "the affected asset"
        stride_val = threat.stride_category.value
        return {
            "attacker_profile": _STRIDE_ATTACKER_DEFAULTS.get(stride_val, "Authenticated normal user"),
            "target": asset_name,
            "objective": f"Demonstrate whether '{threat.title}' is exploitable against {asset_name}.",
            "precondition": "Valid, non-privileged authenticated session in the authorized test environment (or none, for unauthenticated checks).",
            "scenario_narrative": (
                f"Following the '{stride_val}' pattern, attempt the action described by the threat "
                f"('{threat.description}') against {asset_name} using only requests permitted within the "
                f"platform's controlled execution allowlist."
            ),
            "expected_secure_behavior": (
                "The system should reject the unauthorized action (e.g. 401/403), avoid disclosing "
                "resource existence or internal state, and enforce the mitigation: "
                f"{threat.recommended_mitigation or 'apply an explicit server-side control'}."
            ),
        }
