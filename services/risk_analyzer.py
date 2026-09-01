from __future__ import annotations

from datetime import datetime
from typing import Any

from services.base import BaseSecurityStep
from database.models import ExecutionStatus, ProjectStage, RiskAssessment, RiskLevel, Threat
from security.risk_engine import compute_risk_score


class RiskAnalyzer(BaseSecurityStep):
    """
    Fetches threats from the database and delegates the actual scoring math
    to security.risk_engine.compute_risk_score, which has no DB dependency
    and can be unit-tested/reused (e.g. for the Security Posture Score) in
    isolation from SQLAlchemy sessions.
    """

    name = "Risk Analysis"
    stage = ProjectStage.RISK_PRIORITIZATION

    def run(self, project_id: str, context: dict[str, Any]) -> dict[str, Any]:
        threats: list[Threat] = self.db.query(Threat).filter(Threat.project_id == project_id).all()
        level_counts = {level.value: 0 for level in RiskLevel}

        for threat in threats:
            asset_criticality = threat.affected_asset.criticality if threat.affected_asset else "Medium"
            exploitability_score = self._exploitability_from_executions(threat)

            result = compute_risk_score(
                likelihood=threat.likelihood, impact=threat.impact,
                exploitability_score=exploitability_score,
                asset_criticality=asset_criticality, confidence=threat.confidence,
            )
            level_counts[result.risk_level] += 1

            existing = threat.risk_assessment
            if existing:
                existing.likelihood_score = result.likelihood_score
                existing.impact_score = result.impact_score
                existing.exploitability_score = result.exploitability_score
                existing.asset_criticality_score = result.asset_criticality_score
                existing.confidence_score = result.confidence_score
                existing.composite_score = result.composite_score
                existing.risk_level = RiskLevel(result.risk_level)
                existing.rationale = result.rationale
            else:
                self.db.add(RiskAssessment(
                    threat_id=threat.id,
                    likelihood_score=result.likelihood_score,
                    impact_score=result.impact_score,
                    exploitability_score=result.exploitability_score,
                    asset_criticality_score=result.asset_criticality_score,
                    confidence_score=result.confidence_score,
                    composite_score=result.composite_score,
                    risk_level=RiskLevel(result.risk_level),
                    rationale=result.rationale,
                ))
            threat.risk_score = result.composite_score

        self.db.commit()
        return {
            "risk_level_counts": level_counts,
            "_summary": level_counts,
            "_reasoning": "Computed a transparent weighted composite score per threat "
                          "(likelihood 20%, impact 30%, exploitability 25%, asset criticality 15%, "
                          "confidence 10%); exploitability is boosted when a controlled test execution "
                          "actually demonstrated the vulnerability, and reduced when the most recent "
                          "re-test came back secure.",
        }

    def _exploitability_from_executions(self, threat: Threat) -> float:
        """
        Uses each test's MOST RECENT execution, not "was it ever FAILED" —
        otherwise a threat that was remediated and re-verified as fixed
        would stay stuck at maximum exploitability forever, which would
        defeat the entire point of the remediation -> re-test workflow.
        """
        latest_statuses = []
        for test in threat.security_tests:
            executions = sorted(
                test.executions, key=lambda e: e.finished_at or e.started_at or datetime.min
            )
            if executions:
                latest_statuses.append(executions[-1].status)

        if any(s == ExecutionStatus.FAILED for s in latest_statuses):  # currently vulnerable
            return 1.0
        if latest_statuses and all(s == ExecutionStatus.PASSED for s in latest_statuses):  # currently secure
            return 0.15
        return 0.5  # not yet executed / inconclusive
