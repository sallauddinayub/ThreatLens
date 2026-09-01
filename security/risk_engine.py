"""
Pure risk-scoring math, with no database dependency, so the formula that
turns (likelihood, impact, exploitability, asset criticality, confidence)
into a composite score and a Critical/High/Medium/Low/Informational level
can be tested, explained, and reused (e.g. for the Security Posture Score)
independently of how threats are fetched from the database.

Weights are explicit and documented so the score is explainable, not a
black box. Confirmed exploitation (a FAILED/vulnerable test execution) is
weighted heavily because it moves a threat from "theoretical" to
"demonstrated."
"""
from __future__ import annotations

from dataclasses import dataclass

LEVEL_SCORE = {"Critical": 1.0, "High": 0.8, "Medium": 0.5, "Low": 0.25, "Informational": 0.1}
CRITICALITY_SCORE = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25}

WEIGHTS = {
    "likelihood": 0.20,
    "impact": 0.30,
    "exploitability": 0.25,
    "asset_criticality": 0.15,
    "confidence": 0.10,
}


@dataclass
class RiskScoreResult:
    likelihood_score: float
    impact_score: float
    exploitability_score: float
    asset_criticality_score: float
    confidence_score: float
    composite_score: float
    risk_level: str
    rationale: str


def score_to_level(composite: float) -> str:
    if composite >= 0.85:
        return "Critical"
    if composite >= 0.65:
        return "High"
    if composite >= 0.4:
        return "Medium"
    if composite >= 0.2:
        return "Low"
    return "Informational"


def compute_risk_score(
    likelihood: str, impact: str, exploitability_score: float,
    asset_criticality: str, confidence: float,
) -> RiskScoreResult:
    likelihood_score = LEVEL_SCORE.get(likelihood, 0.5)
    impact_score = LEVEL_SCORE.get(impact, 0.5)
    asset_criticality_score = CRITICALITY_SCORE.get(asset_criticality, 0.5)
    confidence_score = confidence if confidence is not None else 0.5

    composite = (
        WEIGHTS["likelihood"] * likelihood_score
        + WEIGHTS["impact"] * impact_score
        + WEIGHTS["exploitability"] * exploitability_score
        + WEIGHTS["asset_criticality"] * asset_criticality_score
        + WEIGHTS["confidence"] * confidence_score
    )
    level = score_to_level(composite)
    rationale = (
        f"composite={composite:.2f} = 0.20*likelihood({likelihood_score}) + "
        f"0.30*impact({impact_score}) + 0.25*exploitability({exploitability_score}) + "
        f"0.15*asset_criticality({asset_criticality_score}) + 0.10*confidence({confidence_score})"
    )
    return RiskScoreResult(
        likelihood_score=likelihood_score, impact_score=impact_score,
        exploitability_score=exploitability_score, asset_criticality_score=asset_criticality_score,
        confidence_score=confidence_score, composite_score=composite, risk_level=level, rationale=rationale,
    )


def compute_security_posture_score(risk_level_counts: dict[str, int], validation_pass_rate: float) -> int:
    """
    A project-defined 0-100 "Security Posture Score" (Section 18) — NOT an
    official industry certification score, and the UI must say so
    explicitly. Derived transparently from the same risk data already on
    screen: it starts at 100 and subtracts a fixed penalty per open
    Critical/High/Medium finding, then blends in how much of the generated
    test suite actually passed validation (a very invalid test suite
    suggests the analysis itself is shaky, which should also depress
    confidence in the posture score).
    """
    total_threats = sum(risk_level_counts.values())
    if total_threats == 0:
        return 100  # nothing analyzed yet defaults to a neutral/perfect score, not a misleadingly low one

    penalty = (
        risk_level_counts.get("Critical", 0) * 12
        + risk_level_counts.get("High", 0) * 6
        + risk_level_counts.get("Medium", 0) * 2
        + risk_level_counts.get("Low", 0) * 0.5
    )
    base_score = max(0.0, 100.0 - penalty)
    # blend in validation health: a suite full of INVALID/NEEDS REVIEW tests
    # means less confidence in "how well-tested" this posture actually is
    blended = base_score * (0.7 + 0.3 * validation_pass_rate)
    return int(round(max(0.0, min(100.0, blended))))
