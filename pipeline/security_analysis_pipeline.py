"""
Security Analysis Pipeline.

This is a fixed, deterministic pipeline, not an autonomous agent
orchestrator. The Python code below explicitly decides which step runs
next — there is no LLM making planning decisions, no dynamic task
delegation, and no component deciding on its own what to do. Every step
is a plain function/class call in a hard-coded sequence:

    System Analysis -> Asset Discovery -> Threat Modeling -> STRIDE
    -> Attack Scenario Generation -> Security Test Generation
    -> Rule-Based Validation -> Risk Analysis

Test generation includes one deliberate exception to "linear only": if
validation marks a generated test INVALID, the pipeline sends it back to
the test generator for a bounded number of retries (MAX_RETRIES). This is
a simple, Python-controlled retry policy — not the LLM or any component
deciding whether to retry. After MAX_RETRIES, the test is left as INVALID
for a human to review; the pipeline never loops indefinitely.

Test EXECUTION is intentionally NOT part of this function — it requires
explicit human approval and is triggered by a separate, later action, per
the human-approval requirement.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from database.models import Project, ProjectStage, SecurityTest, ValidationStatus
from services.asset_discovery import AssetDiscoveryService
from services.attack_scenario import AttackScenarioService
from services.risk_analyzer import RiskAnalyzer
from services.system_analysis import SystemAnalysisService
from services.test_generation import SecurityTestGenerator
from services.test_validation import TestValidator
from services.threat_modeling import ThreatModelingService

logger = logging.getLogger(__name__)

MAX_RETRIES = 2  # fixed retry policy for invalid test regeneration — not an autonomous decision


def run_security_analysis_pipeline(db: Session, project_id: str, initial_input: dict) -> dict:
    """
    Runs SYSTEM_ANALYSIS through RISK_ANALYSIS in a fixed order. Report
    generation is a separate explicit call (services/report_generator.py)
    since a user typically wants to review risk-prioritized results before
    committing to a report. Test EXECUTION is also a separate,
    explicitly-authorized action — this function only generates and
    validates tests, it never executes them.
    """
    project = db.get(Project, project_id)
    log = []

    project.stage = ProjectStage.SYSTEM_ANALYSIS
    db.commit()
    sa = SystemAnalysisService(db).execute_with_logging(project_id, initial_input)
    project.system_model = sa["system_model"]
    db.commit()
    log.append(("System Analysis", sa["_summary"]))

    project.stage = ProjectStage.ASSET_DISCOVERY
    db.commit()
    ad = AssetDiscoveryService(db).execute_with_logging(project_id, {"system_model": sa["system_model"]})
    log.append(("Asset Discovery", ad["_summary"]))

    project.stage = ProjectStage.THREAT_MODELING
    db.commit()
    tm = ThreatModelingService(db).execute_with_logging(project_id, {})
    log.append(("Threat Modeling", tm["_summary"]))
    # STRIDE_ANALYSIS is folded into ThreatModelingService's output (every
    # threat already carries a stride_category) — no separate call needed,
    # but the stage is still recorded for traceability/UI display.
    project.stage = ProjectStage.STRIDE_ANALYSIS
    db.commit()

    project.stage = ProjectStage.ATTACK_SCENARIO_GENERATION
    db.commit()
    asc = AttackScenarioService(db).execute_with_logging(project_id, {"threat_ids": tm["threat_ids"]})
    log.append(("Attack Scenario Generation", asc["_summary"]))

    project.stage = ProjectStage.TEST_GENERATION
    db.commit()
    test_gen_result = _generate_and_validate_with_retry(
        db, project_id, {"attack_scenario_ids": asc["attack_scenario_ids"]}
    )
    log.append(("Security Test Generation + Validation", test_gen_result))

    project.stage = ProjectStage.RISK_PRIORITIZATION
    db.commit()
    risk = RiskAnalyzer(db).execute_with_logging(project_id, {})
    log.append(("Risk Analysis", risk["_summary"]))

    project.stage = ProjectStage.COMPLETE
    db.commit()

    return {"stages": log}


def _generate_and_validate_with_retry(db: Session, project_id: str, gen_context: dict) -> dict:
    """
    Fixed, Python-controlled retry policy (MAX_RETRIES = 2):

        Security Test Generator -> Rule-Based Validation -> INVALID
            -> regenerate (bounded) -> Rule-Based Validation -> ...

    The retry count is a plain module constant. Nothing decides on its own
    whether to keep retrying — after MAX_RETRIES attempts, an INVALID test
    stays INVALID for a human to review; there is no unbounded loop.
    """
    generator = SecurityTestGenerator(db)
    validator = TestValidator(db)

    gen_result = generator.execute_with_logging(project_id, gen_context)
    test_ids = gen_result["security_test_ids"]

    attempts = {tid: 0 for tid in test_ids}
    final_counts = {"VALID": 0, "INVALID": 0, "NEEDS REVIEW": 0}

    pending_ids = list(test_ids)
    while pending_ids:
        validator.execute_with_logging(project_id, {"security_test_ids": pending_ids})
        invalid_ids = []
        for tid in pending_ids:
            test = db.get(SecurityTest, tid)
            if test.validation_status == ValidationStatus.INVALID:
                if attempts[tid] < MAX_RETRIES:
                    invalid_ids.append(tid)
                else:
                    final_counts["INVALID"] += 1
            elif test.validation_status == ValidationStatus.VALID:
                final_counts["VALID"] += 1
            else:
                final_counts["NEEDS REVIEW"] += 1

        if not invalid_ids:
            break

        logger.info("%s tests INVALID, regenerating (retry policy, attempt-bounded).", len(invalid_ids))

        # Regenerate: pull the attack scenario each invalid test came from and regenerate just those.
        scenario_ids = [db.get(SecurityTest, tid).attack_scenario_id for tid in invalid_ids]
        # Remove the invalid rows before regenerating replacements to avoid duplicate-signature false positives.
        for tid in invalid_ids:
            db.delete(db.get(SecurityTest, tid))
            attempts[tid] += 1
        db.commit()

        regen_result = generator.execute_with_logging(
            project_id, {"attack_scenario_ids": [s for s in scenario_ids if s]}
        )
        new_ids = regen_result["security_test_ids"]
        for nid in new_ids:
            attempts[nid] = max((attempts.get(sid, 0) for sid in scenario_ids), default=0)
        pending_ids = new_ids

    return final_counts
