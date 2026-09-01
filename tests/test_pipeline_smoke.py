"""
End-to-end smoke tests. Run with zero API keys and zero external services:

    pytest tests/test_pipeline_smoke.py -v

Uses TM_LLM_PROVIDER=mock and a throwaway SQLite file so this requires
nothing beyond `pip install -r requirements.txt`.
"""
import os

os.environ.setdefault("TM_LLM_PROVIDER", "mock")
os.environ.setdefault("TM_DATABASE_PATH", "/tmp/tm_test_pipeline.db")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.db import Base
from database.models import Project, User
from pipeline.security_analysis_pipeline import run_security_analysis_pipeline


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, future=True)
    session = Session()
    yield session
    session.close()


def test_full_pipeline_runs_end_to_end(db_session):
    user = User(email="demo@local", hashed_password="x")
    db_session.add(user)
    db_session.commit()

    project = Project(owner_id=user.id, name="Demo Shop Assessment")
    db_session.add(project)
    db_session.commit()

    result = run_security_analysis_pipeline(db_session, project.id, {
        "raw_input_type": "manual",
        "manual_entries": {
            "assets": [
                {"name": "API", "asset_type": "API", "technology": "Flask", "criticality": "High"},
                {"name": "Database", "asset_type": "Database", "technology": "SQLite", "criticality": "Critical"},
            ],
            "users": [{"name": "Authenticated User", "role": "user"}],
            "data_flows": [
                {"source": "API", "destination": "Database", "description": "order lookups", "protocol": "internal"}
            ],
        },
    })

    db_session.refresh(project)
    assert project.stage.value == "COMPLETE"

    from database.models import RiskAssessment, SecurityTest, Threat
    threats = db_session.query(Threat).filter(Threat.project_id == project.id).all()
    assert len(threats) > 0, "Threat Modeling should have produced at least one threat"

    for t in threats:
        assert t.stride_category is not None
        assert t.risk_assessment is not None, "Every threat should have a risk assessment after pipeline completes"

    tests = db_session.query(SecurityTest).join(Threat).filter(Threat.project_id == project.id).all()
    assert len(tests) > 0, "Security Test Generation should have produced tests"
    for test in tests:
        assert test.validation_status.value in {"VALID", "NEEDS REVIEW", "INVALID"}

    # Traceability check: every test must map back to a threat with a STRIDE category
    for test in tests:
        assert test.threat_id in {t.id for t in threats}


def test_risk_score_improves_after_verified_remediation(db_session):
    """
    Regression test for a real bug: exploitability used to be computed from
    "was any execution EVER FAILED", which would keep a threat's risk score
    stuck at maximum forever even after a genuine fix was verified. It must
    be based on each test's MOST RECENT execution.
    """
    from datetime import datetime
    from utils import now_utc

    from services.risk_analyzer import RiskAnalyzer
    from database.models import (
        Asset, AssetType, AttackScenario, ExecutionStatus, Project, RiskLevel,
        SecurityTest, STRIDECategory, TestExecution, Threat, ValidationStatus,
    )

    user = User(email="demo2@local", hashed_password="x")
    db_session.add(user)
    db_session.commit()
    project = Project(owner_id=user.id, name="Regression Test")
    db_session.add(project)
    db_session.commit()
    asset = Asset(project_id=project.id, name="API", asset_type=AssetType.API, criticality="High")
    db_session.add(asset)
    db_session.commit()
    threat = Threat(
        project_id=project.id, display_id="TH-001", title="Test threat", description="d",
        affected_asset_id=asset.id, stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        likelihood="High", impact="High", confidence=0.8,
    )
    db_session.add(threat)
    db_session.commit()
    scenario = AttackScenario(
        threat_id=threat.id, attacker_profile="x", target="x", objective="x",
        precondition="x", scenario_narrative="x", expected_secure_behavior="x",
    )
    db_session.add(scenario)
    db_session.commit()
    test = SecurityTest(
        display_id="TC-001", threat_id=threat.id, attack_scenario_id=scenario.id,
        objective="x", validation_status=ValidationStatus.VALID, approved=True,
        risk_level=RiskLevel.HIGH,
    )
    db_session.add(test)
    db_session.commit()

    db_session.add(TestExecution(security_test_id=test.id, status=ExecutionStatus.FAILED,
                                  started_at=now_utc(), finished_at=now_utc()))
    db_session.commit()
    RiskAnalyzer(db_session).run(project.id, {})
    db_session.commit()
    db_session.refresh(threat)
    risk_after_fail = threat.risk_score
    assert risk_after_fail > 0.7, "A confirmed vulnerability should score high risk"

    db_session.add(TestExecution(security_test_id=test.id, status=ExecutionStatus.PASSED,
                                  started_at=now_utc(), finished_at=now_utc()))
    db_session.commit()
    RiskAnalyzer(db_session).run(project.id, {})
    db_session.commit()
    db_session.refresh(threat)
    risk_after_fix = threat.risk_score

    assert risk_after_fix < risk_after_fail, (
        "Risk score must improve after a verified fix — it should reflect the MOST RECENT "
        "execution, not whether any execution ever failed."
    )
