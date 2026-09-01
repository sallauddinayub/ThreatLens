"""
Database schema for the threat-modeling platform.

Tables: users, projects, assets, data_flows, trust_boundaries, threats,
attack_scenarios, security_tests, test_executions, evidence,
risk_assessments, knowledge_documents, pipeline_step_runs, reports.

Every row that participates in the threat -> test -> execution -> risk
chain carries the foreign keys needed to reconstruct full traceability
(Section 15), which is the platform's core differentiator.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.db import Base
from utils import now_utc


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------- enums --

class STRIDECategory(str, enum.Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class RiskLevel(str, enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class ValidationStatus(str, enum.Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    NEEDS_REVIEW = "NEEDS REVIEW"
    PENDING = "PENDING"


class ExecutionStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"          # secure behavior confirmed
    FAILED = "FAILED"          # vulnerability confirmed
    ERROR = "ERROR"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    STOPPED = "STOPPED"


class AssetType(str, enum.Enum):
    USER = "User"
    ADMIN = "Admin"
    WEB_APPLICATION = "Web Application"
    API = "API"
    AUTH_SERVICE = "Authentication Service"
    DATABASE = "Database"
    PAYMENT_SERVICE = "Payment Service"
    EXTERNAL_API = "External API"
    CLOUD_SERVICE = "Cloud Service"
    MONITORING_SERVICE = "Monitoring Service"
    STORAGE = "Storage"


class ProjectStage(str, enum.Enum):
    SYSTEM_ANALYSIS = "SYSTEM_ANALYSIS"
    ASSET_DISCOVERY = "ASSET_DISCOVERY"
    THREAT_MODELING = "THREAT_MODELING"
    STRIDE_ANALYSIS = "STRIDE_ANALYSIS"
    ATTACK_SCENARIO_GENERATION = "ATTACK_SCENARIO_GENERATION"
    TEST_GENERATION = "TEST_GENERATION"
    TEST_VALIDATION = "TEST_VALIDATION"
    TEST_EXECUTION = "TEST_EXECUTION"
    RISK_PRIORITIZATION = "RISK_PRIORITIZATION"
    REPORT_GENERATION = "REPORT_GENERATION"
    COMPLETE = "COMPLETE"


class PipelineStepStatus(str, enum.Enum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    RETRIED = "RETRIED"


class RemediationStatus(str, enum.Enum):
    OPEN = "Open"                        # vulnerability confirmed, no remediation action logged yet
    IN_REMEDIATION = "In Remediation"     # a fix has been described, not yet re-verified
    FIXED = "Fixed"                       # re-tested after remediation and confirmed secure
    ACCEPTED_RISK = "Accepted Risk"       # manually accepted, no fix planned (terminal)
    FALSE_POSITIVE = "False Positive"     # manually dismissed as not a real vulnerability (terminal)
    RETEST_REQUIRED = "Retest Required"   # a later re-test after FIXED failed again (regression)


# --------------------------------------------------------------- tables --

class UserRole(str, enum.Enum):
    USER = "USER"
    ADMIN = "ADMIN"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    full_name: Mapped[str] = mapped_column(String, nullable=True)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.USER)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)

    # Login rate limiting (Section 3) — simple, per-account lockout after
    # repeated failed attempts. Deliberately not IP-based: this is a
    # single-process Flask app with no reverse proxy assumed, so per-account
    # is the more reliable signal available here.
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    projects: Mapped[list["Project"]] = relationship(back_populates="owner")


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    stage: Mapped[ProjectStage] = mapped_column(Enum(ProjectStage), default=ProjectStage.SYSTEM_ANALYSIS)

    # Section 30: no active testing without explicit, per-project authorization
    authorized_for_active_testing: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_statement: Mapped[str] = mapped_column(Text, nullable=True)
    authorized_by_user_id: Mapped[str] = mapped_column(String, nullable=True)
    authorized_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    allowlisted_targets: Mapped[list] = mapped_column(JSON, default=list)  # explicit hosts/IPs for THIS project

    raw_input_type: Mapped[str] = mapped_column(String, nullable=True)  # openapi | architecture | diagram | source | manual
    raw_input_ref: Mapped[str] = mapped_column(String, nullable=True)   # path/URL to stored input
    system_model: Mapped[dict] = mapped_column(JSON, nullable=True)     # output of System Analysis

    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)

    owner: Mapped["User"] = relationship(back_populates="projects")
    assets: Mapped[list["Asset"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    data_flows: Mapped[list["DataFlow"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    trust_boundaries: Mapped[list["TrustBoundary"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    threats: Mapped[list["Threat"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    pipeline_step_runs: Mapped[list["PipelineStepRun"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String)
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType))
    technology: Mapped[str] = mapped_column(String, nullable=True)
    criticality: Mapped[str] = mapped_column(String, default="Medium")  # Critical/High/Medium/Low
    trust_zone: Mapped[str] = mapped_column(String, nullable=True)
    connections: Mapped[list] = mapped_column(JSON, default=list)  # list of asset ids
    sensitive_data: Mapped[list] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)

    project: Mapped["Project"] = relationship(back_populates="assets")
    threats: Mapped[list["Threat"]] = relationship(back_populates="affected_asset")


class DataFlow(Base):
    __tablename__ = "data_flows"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    source_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), nullable=True)
    destination_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    protocol: Mapped[str] = mapped_column(String, nullable=True)
    crosses_trust_boundary: Mapped[bool] = mapped_column(Boolean, default=False)
    data_classification: Mapped[str] = mapped_column(String, nullable=True)  # e.g. PII, financial, public

    project: Mapped["Project"] = relationship(back_populates="data_flows")


class TrustBoundary(Base):
    __tablename__ = "trust_boundaries"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    asset_ids: Mapped[list] = mapped_column(JSON, default=list)

    project: Mapped["Project"] = relationship(back_populates="trust_boundaries")


class Threat(Base):
    __tablename__ = "threats"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    display_id: Mapped[str] = mapped_column(String)  # e.g. TH-001, human friendly
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)

    affected_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), nullable=True)
    affected_data_flow_id: Mapped[str] = mapped_column(ForeignKey("data_flows.id"), nullable=True)

    stride_category: Mapped[STRIDECategory] = mapped_column(Enum(STRIDECategory))
    likelihood: Mapped[str] = mapped_column(String)   # High/Medium/Low
    impact: Mapped[str] = mapped_column(String)       # High/Medium/Low
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)  # 0-1, the LLM's self-reported confidence

    recommended_mitigation: Mapped[str] = mapped_column(Text, nullable=True)

    # Mapping (Section 21) — only populated when RAG-grounded, never invented
    owasp_category: Mapped[str] = mapped_column(String, nullable=True)
    cwe_id: Mapped[str] = mapped_column(String, nullable=True)
    mitre_attack_technique: Mapped[str] = mapped_column(String, nullable=True)
    rag_sources: Mapped[list] = mapped_column(JSON, default=list)  # list of {title, url/id, snippet}

    reasoning_summary: Mapped[str] = mapped_column(Text, nullable=True)  # explainability, Section 26

    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)

    project: Mapped["Project"] = relationship(back_populates="threats")
    affected_asset: Mapped["Asset"] = relationship(back_populates="threats")
    attack_scenarios: Mapped[list["AttackScenario"]] = relationship(back_populates="threat", cascade="all, delete-orphan")
    security_tests: Mapped[list["SecurityTest"]] = relationship(back_populates="threat", cascade="all, delete-orphan")
    risk_assessment: Mapped["RiskAssessment"] = relationship(back_populates="threat", uselist=False, cascade="all, delete-orphan")
    remediations: Mapped[list["Remediation"]] = relationship(back_populates="threat", cascade="all, delete-orphan")


class AttackScenario(Base):
    __tablename__ = "attack_scenarios"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    threat_id: Mapped[str] = mapped_column(ForeignKey("threats.id"))
    attacker_profile: Mapped[str] = mapped_column(String)
    target: Mapped[str] = mapped_column(String)
    objective: Mapped[str] = mapped_column(Text)
    precondition: Mapped[str] = mapped_column(Text)
    scenario_narrative: Mapped[str] = mapped_column(Text)
    expected_secure_behavior: Mapped[str] = mapped_column(Text)

    threat: Mapped["Threat"] = relationship(back_populates="attack_scenarios")
    security_tests: Mapped[list["SecurityTest"]] = relationship(back_populates="attack_scenario")


class SecurityTest(Base):
    __tablename__ = "security_tests"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    display_id: Mapped[str] = mapped_column(String)  # e.g. TC-001
    threat_id: Mapped[str] = mapped_column(ForeignKey("threats.id"))
    attack_scenario_id: Mapped[str] = mapped_column(ForeignKey("attack_scenarios.id"), nullable=True)

    objective: Mapped[str] = mapped_column(Text)
    preconditions: Mapped[str] = mapped_column(Text, nullable=True)
    endpoint: Mapped[str] = mapped_column(String, nullable=True)
    http_method: Mapped[str] = mapped_column(String, nullable=True)
    required_role: Mapped[str] = mapped_column(String, nullable=True)
    test_steps: Mapped[list] = mapped_column(JSON, default=list)  # ordered list of step strings
    expected_result: Mapped[str] = mapped_column(Text, nullable=True)
    validation_criteria: Mapped[str] = mapped_column(Text, nullable=True)
    risk_level: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel), default=RiskLevel.MEDIUM)

    validation_status: Mapped[ValidationStatus] = mapped_column(Enum(ValidationStatus), default=ValidationStatus.PENDING)
    validation_explanation: Mapped[str] = mapped_column(Text, nullable=True)

    approved: Mapped[bool] = mapped_column(Boolean, default=False)  # human approval gate before execution

    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)

    threat: Mapped["Threat"] = relationship(back_populates="security_tests")
    attack_scenario: Mapped["AttackScenario"] = relationship(back_populates="security_tests")
    executions: Mapped[list["TestExecution"]] = relationship(back_populates="security_test", cascade="all, delete-orphan")
    remediations: Mapped[list["Remediation"]] = relationship(back_populates="security_test", cascade="all, delete-orphan")


class TestExecution(Base):
    __test__ = False  # tells pytest this ORM model isn't a test class, despite the "Test" prefix
    __tablename__ = "test_executions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    security_test_id: Mapped[str] = mapped_column(ForeignKey("security_tests.id"))
    status: Mapped[ExecutionStatus] = mapped_column(Enum(ExecutionStatus), default=ExecutionStatus.PENDING)

    request_metadata: Mapped[dict] = mapped_column(JSON, nullable=True)
    response_status: Mapped[int] = mapped_column(Integer, nullable=True)
    response_metadata: Mapped[dict] = mapped_column(JSON, nullable=True)
    actual_result: Mapped[str] = mapped_column(Text, nullable=True)
    execution_time_ms: Mapped[float] = mapped_column(Float, nullable=True)

    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    security_test: Mapped["SecurityTest"] = relationship(back_populates="executions")
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="execution", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    execution_id: Mapped[str] = mapped_column(ForeignKey("test_executions.id"))
    kind: Mapped[str] = mapped_column(String)  # request_log, response_log, screenshot_ref, note
    content: Mapped[str] = mapped_column(Text)  # sanitized — see evidence collector for redaction rules
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)

    execution: Mapped["TestExecution"] = relationship(back_populates="evidence")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    threat_id: Mapped[str] = mapped_column(ForeignKey("threats.id"), unique=True)

    likelihood_score: Mapped[float] = mapped_column(Float)
    impact_score: Mapped[float] = mapped_column(Float)
    exploitability_score: Mapped[float] = mapped_column(Float)
    asset_criticality_score: Mapped[float] = mapped_column(Float)
    confidence_score: Mapped[float] = mapped_column(Float)

    composite_score: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel))
    rationale: Mapped[str] = mapped_column(Text, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)

    threat: Mapped["Threat"] = relationship(back_populates="risk_assessment")


class Remediation(Base):
    """
    Remediation -> Re-test workflow. An append-only audit trail: each row
    is one remediation action/status change against a specific security
    test. The CURRENT status shown to the user is simply the most recent
    row for that test (ordered by created_at) — never mutated in place,
    so the full history of what was tried and when is preserved.

    risk_score_before/after capture the threat's composite risk score at
    the moment remediation was logged and at the moment it was verified
    fixed, purely so the UI can show a genuine, calculated risk-reduction
    percentage rather than an invented one.
    """
    __tablename__ = "remediations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    threat_id: Mapped[str] = mapped_column(ForeignKey("threats.id"))
    security_test_id: Mapped[str] = mapped_column(ForeignKey("security_tests.id"))
    description: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[RemediationStatus] = mapped_column(Enum(RemediationStatus), default=RemediationStatus.OPEN)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    resolved_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    resolving_execution_id: Mapped[str] = mapped_column(ForeignKey("test_executions.id"), nullable=True)

    risk_score_before: Mapped[float] = mapped_column(Float, nullable=True)
    risk_score_after: Mapped[float] = mapped_column(Float, nullable=True)

    threat: Mapped["Threat"] = relationship(back_populates="remediations")
    security_test: Mapped["SecurityTest"] = relationship(back_populates="remediations")
    resolving_execution: Mapped["TestExecution"] = relationship(foreign_keys=[resolving_execution_id])


class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    source: Mapped[str] = mapped_column(String)  # OWASP / CWE / MITRE ATT&CK / STRIDE_DOC / API_SECURITY / CVE
    title: Mapped[str] = mapped_column(String)
    identifier: Mapped[str] = mapped_column(String, nullable=True)  # e.g. CWE-284, T1078
    url: Mapped[str] = mapped_column(String, nullable=True)
    content: Mapped[str] = mapped_column(Text)
    embedding_ref: Mapped[str] = mapped_column(String, nullable=True)  # id in vector store
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class PipelineStepRun(Base):
    """
    Records one execution of one deterministic pipeline step (System
    Analysis, Asset Discovery, Threat Modeling, ...) for a project. This
    is what the Security Analysis Pipeline page and the Pipeline Activity
    Log read from — it's a plain audit trail of a fixed, Python-controlled
    workflow, not state belonging to an autonomous agent.
    """
    __tablename__ = "pipeline_step_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    step_name: Mapped[str] = mapped_column(String)
    stage: Mapped[ProjectStage] = mapped_column(Enum(ProjectStage))
    status: Mapped[PipelineStepStatus] = mapped_column(Enum(PipelineStepStatus), default=PipelineStepStatus.RUNNING)
    input_summary: Mapped[dict] = mapped_column(JSON, nullable=True)
    output_summary: Mapped[dict] = mapped_column(JSON, nullable=True)
    reasoning_summary: Mapped[str] = mapped_column(Text, nullable=True)
    error: Mapped[str] = mapped_column(Text, nullable=True)
    retry_of_run_id: Mapped[str] = mapped_column(String, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    finished_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    project: Mapped["Project"] = relationship(back_populates="pipeline_step_runs")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    format: Mapped[str] = mapped_column(String)  # pdf | json | csv
    file_path: Mapped[str] = mapped_column(String, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)

    project: Mapped["Project"] = relationship(back_populates="reports")
