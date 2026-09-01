"""
AI-Driven Threat Modeling and Security Test Generation Platform.

Flask entrypoint. Every page is server-rendered HTML (Jinja2 templates +
hand-written CSS + a small amount of vanilla JS) — no React, no npm, no
separate frontend process. Run with:

    pip install -r requirements.txt
    python app.py

then open http://localhost:5000/
"""
from __future__ import annotations

import io
import json
import os
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, redirect, render_template, request, send_file, session
from flask_wtf import CSRFProtect

from services.asset_discovery import AssetDiscoveryService
from pipeline.security_analysis_pipeline import run_security_analysis_pipeline
from services.report_generator import generate_csv_report, generate_json_report, generate_pdf_report
from services.risk_analyzer import RiskAnalyzer
from config import get_settings
from database import models as m
from database.db import SessionLocal, init_db
from rag.corpus_browser import filter_documents, find_citing_threats, get_document, load_all_documents
from security.risk_engine import compute_security_posture_score
from security.test_engine import ControlledTestExecutionEngine
from security.auth import (
    GENERIC_LOGIN_ERROR, admin_required, get_current_user, hash_password,
    is_locked_out, login_required, record_failed_login, record_successful_login,
    seed_default_admin, verify_password,
)
from utils import now_utc
from web_charts import bar_chart, donut_chart
from web_graph import TYPE_COLORS, build_asset_graph, _json_for_script

settings = get_settings()
app = Flask(__name__)
app.secret_key = settings.secret_key
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024  # hard ceiling on any single request body — belt-and-suspenders
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
csrf = CSRFProtect(app)

PUBLIC_PATHS = {"/login", "/register", "/health"}


@app.before_request
def _require_login():
    """
    Every route requires a logged-in session except the handful of
    genuinely public ones. This is the actual enforcement point — the
    per-route @login_required/@admin_required decorators add role checks
    on top of this, but even a route with no decorator at all is still
    gated here, so nothing can be reached unauthenticated by accident.

    Also self-heals a stale session: if the browser holds a session cookie
    referencing a user_id that no longer exists in the database (for
    example, after the .db file was deleted/reset but the browser's
    session cookie survived, since the app's secret key doesn't change
    across restarts), that's cleared and the person is sent back to
    /login — rather than letting a route crash later on a None user.
    """
    path = request.path
    if path in PUBLIC_PATHS or path.startswith("/static/"):
        return None
    user_id = session.get("user_id")
    if not user_id:
        return redirect(f"/login?next={path}")

    db = SessionLocal()
    try:
        if not db.get(m.User, user_id):
            session.clear()
            return redirect(f"/login?next={path}")
    finally:
        db.close()
    return None


@app.context_processor
def _inject_current_user():
    """Makes `current_user` available in every template automatically, so
    base.html's profile menu doesn't require every single route to remember
    to pass it explicitly."""
    if not session.get("user_id"):
        return {"current_user": None}
    db = SessionLocal()
    try:
        return {"current_user": db.get(m.User, session["user_id"])}
    finally:
        db.close()


@app.context_processor
def _inject_current_year():
    return {"current_year": now_utc().year}


IST = timezone(timedelta(hours=5, minutes=30))  # fixed offset, no DST — correct for India year-round


@app.template_filter("ist")
def _format_ist(dt, fmt="%b %d, %Y %H:%M IST"):
    """
    Every timestamp is stored in the database as UTC (the correct practice —
    never store local time). This filter converts to IST only at display
    time, so the database itself stays timezone-unambiguous. Used in every
    template instead of calling .strftime() directly on a raw UTC value.
    """
    if dt is None:
        return ""
    aware_utc = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    return aware_utc.astimezone(IST).strftime(fmt)

MAX_OPENAPI_SIZE = 10 * 1024 * 1024

STRIDE_INITIALS = {
    "Spoofing": "S", "Tampering": "T", "Repudiation": "R",
    "Information Disclosure": "I", "Denial of Service": "D", "Elevation of Privilege": "E",
}
STRIDE_COLORS = {
    "Spoofing": "#7c3aed", "Tampering": "#ea580c", "Repudiation": "#0d9488",
    "Information Disclosure": "#2563eb", "Denial of Service": "#e11d48", "Elevation of Privilege": "#b45309",
}
RISK_COLORS = {
    "Critical": "#c0293c", "High": "#d9682f", "Medium": "#c08a1e", "Low": "#3d7ab8", "Informational": "#6b7688",
}
REQUIRED_CONFIRMATION = "I confirm that I am authorized to test this target."

SAMPLE_MANUAL = {
    "assets": [
        {"name": "API", "asset_type": "API", "technology": "Flask", "criticality": "High"},
        {"name": "Database", "asset_type": "Database", "technology": "SQLite", "criticality": "Critical"},
        {"name": "Authentication Service", "asset_type": "Authentication Service", "criticality": "High"},
    ],
    "users": [{"name": "Authenticated User", "role": "user"}],
    "data_flows": [
        {"source": "API", "destination": "Database", "description": "order lookups", "protocol": "internal"},
        {"source": "Authentication Service", "destination": "API", "description": "token issuance", "protocol": "HTTPS"},
    ],
}


def _validate_openapi(raw_text: str, size_bytes: int) -> dict:
    """
    Real parsing, not a mock: uses PyYAML (which also parses plain JSON,
    since JSON is a YAML subset) to extract the actual OpenAPI version,
    endpoint count, schema count, and detected auth scheme from the
    uploaded/pasted spec. Returns {"valid": False, "error": ...} for
    anything that isn't a usable OpenAPI document, so the UI can show a
    friendly error instead of a raw exception.
    """
    import yaml

    try:
        spec = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        return {"valid": False, "error": f"The file isn't valid YAML/JSON: {exc}"}

    if not isinstance(spec, dict):
        return {"valid": False, "error": "The file doesn't contain a JSON/YAML object at the top level."}

    version = spec.get("openapi") or spec.get("swagger")
    paths = spec.get("paths")
    if not version or not isinstance(paths, dict):
        return {"valid": False, "error": "This doesn't look like an OpenAPI/Swagger specification - no 'openapi'/'swagger' version field and 'paths' object were found."}

    endpoint_count = sum(
        len([m for m in methods if m.lower() in {"get", "post", "put", "patch", "delete", "options", "head"}])
        for methods in paths.values() if isinstance(methods, dict)
    )
    schemas = (spec.get("components") or {}).get("schemas") or {}
    security_schemes = (spec.get("components") or {}).get("securitySchemes") or {}
    auth_types = []
    for s in security_schemes.values():
        if not isinstance(s, dict):
            continue
        scheme_type = (s.get("type") or "").lower()
        if scheme_type == "http" and s.get("scheme"):
            auth_types.append(s["scheme"].upper())  # e.g. "bearer" -> "BEARER"
        elif scheme_type == "oauth2":
            auth_types.append("OAUTH2")
        else:
            auth_types.append((scheme_type or "unknown").upper())

    return {
        "valid": True,
        "version": str(version),
        "endpoint_count": endpoint_count,
        "path_count": len(paths),
        "schema_count": len(schemas),
        "auth_label": ", ".join(sorted(set(auth_types))) if auth_types else "Not detected",
        "size_label": f"{size_bytes / 1024:.1f} KB" if size_bytes < 1024 * 1024 else f"{size_bytes / (1024 * 1024):.2f} MB",
    }


# ---------------------------------------------------------------- helpers --

def _get_project(db):
    project_id = request.cookies.get("tm_project_id")
    if not project_id:
        return None
    return db.get(m.Project, project_id)


def _sorted_executions_by_test(threat) -> dict:
    """
    Sorts each SecurityTest's executions oldest-first, safely, regardless
    of whether any execution's started_at is None (e.g. a BLOCKED_BY_POLICY
    execution from an older database that predates the fix ensuring
    started_at is always set). Doing this in Python with an explicit
    None-safe key avoids relying on Jinja's `sort` filter, which raises
    TypeError the moment it has to compare a real datetime against None —
    the exact crash this replaces. Computed once per page load and handed
    to the template as a plain dict, so the template itself never sorts.
    """
    from datetime import datetime
    result = {}
    for scenario in threat.attack_scenarios:
        for test in scenario.security_tests:
            result[test.id] = sorted(test.executions, key=lambda e: e.started_at or datetime.min)
    return result


def _run_pipeline(db, project, payload) -> list:
    project.raw_input_type = payload.get("raw_input_type")
    db.commit()
    result = run_security_analysis_pipeline(db, project.id, payload)
    return result["stages"]


def get_test_for_threat(db, threat_id: str, test_id: str):
    """
    The single choke point every /threats/<threat_id>/tests/<test_id>/...
    route must go through. Returns the SecurityTest only if it genuinely
    belongs to the supplied threat_id — never trusts test_id alone, which
    would otherwise let one project's authenticated session act on a test
    belonging to a completely different threat (IDOR) just by guessing/
    enumerating test IDs in the URL.
    """
    test = db.get(m.SecurityTest, test_id)
    if not test:
        return None
    if not test.threat or test.threat_id != threat_id:
        return None
    return test


# --------------------------------------------------------------- dashboard --

@app.route("/")
def dashboard():
    db = SessionLocal()
    try:
        project = _get_project(db)
        threats, risk_distribution, stride_counts, heatmap = [], {}, {}, {}
        avg_risk_score, top_threats = "0.00", []
        recent_pipeline_runs, last_analyzed = [], None
        total_assets = 0
        test_stats = {"total": 0, "valid": 0, "failed_executions": 0}
        posture_score, posture_color = 100, "#22c55e"
        coverage = {"threats_with_tests": 0, "total_threats": 0, "valid_tests": 0, "total_tests": 0, "critical_coverage_pct": 0}

        if project:
            threats = db.query(m.Threat).filter(m.Threat.project_id == project.id).all()
            total_assets = db.query(m.Asset).filter(m.Asset.project_id == project.id).count()

            all_tests = db.query(m.SecurityTest).join(m.Threat).filter(m.Threat.project_id == project.id).all()
            test_stats["total"] = len(all_tests)
            test_stats["valid"] = sum(1 for t in all_tests if t.validation_status == m.ValidationStatus.VALID)
            test_stats["failed_executions"] = sum(
                1 for t in all_tests
                if t.executions and sorted(t.executions, key=lambda e: e.started_at or datetime.min)[-1].status == m.ExecutionStatus.FAILED
            )

            threats_with_tests = sum(1 for t in threats if t.security_tests)
            critical_threats = [t for t in threats if t.risk_assessment and t.risk_assessment.risk_level == m.RiskLevel.CRITICAL]
            critical_with_valid_test = sum(
                1 for t in critical_threats
                if any(st.validation_status == m.ValidationStatus.VALID for st in t.security_tests)
            )
            coverage = {
                "threats_with_tests": threats_with_tests, "total_threats": len(threats),
                "valid_tests": test_stats["valid"], "total_tests": test_stats["total"],
                "critical_coverage_pct": round(100 * critical_with_valid_test / len(critical_threats)) if critical_threats else 100,
            }

            for t in threats:
                level = t.risk_assessment.risk_level.value if t.risk_assessment else "Informational"
                risk_distribution[level] = risk_distribution.get(level, 0) + 1
                stride_counts[t.stride_category.value] = stride_counts.get(t.stride_category.value, 0) + 1

                asset_name = t.affected_asset.name if t.affected_asset else "Unassigned"
                heatmap.setdefault(asset_name, {})
                cat = t.stride_category.value
                existing = heatmap[asset_name].get(cat)
                if not existing or t.risk_score > existing["risk_score"]:
                    heatmap[asset_name][cat] = {
                        "id": t.id, "title": t.title, "risk_score": t.risk_score,
                        "color": RISK_COLORS.get(level, "#6b7688"),
                    }

            if threats:
                avg_risk_score = f"{sum(t.risk_score for t in threats) / len(threats):.2f}"
            top_threats = sorted(threats, key=lambda t: t.risk_score or 0, reverse=True)[:6]

            recent_pipeline_runs = (
                db.query(m.PipelineStepRun).filter(m.PipelineStepRun.project_id == project.id)
                .order_by(m.PipelineStepRun.started_at.desc()).limit(8).all()
            )
            if recent_pipeline_runs:
                last_analyzed = recent_pipeline_runs[0].finished_at or recent_pipeline_runs[0].started_at

            validation_pass_rate = (test_stats["valid"] / test_stats["total"]) if test_stats["total"] else 1.0
            posture_score = compute_security_posture_score(risk_distribution, validation_pass_rate)
            posture_color = "#22c55e" if posture_score >= 75 else ("#c08a1e" if posture_score >= 50 else "#c0293c")

        stride_svg = donut_chart(stride_counts, STRIDE_COLORS)
        risk_svg = bar_chart(risk_distribution, RISK_COLORS)

        return render_template(
            "dashboard.html", project=project,
            threats=threats, risk_distribution=risk_distribution,
            stride_chart_svg=stride_svg, risk_chart_svg=risk_svg,
            heatmap=heatmap, stride_categories=list(STRIDE_INITIALS.keys()),
            stride_legend=list(STRIDE_COLORS.items()), stride_counts_display=stride_counts,
            avg_risk_score=avg_risk_score, top_threats=top_threats,
            recent_pipeline_runs=recent_pipeline_runs, last_analyzed=last_analyzed,
            total_assets=total_assets, test_stats=test_stats,
            posture_score=posture_score, posture_color=posture_color, coverage=coverage,
        )
    finally:
        db.close()


# ---------------------------------------------------------- system analysis --

@app.route("/system-analysis")
def system_analysis_page():
    db = SessionLocal()
    try:
        project = _get_project(db)
        model = project.system_model if project else None
        return render_template(
            "system_analysis.html", project=project, system_model=model,
            system_model_json=json.dumps(model, indent=2) if model else None,
        )
    finally:
        db.close()


# ------------------------------------------------------------------ assets --

@app.route("/assets")
def assets_page():
    db = SessionLocal()
    try:
        project = _get_project(db)
        assets_raw, threats_raw, graph_svg, node_meta_json = [], [], "", "{}"

        if project:
            assets = db.query(m.Asset).filter(m.Asset.project_id == project.id).all()
            assets_raw = [
                {"id": a.id, "name": a.name, "type": a.asset_type.value, "criticality": a.criticality,
                 "technology": a.technology, "connections": a.connections or []}
                for a in assets
            ]
            threats = db.query(m.Threat).filter(m.Threat.project_id == project.id).all()
            threats_raw = [
                {"id": t.id, "title": t.title, "stride_category": t.stride_category.value,
                 "affected_asset": t.affected_asset.name if t.affected_asset else None,
                 "risk_level": t.risk_assessment.risk_level.value if t.risk_assessment else "Informational"}
                for t in threats
            ]
            graph_svg, node_meta_json, _ = build_asset_graph(assets_raw)

        return render_template(
            "assets.html", project=project, assets=assets_raw,
            graph_svg=graph_svg, node_meta_json=node_meta_json,
            threats_json=_json_for_script(threats_raw), legend=list(TYPE_COLORS.items()),
        )
    finally:
        db.close()


# ----------------------------------------------------------------- threats --

@app.route("/threats")
def threats_page():
    db = SessionLocal()
    try:
        project = _get_project(db)
        stride = request.args.get("stride", "All")
        risk = request.args.get("risk", "All")
        sort = request.args.get("sort", "risk")
        q = request.args.get("q", "")
        threats_raw, stride_options = [], []

        if project:
            threats = db.query(m.Threat).filter(m.Threat.project_id == project.id).all()
            stride_options = sorted({t.stride_category.value for t in threats})
            filtered = threats if stride == "All" else [t for t in threats if t.stride_category.value == stride]
            if risk != "All":
                filtered = [t for t in filtered if (t.risk_assessment.risk_level.value if t.risk_assessment else "Informational") == risk]
            if q.strip():
                needle = q.strip().lower()
                filtered = [t for t in filtered if needle in t.title.lower() or needle in (t.description or "").lower()]

            risk_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}

            def sort_key(t):
                level = t.risk_assessment.risk_level.value if t.risk_assessment else "Informational"
                return (t.display_id,) if sort == "id" else (-risk_order.get(level, 0), -(t.risk_score or 0))

            filtered = sorted(filtered, key=sort_key)
            for t in filtered:
                level = t.risk_assessment.risk_level.value if t.risk_assessment else None
                mapping = " · ".join(filter(None, [t.owasp_category, t.cwe_id, t.mitre_attack_technique]))
                threats_raw.append({
                    "id": t.id, "display_id": t.display_id, "title": t.title,
                    "stride_category": t.stride_category.value, "stride_initial": STRIDE_INITIALS[t.stride_category.value],
                    "affected_asset": t.affected_asset.name if t.affected_asset else None,
                    "likelihood": t.likelihood, "impact": t.impact, "risk_score": t.risk_score or 0,
                    "risk_level": level, "mapping": mapping or None,
                })

        return render_template(
            "threats.html", project=project, threats=threats_raw,
            stride_filter=stride, risk_filter=risk, sort_by=sort, stride_options=stride_options, search_q=q,
        )
    finally:
        db.close()


@app.route("/threats/<threat_id>")
def threat_detail_page(threat_id):
    db = SessionLocal()
    try:
        project = _get_project(db)
        threat = db.get(m.Threat, threat_id)
        if not threat:
            return "Threat not found", 404
        try:
            import chromadb  # noqa: F401
            rag_available = True
        except ImportError:
            rag_available = False
        return render_template(
            "threat_detail.html", project=project, threat=threat,
            stride_initial=STRIDE_INITIALS[threat.stride_category.value],
            rag_available=rag_available,
            executions_by_test=_sorted_executions_by_test(threat),
        )
    finally:
        db.close()


@app.route("/threats/<threat_id>/tests/<test_id>/approve", methods=["POST"])
def approve_test(threat_id, test_id):
    db = SessionLocal()
    try:
        test = get_test_for_threat(db, threat_id, test_id)
        if not test:
            return "Test not found for this threat.", 404
        if test.validation_status == m.ValidationStatus.VALID:
            test.approved = True
            db.commit()
        return redirect(f"/threats/{threat_id}")
    finally:
        db.close()


@app.route("/threats/<threat_id>/tests/<test_id>/execute", methods=["POST"])
def execute_test(threat_id, test_id):
    db = SessionLocal()
    try:
        test = get_test_for_threat(db, threat_id, test_id)
        if not test:
            return "Test not found for this threat.", 404
        # Auto-generated endpoints in mock mode are a naive slugification of
        # the asset name (e.g. "API Gateway" -> "/api-gateway/{id}") and often
        # don't correspond to any real route on the actual target being
        # tested. This lets the operator override it at execution time
        # instead of getting a guaranteed, meaningless 404.
        endpoint_override = request.form.get("endpoint_override", "").strip()
        if endpoint_override:
            test.endpoint = endpoint_override
            db.commit()
        engine = ControlledTestExecutionEngine(db)
        auth_token = request.form.get("auth_token") or None
        engine.execute_test(test, test.threat.project, request.form.get("base_url", ""), auth_token=auth_token)
        return redirect(f"/threats/{threat_id}")
    finally:
        db.close()


@app.route("/threats/<threat_id>/tests/<test_id>/remediate", methods=["POST"])
def log_remediation(threat_id, test_id):
    db = SessionLocal()
    try:
        test = get_test_for_threat(db, threat_id, test_id)
        if not test:
            return "Test not found for this threat.", 404
        db.add(m.Remediation(
            threat_id=threat_id, security_test_id=test_id,
            description=request.form.get("description", ""),
            status=m.RemediationStatus.IN_REMEDIATION,
            risk_score_before=test.threat.risk_score,
        ))
        db.commit()
        return redirect(f"/threats/{threat_id}")
    finally:
        db.close()


@app.route("/threats/<threat_id>/tests/<test_id>/mark-status", methods=["POST"])
def mark_remediation_status(threat_id, test_id):
    """Manual terminal states: Accepted Risk / False Positive — no re-test needed."""
    db = SessionLocal()
    try:
        test = get_test_for_threat(db, threat_id, test_id)
        if not test:
            return "Test not found for this threat.", 404
        status_value = request.form.get("status")
        if status_value in (m.RemediationStatus.ACCEPTED_RISK.value, m.RemediationStatus.FALSE_POSITIVE.value):
            db.add(m.Remediation(
                threat_id=threat_id, security_test_id=test_id,
                description=request.form.get("description", "") or f"Marked as {status_value}.",
                status=m.RemediationStatus(status_value),
                risk_score_before=test.threat.risk_score,
                resolved_at=now_utc(),
            ))
            db.commit()
        return redirect(f"/threats/{threat_id}")
    finally:
        db.close()


@app.route("/threats/<threat_id>/tests/<test_id>/retest", methods=["POST"])
def retest(threat_id, test_id):
    """
    Re-runs the same controlled test and resolves the current remediation
    state based on the new result: PASSED -> FIXED (captures risk_score_after
    for the before/after comparison); FAILED -> stays/returns to whatever
    reflects reality (IN_REMEDIATION if still being worked on, or
    RETEST_REQUIRED if this regressed after being FIXED).
    """
    db = SessionLocal()
    try:
        test = get_test_for_threat(db, threat_id, test_id)
        if not test:
            return "Test not found for this threat.", 404

        project = test.threat.project
        endpoint_override = request.form.get("endpoint_override", "").strip()
        if endpoint_override:
            test.endpoint = endpoint_override
            db.commit()
        engine = ControlledTestExecutionEngine(db)
        auth_token = request.form.get("auth_token") or None
        execution = engine.execute_test(test, project, request.form.get("base_url", ""), auth_token=auth_token)

        latest_remediation = (
            db.query(m.Remediation)
            .filter(m.Remediation.security_test_id == test_id)
            .order_by(m.Remediation.created_at.desc())
            .first()
        )

        if execution.status == m.ExecutionStatus.PASSED and latest_remediation and latest_remediation.status in (
            m.RemediationStatus.IN_REMEDIATION, m.RemediationStatus.RETEST_REQUIRED
        ):
            latest_remediation.status = m.RemediationStatus.FIXED
            latest_remediation.resolved_at = now_utc()
            latest_remediation.resolving_execution_id = execution.id
            db.commit()
            RiskAnalyzer(db).run(project.id, {})
            db.commit()
            db.refresh(test.threat)
            latest_remediation.risk_score_after = test.threat.risk_score
            db.commit()
        elif execution.status == m.ExecutionStatus.FAILED and latest_remediation and latest_remediation.status == m.RemediationStatus.FIXED:
            latest_remediation.status = m.RemediationStatus.RETEST_REQUIRED
            db.commit()
            RiskAnalyzer(db).run(project.id, {})
            db.commit()
        else:
            RiskAnalyzer(db).run(project.id, {})
            db.commit()

        return redirect(f"/threats/{threat_id}")
    finally:
        db.close()


# ------------------------------------------------------------ traceability --

@app.route("/traceability")
def traceability_page():
    db = SessionLocal()
    try:
        project = _get_project(db)
        rows = []
        if project:
            threats = db.query(m.Threat).filter(m.Threat.project_id == project.id).all()
            for t in threats:
                risk_level = t.risk_assessment.risk_level.value if t.risk_assessment else "Informational"
                for scenario in t.attack_scenarios:
                    for test in scenario.security_tests:
                        executions = sorted(test.executions, key=lambda e: e.started_at or datetime.min)
                        latest_execution = executions[-1] if executions else None
                        remediations = sorted(test.remediations, key=lambda r: r.created_at, reverse=True)
                        latest_remediation = remediations[0] if remediations else None
                        rows.append({
                            "asset": t.affected_asset.name if t.affected_asset else "Unassigned",
                            "threat": t, "stride_initial": STRIDE_INITIALS[t.stride_category.value],
                            "scenario": scenario, "test": test, "latest_execution": latest_execution,
                            "evidence_count": sum(len(e.evidence) for e in executions),
                            "latest_remediation": latest_remediation, "risk_level": risk_level,
                        })
            risk_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
            rows.sort(key=lambda r: -risk_order.get(r["risk_level"], 0))
        return render_template("traceability.html", project=project, rows=rows)
    finally:
        db.close()


@app.route("/executions/<execution_id>/evidence")
def evidence_page(execution_id):
    db = SessionLocal()
    try:
        project = _get_project(db)
        execution = db.get(m.TestExecution, execution_id)
        if not execution:
            return "Execution not found", 404
        return render_template("evidence.html", project=project, execution=execution)
    finally:
        db.close()


# ------------------------------------------------------------ RAG explorer --

@app.route("/knowledge-base")
def knowledge_base_page():
    db = SessionLocal()
    try:
        project = _get_project(db)
        source = request.args.get("source", "All")
        q = request.args.get("q", "")
        all_docs = load_all_documents()
        filtered = filter_documents(all_docs, source=source, query=q)

        cited_identifiers = set()
        if project:
            project_threats = db.query(m.Threat).filter(m.Threat.project_id == project.id).all()
            for t in project_threats:
                for field in (t.owasp_category, t.cwe_id, t.mitre_attack_technique):
                    if field:
                        cited_identifiers.add(field.lower())
                for src in (t.rag_sources or []):
                    if src.get("identifier"):
                        cited_identifiers.add(src["identifier"].lower())

        source_counts = {}
        for d in all_docs:
            source_counts[d["source"]] = source_counts.get(d["source"], 0) + 1

        try:
            import chromadb  # noqa: F401
            vector_store_available = True
        except ImportError:
            vector_store_available = False

        return render_template(
            "knowledge_base.html", project=project, documents=filtered, total_count=len(all_docs),
            source_counts=source_counts, source_filter=source, search_q=q,
            cited_identifiers=cited_identifiers, vector_store_available=vector_store_available,
        )
    finally:
        db.close()


@app.route("/knowledge-base/<path:doc_id>")
def knowledge_base_detail_page(doc_id):
    db = SessionLocal()
    try:
        project = _get_project(db)
        doc = get_document(doc_id)
        if not doc:
            return "Document not found in the knowledge base corpus.", 404
        citing_threats = []
        if project:
            project_threats = db.query(m.Threat).filter(m.Threat.project_id == project.id).all()
            citing_threats = find_citing_threats(project_threats, doc)
        return render_template("knowledge_base_detail.html", project=project, doc=doc, citing_threats=citing_threats)
    finally:
        db.close()


# ------------------------------------------------------- security pipeline --

STAGE_DISPLAY = [
    (m.ProjectStage.SYSTEM_ANALYSIS, "System Analysis"),
    (m.ProjectStage.ASSET_DISCOVERY, "Asset Discovery"),
    (m.ProjectStage.THREAT_MODELING, "Threat Modeling"),
    (m.ProjectStage.ATTACK_SCENARIO_GENERATION, "Attack Scenario Generation"),
    (m.ProjectStage.TEST_GENERATION, "Test Generation"),
    (m.ProjectStage.TEST_VALIDATION, "Validation"),
    (m.ProjectStage.RISK_PRIORITIZATION, "Risk Analysis"),
]


@app.route("/security-pipeline")
def security_pipeline_page():
    """
    Shows the fixed, deterministic pipeline's progress for the active
    project: each stage is Pending, Processing, Completed, or Failed,
    read directly from PipelineStepRun history — not simulated, and not
    an "agent status" (there are no autonomous agents in this system).
    """
    db = SessionLocal()
    try:
        project = _get_project(db)
        stage_statuses, timeline = [], []
        if project:
            all_runs = (
                db.query(m.PipelineStepRun).filter(m.PipelineStepRun.project_id == project.id)
                .order_by(m.PipelineStepRun.started_at.asc()).all()
            )
            for stage_key, stage_label in STAGE_DISPLAY:
                runs_for_stage = [r for r in all_runs if r.stage == stage_key]
                latest_run = runs_for_stage[-1] if runs_for_stage else None
                if latest_run and latest_run.status == m.PipelineStepStatus.SUCCEEDED:
                    status = "completed"
                elif latest_run and latest_run.status == m.PipelineStepStatus.RUNNING:
                    status = "processing"
                elif latest_run and latest_run.status == m.PipelineStepStatus.FAILED:
                    status = "failed"
                else:
                    status = "pending"
                stage_statuses.append((stage_key.value, stage_label, status, latest_run))

            for r in reversed(all_runs):
                verb = {"SUCCEEDED": "completed", "FAILED": "failed", "RUNNING": "started", "RETRIED": "retried"}.get(r.status.value, "updated")
                timeline.append({
                    "timestamp": r.finished_at or r.started_at,
                    "status": r.status,
                    "description": f"{r.step_name} {verb}" + (f" - {r.error}" if r.error else ""),
                })

        return render_template("security_pipeline.html", project=project, stage_statuses=stage_statuses, timeline=timeline)
    finally:
        db.close()





# ----------------------------------------------------------------- reports --

@app.route("/reports")
def reports_page():
    db = SessionLocal()
    try:
        project = _get_project(db)
        formats = [
            ("pdf", "PDF Report", "Full narrative report with executive summary, threat model, and traceability tables."),
            ("json", "JSON Export", "Machine-readable export of the complete assessment, for integration or archival."),
            ("csv", "CSV (Threats)", "Flat threat list for spreadsheets - ID, STRIDE category, risk score, mitigation."),
        ]
        return render_template("reports.html", project=project, formats=formats)
    finally:
        db.close()


@app.route("/reports/download/<fmt>")
def download_report(fmt):
    db = SessionLocal()
    try:
        project = _get_project(db)
        if not project:
            return redirect("/settings")
        output_dir = settings.reports_dir
        if fmt == "json":
            path = generate_json_report(db, project, output_dir)
        elif fmt == "csv":
            path = generate_csv_report(db, project, output_dir)
        elif fmt == "pdf":
            path = generate_pdf_report(db, project, output_dir)
        else:
            return "Unknown format", 400
        return send_file(path, as_attachment=True, download_name=os.path.basename(path))
    finally:
        db.close()


# ----------------------------------------------------------------- settings --

@app.route("/settings")
def settings_page():
    db = SessionLocal()
    try:
        project = _get_project(db)
        tab = request.args.get("tab", "manual")
        return render_template("settings.html", project=project, tab=tab, run_log=None, extracted_model_json=None)
    finally:
        db.close()


@app.route("/settings/create-project", methods=["POST"])
def create_project():
    db = SessionLocal()
    try:
        owner = get_current_user(db)
        if not owner:
            session.clear()
            return redirect("/login")
        project = m.Project(owner_id=owner.id, name=request.form.get("name", "Untitled Project"))
        db.add(project)
        db.commit()
        db.refresh(project)
        resp = redirect("/settings")
        resp.set_cookie("tm_project_id", project.id, max_age=60 * 60 * 24 * 30)
        return resp
    finally:
        db.close()


@app.route("/settings/authorize", methods=["POST"])
def authorize_project():
    db = SessionLocal()
    try:
        project = _get_project(db)
        if not project:
            return redirect("/settings")
        confirmation = request.form.get("confirmation", "")
        if confirmation.strip() != REQUIRED_CONFIRMATION:
            return render_template(
                "settings.html", project=project, tab="manual", run_log=None, extracted_model_json=None,
                error=f"Confirmation statement must exactly read: {REQUIRED_CONFIRMATION!r}",
            ), 400
        project.authorized_for_active_testing = True
        project.authorization_statement = confirmation
        project.allowlisted_targets = [s.strip() for s in request.form.get("allowlist", "").split(",") if s.strip()]
        db.commit()
        return redirect("/settings")
    finally:
        db.close()


@app.route("/settings/run-pipeline", methods=["POST"])
def run_pipeline_route():
    db = SessionLocal()
    try:
        project = _get_project(db)
        if not project:
            return redirect("/settings")
        input_type = request.form.get("input_type", "manual")
        raw_text = request.form.get("raw_text", "")
        payload = (
            {"raw_input_type": "manual", "manual_entries": SAMPLE_MANUAL} if input_type == "manual"
            else {"raw_input_type": input_type, "raw_text": raw_text}
        )
        try:
            run_log = _run_pipeline(db, project, payload)
        except Exception as exc:  # noqa: BLE001
            return render_template(
                "settings.html", project=project, tab=input_type, run_log=None, extracted_model_json=None,
                error=f"Pipeline run failed: {exc}",
            ), 500
        return render_template("settings.html", project=project, tab=input_type, run_log=run_log, extracted_model_json=None)
    finally:
        db.close()


@app.route("/settings/validate-openapi", methods=["POST"])
def validate_openapi_route():
    """
    Section 14 of the upload spec — 'THIS IS IMPORTANT': show a real
    validation summary (actual parsed version/endpoint/schema/auth counts,
    never hard-coded) BEFORE committing to a full AI analysis run. Works
    for both the file-upload dropzone and the "paste directly" textarea —
    both funnel through here. On success, the raw spec text is embedded in
    a hidden field so the follow-up "Start AI Security Analysis" button
    can submit it without re-uploading anything.
    """
    db = SessionLocal()
    try:
        project = _get_project(db)
        if not project:
            return redirect("/settings")

        file = request.files.get("file")
        if file and file.filename:
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in {".json", ".yaml", ".yml"}:
                return render_template(
                    "settings.html", project=project, tab="openapi", run_log=None, extracted_model_json=None,
                    openapi_validation={"valid": False, "error": f"Unsupported file extension '{ext or '(none)'}'. Supported formats: JSON, YAML."},
                ), 400

            raw_bytes = file.read(MAX_OPENAPI_SIZE + 1)  # read one byte past the limit so we can detect overflow without loading the whole file
            if len(raw_bytes) > MAX_OPENAPI_SIZE:
                return render_template(
                    "settings.html", project=project, tab="openapi", run_log=None, extracted_model_json=None,
                    openapi_validation={"valid": False, "error": "File exceeds the maximum allowed size of 10 MB."},
                ), 400
            size_bytes = len(raw_bytes)
            try:
                raw_text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                return render_template(
                    "settings.html", project=project, tab="openapi", run_log=None, extracted_model_json=None,
                    openapi_validation={"valid": False, "error": "Could not read the file as UTF-8 text."},
                ), 400
        else:
            raw_text = request.form.get("raw_text", "")
            size_bytes = len(raw_text.encode("utf-8"))
            if size_bytes > MAX_OPENAPI_SIZE:
                return render_template(
                    "settings.html", project=project, tab="openapi", run_log=None, extracted_model_json=None,
                    openapi_validation={"valid": False, "error": "Pasted content exceeds the maximum allowed size of 10 MB."},
                ), 400

        if not raw_text.strip():
            return render_template(
                "settings.html", project=project, tab="openapi", run_log=None, extracted_model_json=None,
                openapi_validation={"valid": False, "error": "No file or text was provided."},
            ), 400

        result = _validate_openapi(raw_text, size_bytes)
        return render_template(
            "settings.html", project=project, tab="openapi", run_log=None, extracted_model_json=None,
            openapi_validation=result, openapi_raw_text=raw_text if result.get("valid") else None,
        )
    finally:
        db.close()


# ------------------------------------------------------------------- auth --

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if session.get("user_id"):
        return redirect("/")

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        next_path = request.form.get("next") or "/"

        db = SessionLocal()
        try:
            user = db.query(m.User).filter(m.User.email == email).first()
            if not user:
                error = GENERIC_LOGIN_ERROR
            elif is_locked_out(user):
                error = f"This account is temporarily locked due to repeated failed sign-in attempts. Try again in a few minutes."
            elif not verify_password(password, user.hashed_password):
                record_failed_login(db, user)
                error = GENERIC_LOGIN_ERROR
            else:
                record_successful_login(db, user)
                session["user_id"] = user.id
                session["role"] = user.role.value
                session["email"] = user.email
                # "Remember me" extends the session cookie to PERMANENT_SESSION_LIFETIME
                # (30 days); unchecked, the session ends when the browser closes, as normal.
                session.permanent = bool(request.form.get("remember_me"))
                return redirect(next_path if next_path.startswith("/") else "/")
        finally:
            db.close()

    return render_template("login.html", error=error, next_path=request.args.get("next", "/"))


@app.route("/register", methods=["GET", "POST"])
def register_page():
    if session.get("user_id"):
        return redirect("/")

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        full_name = request.form.get("full_name", "").strip()

        if not email or "@" not in email:
            error = "Enter a valid email address."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        else:
            db = SessionLocal()
            try:
                existing = db.query(m.User).filter(m.User.email == email).first()
                if existing:
                    error = "An account with that email already exists."
                else:
                    # New self-registrations are always USER role — nobody can grant
                    # themselves ADMIN through this form; that's a server-enforced rule,
                    # not a UI convenience.
                    user = m.User(
                        email=email, hashed_password=hash_password(password),
                        full_name=full_name or None, role=m.UserRole.USER,
                    )
                    db.add(user)
                    db.commit()
                    return redirect("/login")
            finally:
                db.close()

    return render_template("register.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")


@app.route("/admin/users")
@admin_required
def admin_users_page():
    db = SessionLocal()
    try:
        users = db.query(m.User).order_by(m.User.created_at.asc()).all()
        return render_template("admin_users.html", users=users)
    finally:
        db.close()


# -------------------------------------------------------------------- misc --

@app.route("/health")
def health():
    return {"status": "ok", "llm_provider": settings.llm_provider}


def _ingest_knowledge_base_if_available():
    """
    Loads the OWASP/CWE/MITRE corpus into the vector store at startup, so
    RAG retrieval actually has something to search. This is genuinely
    optional: if chromadb isn't installed, this fails fast and silently —
    RAG retrieval will then honestly report itself as unavailable
    everywhere in the UI, exactly as designed, rather than crashing the
    whole app over an optional dependency.
    """
    try:
        from rag.ingest import ingest_knowledge_base
        count = ingest_knowledge_base()
        print(f"RAG knowledge base ready: {count} chunks indexed.")
    except ImportError:
        print("chromadb not installed - RAG retrieval will report itself as unavailable. "
              "Run 'pip install chromadb sentence-transformers' to enable it.")
    except Exception as exc:  # noqa: BLE001
        print(f"RAG knowledge base ingestion failed ({exc}) - continuing without it.")


if __name__ == "__main__":
    init_db()
    seed_default_admin()
    _ingest_knowledge_base_if_available()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=(settings.environment == "dev"))
