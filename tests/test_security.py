"""
Security hardening regression tests. Run with:

    pytest tests/test_security.py -v

These exercise the actual Flask routes via the test client (not just the
underlying functions in isolation), so a passing suite here means the real
HTTP-facing behavior is correct, not just that a helper function works when
called directly.
"""
import io
import os
import re
import uuid

os.environ.setdefault("TM_LLM_PROVIDER", "mock")
os.environ.setdefault("TM_DATABASE_PATH", "/tmp/tm_test_security.db")

import pytest

from app import app as flask_app
from database.db import SessionLocal, init_db
from database import models as m


def _get_token(client, path):
    r = client.get(path)
    match = re.search(r'name="csrf_token" value="([^"]+)"', r.data.decode())
    assert match, f"CSRF token not found on {path} — cannot proceed with test"
    return match.group(1)


@pytest.fixture()
def client():
    init_db()
    flask_app.config.update(TESTING=True)
    with flask_app.test_client() as c:
        # Every test gets its own fresh, uniquely-emailed account so tests
        # never collide with each other even though they share one SQLite
        # file across the whole pytest session (consistent with how project
        # names are already kept unique per test below).
        email = f"sectest-{uuid.uuid4().hex[:10]}@example.com"
        password = "TestPassw0rd!"

        token = _get_token(c, "/register")
        c.post("/register", data={"email": email, "password": password, "csrf_token": token})

        token = _get_token(c, "/login")
        c.post("/login", data={"email": email, "password": password, "next": "/", "csrf_token": token})

        yield c


def _csrf_token(client, path="/settings"):
    return _get_token(client, path)


def _create_authorized_project(client, name):
    token = _csrf_token(client)
    client.post("/settings/create-project", data={"name": name, "csrf_token": token})
    token = _csrf_token(client)
    client.post("/settings/authorize", data={
        "confirmation": "I confirm that I am authorized to test this target.",
        "allowlist": "localhost",
        "csrf_token": token,
    })
    token = _csrf_token(client)
    client.post("/settings/run-pipeline", data={"input_type": "manual", "csrf_token": token})


# ------------------------------------------------------------------ IDOR --

def test_idor_correct_threat_and_test_allowed(client):
    _create_authorized_project(client, "IDOR Allowed Test")
    db = SessionLocal()
    project = db.query(m.Project).filter(m.Project.name == "IDOR Allowed Test").first()
    threat = db.query(m.Threat).filter(m.Threat.project_id == project.id).first()
    test = threat.attack_scenarios[0].security_tests[0]
    threat_id, test_id = threat.id, test.id
    db.close()

    token = _csrf_token(client)
    r = client.post(f"/threats/{threat_id}/tests/{test_id}/approve", data={"csrf_token": token})
    assert r.status_code == 302


def test_idor_wrong_threat_rejected(client):
    _create_authorized_project(client, "IDOR Rejected Test")
    db = SessionLocal()
    project = db.query(m.Project).filter(m.Project.name == "IDOR Rejected Test").first()
    threats = db.query(m.Threat).filter(m.Threat.project_id == project.id).all()
    assert len(threats) >= 2, "need at least 2 threats for a cross-threat IDOR test"
    test_belongs_to_threat_a = threats[0].attack_scenarios[0].security_tests[0]
    threat_b_id = threats[1].id
    test_id = test_belongs_to_threat_a.id
    db.close()

    token = _csrf_token(client)
    r = client.post(f"/threats/{threat_b_id}/tests/{test_id}/approve", data={"csrf_token": token})
    assert r.status_code == 404


def test_idor_nonexistent_threat_rejected(client):
    _create_authorized_project(client, "IDOR Nonexistent Threat")
    db = SessionLocal()
    project = db.query(m.Project).filter(m.Project.name == "IDOR Nonexistent Threat").first()
    threat = db.query(m.Threat).filter(m.Threat.project_id == project.id).first()
    test = threat.attack_scenarios[0].security_tests[0]
    test_id = test.id
    db.close()

    token = _csrf_token(client)
    r = client.post(f"/threats/does-not-exist/tests/{test_id}/approve", data={"csrf_token": token})
    assert r.status_code == 404


def test_idor_nonexistent_test_rejected(client):
    _create_authorized_project(client, "IDOR Nonexistent Test")
    db = SessionLocal()
    project = db.query(m.Project).filter(m.Project.name == "IDOR Nonexistent Test").first()
    threat = db.query(m.Threat).filter(m.Threat.project_id == project.id).first()
    threat_id = threat.id
    db.close()

    token = _csrf_token(client)
    r = client.post(f"/threats/{threat_id}/tests/does-not-exist/approve", data={"csrf_token": token})
    assert r.status_code == 404


# ------------------------------------------------------------------ CSRF --

def test_csrf_post_without_token_rejected(client):
    r = client.post("/settings/create-project", data={"name": "No Token"})
    assert r.status_code == 400


def test_csrf_post_with_valid_token_allowed(client):
    token = _csrf_token(client)
    r = client.post("/settings/create-project", data={"name": "Valid Token", "csrf_token": token})
    assert r.status_code == 302


# ------------------------------------------------------------- uploads --

def test_oversized_openapi_upload_rejected(client):
    _create_authorized_project(client, "Oversized OpenAPI Test")
    token = _csrf_token(client)
    huge = "openapi: 3.0.0\n" + ("x: 1\n" * 3_000_000)  # well over 10MB
    files = {"file": (io.BytesIO(huge.encode()), "huge.yaml")}
    r = client.post("/settings/validate-openapi", data={"csrf_token": token, **files}, content_type="multipart/form-data")
    assert r.status_code == 400
    assert b"maximum allowed size" in r.data


def test_invalid_openapi_content_rejected(client):
    _create_authorized_project(client, "Invalid OpenAPI Test")
    token = _csrf_token(client)
    files = {"file": (io.BytesIO(b"this is not an openapi document"), "bad.yaml")}
    r = client.post("/settings/validate-openapi", data={"csrf_token": token, **files}, content_type="multipart/form-data")
    assert r.status_code == 200  # renders the friendly invalid-file card, not an error status
    assert b"Unable to process file" in r.data


# ------------------------------------------------------------ authorization --

def test_unauthorized_target_rejected(client):
    """
    A project that has NOT submitted the Section 30 authorization statement
    must never be able to execute a controlled test, regardless of what the
    UI would normally gate — this exercises the actual execution engine's
    authorization check, not just the button's disabled state.
    """
    token = _csrf_token(client)
    client.post("/settings/create-project", data={"name": "Unauthorized Target Test", "csrf_token": token})
    token = _csrf_token(client)
    client.post("/settings/run-pipeline", data={"input_type": "manual", "csrf_token": token})
    # deliberately skip /settings/authorize

    db = SessionLocal()
    project = db.query(m.Project).filter(m.Project.name == "Unauthorized Target Test").first()
    assert project.authorized_for_active_testing is False
    threat = db.query(m.Threat).filter(m.Threat.project_id == project.id).first()
    test = threat.attack_scenarios[0].security_tests[0]
    test.validation_status = m.ValidationStatus.VALID
    test.approved = True
    db.commit()
    threat_id, test_id = threat.id, test.id
    db.close()

    token = _csrf_token(client)
    client.post(f"/threats/{threat_id}/tests/{test_id}/execute", data={"base_url": "http://localhost:9999", "csrf_token": token})

    db = SessionLocal()
    test = db.get(m.SecurityTest, test_id)
    latest_execution = sorted(test.executions, key=lambda e: e.started_at)[-1]
    assert latest_execution.status == m.ExecutionStatus.BLOCKED_BY_POLICY
    assert "not authorized" in (latest_execution.actual_result or "").lower()
    db.close()


# ---------------------------------------------------------------- xss --

def test_asset_graph_escapes_malicious_asset_name(client):
    """
    Regression test for a real, confirmed-exploitable stored XSS: the SVG
    asset graph is rendered with Jinja's `| safe` filter (required so it
    displays as an actual diagram), which bypasses HTML auto-escaping. A
    crafted asset name containing a raw '</text><script>...' sequence must
    never appear unescaped in the rendered page.
    """
    _create_authorized_project(client, "XSS Asset Name Test")
    db = SessionLocal()
    project = db.query(m.Project).filter(m.Project.name == "XSS Asset Name Test").first()
    evil_name = "</text><script>alert(document.cookie)</script><text>"
    db.add(m.Asset(project_id=project.id, name=evil_name, asset_type=m.AssetType.API, criticality="High"))
    db.commit()
    db.close()

    r = client.get("/assets")
    assert r.status_code == 200
    assert b"</text><script>alert" not in r.data
    assert b"&lt;script&gt;" in r.data


def test_asset_graph_json_cannot_break_out_of_script_tag(client):
    """
    Regression test for the classic JSON-in-<script>-tag vulnerability:
    json.dumps() does not escape '/', so an asset name containing the
    literal text '</script>' could prematurely close the embedding
    <script type="application/json"> block and inject arbitrary HTML.
    """
    _create_authorized_project(client, "XSS JSON Breakout Test")
    db = SessionLocal()
    project = db.query(m.Project).filter(m.Project.name == "XSS JSON Breakout Test").first()
    evil_name = "</script><script>alert(1)</script>"
    db.add(m.Asset(project_id=project.id, name=evil_name, asset_type=m.AssetType.API, criticality="High"))
    db.commit()
    db.close()

    r = client.get("/assets")
    assert r.status_code == 200
    assert b"</script><script>alert(1)</script>" not in r.data
