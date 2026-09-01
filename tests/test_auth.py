"""
Authentication and RBAC tests. Run with:

    pytest tests/test_auth.py -v
"""
import os
import re
import uuid

os.environ.setdefault("TM_LLM_PROVIDER", "mock")
os.environ.setdefault("TM_DATABASE_PATH", "/tmp/tm_test_security.db")

import pytest

from app import app as flask_app
from database.db import SessionLocal, init_db
from database import models as m
from security.auth import hash_password, seed_default_admin


def _get_token(client, path):
    r = client.get(path)
    match = re.search(r'name="csrf_token" value="([^"]+)"', r.data.decode())
    assert match, f"CSRF token not found on {path}"
    return match.group(1)


@pytest.fixture()
def client():
    init_db()
    flask_app.config.update(TESTING=True)
    with flask_app.test_client() as c:
        yield c


def _register(client, email, password="TestPassw0rd!"):
    token = _get_token(client, "/register")
    return client.post("/register", data={"email": email, "password": password, "csrf_token": token})


def _login(client, email, password="TestPassw0rd!"):
    token = _get_token(client, "/login")
    return client.post("/login", data={"email": email, "password": password, "next": "/", "csrf_token": token})


# ------------------------------------------------------------- unauthenticated access --

def test_protected_route_redirects_to_login_when_not_authenticated(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_login_page_itself_is_reachable_without_auth(client):
    r = client.get("/login")
    assert r.status_code == 200


def test_health_endpoint_is_reachable_without_auth(client):
    r = client.get("/health")
    assert r.status_code == 200


# ------------------------------------------------------------------- login --

def test_register_then_login_succeeds(client):
    email = f"login-ok-{uuid.uuid4().hex[:8]}@example.com"
    r = _register(client, email)
    assert r.status_code == 302  # redirect to /login on success

    r = _login(client, email)
    assert r.status_code == 302
    assert r.headers["Location"] == "/"

    # session should now grant access to a previously-protected route
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 200


def test_login_wrong_password_rejected_with_generic_error(client):
    email = f"login-bad-{uuid.uuid4().hex[:8]}@example.com"
    _register(client, email)

    token = _get_token(client, "/login")
    r = client.post("/login", data={"email": email, "password": "wrong-password", "next": "/", "csrf_token": token})
    assert r.status_code == 200  # re-renders login page with error, no redirect
    assert b"Invalid username or password" in r.data
    # must not leak whether the account exists
    assert b"no such user" not in r.data.lower()
    assert b"user not found" not in r.data.lower()


def test_login_nonexistent_account_same_generic_error(client):
    token = _get_token(client, "/login")
    r = client.post("/login", data={
        "email": "definitely-does-not-exist@example.com", "password": "whatever123",
        "next": "/", "csrf_token": token,
    })
    assert b"Invalid username or password" in r.data


def test_account_locks_out_after_repeated_failed_logins(client):
    email = f"lockout-{uuid.uuid4().hex[:8]}@example.com"
    _register(client, email)

    for _ in range(5):
        token = _get_token(client, "/login")
        client.post("/login", data={"email": email, "password": "wrong", "next": "/", "csrf_token": token})

    # 6th attempt, even with the CORRECT password, should now be locked out
    token = _get_token(client, "/login")
    r = client.post("/login", data={"email": email, "password": "TestPassw0rd!", "next": "/", "csrf_token": token})
    assert b"locked" in r.data.lower()

    db = SessionLocal()
    user = db.query(m.User).filter(m.User.email == email).first()
    assert user.locked_until is not None
    db.close()


def test_logout_clears_session(client):
    email = f"logout-{uuid.uuid4().hex[:8]}@example.com"
    _register(client, email)
    _login(client, email)
    assert client.get("/", follow_redirects=False).status_code == 200

    token = _get_token(client, "/settings")
    client.post("/logout", data={"csrf_token": token})

    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


# ------------------------------------------------------------------- RBAC --

def test_regular_user_cannot_access_admin_route(client):
    email = f"regular-{uuid.uuid4().hex[:8]}@example.com"
    _register(client, email)
    _login(client, email)

    r = client.get("/admin/users")
    assert r.status_code == 403


def test_admin_can_access_admin_route(client):
    seed_default_admin()
    token = _get_token(client, "/login")
    r = client.post("/login", data={
        "email": "admin", "password": "admin",
        "next": "/", "csrf_token": token,
    })
    assert r.status_code == 302

    r = client.get("/admin/users")
    assert r.status_code == 200
    assert b"User Management" in r.data


def test_new_registrations_cannot_self_grant_admin_role(client):
    """A registration form field can't be used to smuggle in role=ADMIN."""
    email = f"norole-{uuid.uuid4().hex[:8]}@example.com"
    token = _get_token(client, "/register")
    client.post("/register", data={"email": email, "password": "TestPassw0rd!", "role": "ADMIN", "csrf_token": token})

    db = SessionLocal()
    user = db.query(m.User).filter(m.User.email == email).first()
    assert user.role == m.UserRole.USER
    db.close()


def test_passwords_are_hashed_not_plaintext(client):
    email = f"hash-{uuid.uuid4().hex[:8]}@example.com"
    _register(client, email, password="SuperSecret123!")

    db = SessionLocal()
    user = db.query(m.User).filter(m.User.email == email).first()
    assert user.hashed_password != "SuperSecret123!"
    assert "SuperSecret123!" not in user.hashed_password
    db.close()
