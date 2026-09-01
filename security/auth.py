"""
Authentication and role-based access control.

- Passwords are hashed with Werkzeug's generate_password_hash/check_password_hash
  (PBKDF2-SHA256 by default) — never stored or logged in plaintext.
- Sessions use Flask's signed session cookie (server-side secret_key already
  configured in app.py), not a custom token scheme.
- Login is rate-limited per account: after MAX_FAILED_ATTEMPTS consecutive
  failures, the account is locked for LOCKOUT_MINUTES. This is deliberately
  simple (no external cache/service) since the whole point of this project
  is to stay SQLite-only and dependency-light.
- Every protected route is enforced server-side via the @login_required /
  @admin_required decorators (or the blanket before_request gate in app.py)
  — never just a hidden sidebar link. A normal USER hitting an admin URL
  directly gets a 403, not a redirect to a page they can't see a link to.
"""
from __future__ import annotations

from functools import wraps

from flask import abort, redirect, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from database.db import SessionLocal
from database.models import User, UserRole
from utils import now_utc

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

GENERIC_LOGIN_ERROR = "Invalid username or password."


def hash_password(raw_password: str) -> str:
    return generate_password_hash(raw_password)


def verify_password(raw_password: str, hashed: str) -> bool:
    return check_password_hash(hashed, raw_password)


def is_locked_out(user: User) -> bool:
    return bool(user.locked_until and user.locked_until > now_utc())


def record_failed_login(db, user: User) -> None:
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        from datetime import timedelta
        user.locked_until = now_utc() + timedelta(minutes=LOCKOUT_MINUTES)
    db.commit()


def record_successful_login(db, user: User) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()


def get_current_user(db) -> User | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.get(User, user_id)


def login_required(view_func):
    """Redirects to /login if no session is present. Use for ordinary protected pages."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(f"/login?next={request.path}")
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    """
    403s (does not redirect) if the session user isn't an ADMIN — a normal
    user typing an admin URL directly gets a hard, server-enforced denial,
    not a UI that merely hides the link.
    """
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(f"/login?next={request.path}")
        if session.get("role") != UserRole.ADMIN.value:
            abort(403)
        return view_func(*args, **kwargs)
    return wrapped


def seed_default_admin() -> None:
    """
    Creates a default admin account on first run so there's always a way in
    on a fresh database. Login ID is the literal string "admin" (not an
    email — the login field accepts either), password "admin". This is a
    deliberately simple demo credential, still stored as a proper hash,
    never plaintext — change it immediately in any real deployment.
    """
    db = SessionLocal()
    try:
        existing_admin = db.query(User).filter(User.role == UserRole.ADMIN).first()
        if existing_admin:
            return
        admin = User(
            email="admin",
            hashed_password=hash_password("admin"),
            full_name="Administrator",
            role=UserRole.ADMIN,
        )
        db.add(admin)
        db.commit()
    finally:
        db.close()
