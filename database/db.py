"""
Database engine + session management. Plain SQLAlchemy rather than the
Flask-SQLAlchemy extension — this keeps every service module exactly as
framework-agnostic as it was before the Flask migration (they all just take
a `db: Session` argument), and avoids tying the whole codebase to Flask's
app-context lifecycle for something as basic as opening a DB connection.

SQLite only, per Section 3 — no Postgres. The database file is created
automatically on first run if it doesn't exist (SQLite just creates it on
connect; we also make sure the containing `data/` directory exists).
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from config import get_settings

settings = get_settings()

os.makedirs(os.path.dirname(settings.database_path) or ".", exist_ok=True)

engine = create_engine(
    f"sqlite:///{settings.database_path}",
    connect_args={"check_same_thread": False},  # needed since Flask's dev server may use threads
    pool_pre_ping=True,
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def init_db():
    """Creates all tables if they don't already exist. Called once at app startup."""
    from database import models  # noqa: F401  (ensures all model classes are registered on Base)
    Base.metadata.create_all(bind=engine)
