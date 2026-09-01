"""
Central configuration for the AI-Driven Threat Modeling & Security Test
Generation platform (Flask edition).

Deliberately plain os.environ + python-dotenv rather than pydantic-settings
— one fewer dependency, and this project's whole ethos is "keep it simple
enough to explain in an M.Tech evaluation." Everything that must never be
hard-coded (LLM provider, DB path, allowlisted test targets, execution
limits) is read from environment variables / .env so the same codebase
runs in dev or on a grading machine without code changes.
"""
from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str, default: list[str]) -> list[str]:
    val = os.environ.get(name)
    if not val:
        return default
    return [v.strip() for v in val.split(",") if v.strip()]


class Settings:
    # --- App ---
    app_name = "AI-Driven Threat Modeling & Security Test Generation Platform"
    environment = os.environ.get("TM_ENVIRONMENT", "dev")
    secret_key = os.environ.get("TM_SECRET_KEY", "dev-secret-key-change-in-production")

    # --- Database (SQLite only — no Postgres per Section 3) ---
    database_path = os.environ.get("TM_DATABASE_PATH", os.path.join("data", "threatmodel.db"))

    # --- LLM provider (never hard-coded) ---
    llm_provider = os.environ.get("TM_LLM_PROVIDER", "mock")  # mock | openai | azure_openai | ollama | anthropic
    llm_model = os.environ.get("TM_LLM_MODEL", "gpt-4o-mini")
    llm_api_key = os.environ.get("TM_LLM_API_KEY", "")
    llm_api_base = os.environ.get("TM_LLM_API_BASE", "")
    llm_temperature = float(os.environ.get("TM_LLM_TEMPERATURE", "0.1"))
    llm_max_retries = int(os.environ.get("TM_LLM_MAX_RETRIES", "3"))

    # --- RAG ---
    vector_store = os.environ.get("TM_VECTOR_STORE", "chroma")
    embedding_provider = os.environ.get("TM_EMBEDDING_PROVIDER", "sentence-transformers")
    embedding_model = os.environ.get("TM_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    rag_top_k = int(os.environ.get("TM_RAG_TOP_K", "6"))
    knowledge_base_dir = os.environ.get("TM_KNOWLEDGE_BASE_DIR", os.path.join("rag", "knowledge_base"))
    vector_store_dir = os.environ.get("TM_VECTOR_STORE_DIR", os.path.join("data", "vector_store"))

    # --- Controlled test execution / safety (Section 20) ---
    execution_target_allowlist = _list(
        "TM_EXECUTION_TARGET_ALLOWLIST", ["localhost", "127.0.0.1", "demo-app"]
    )
    execution_require_explicit_authorization = _bool("TM_EXECUTION_REQUIRE_EXPLICIT_AUTHORIZATION", True)
    execution_max_requests_per_test = int(os.environ.get("TM_EXECUTION_MAX_REQUESTS_PER_TEST", "25"))
    execution_rate_limit_per_second = float(os.environ.get("TM_EXECUTION_RATE_LIMIT_PER_SECOND", "5"))
    execution_timeout_seconds = int(os.environ.get("TM_EXECUTION_TIMEOUT_SECONDS", "15"))
    execution_total_run_timeout_seconds = int(os.environ.get("TM_EXECUTION_TOTAL_RUN_TIMEOUT_SECONDS", "300"))

    # --- Reports ---
    reports_dir = os.environ.get("TM_REPORTS_DIR", "reports")


_settings = Settings()


def get_settings() -> Settings:
    return _settings
