# ThreatLens - AI-Assisted Threat Modeling and Automated Security Test Generation

M.Tech Cybersecurity capstone project. ThreatLens is an AI-assisted
cybersecurity platform that combines deterministic threat modeling,
STRIDE, RAG-grounded LLM analysis, automated security test generation,
validation, controlled security testing, risk prioritization, evidence
collection, remediation tracking, and reporting.

**Python-only. No machine-learning model training or dataset is
required.** No React, no Node/npm, no Docker, no PostgreSQL, no Redis.
One process, one command:

```bash
pip install -r requirements.txt
python app.py
```

Then open **http://localhost:5000/**.

## Architecture: a fixed, deterministic pipeline — not Agentic AI

This system does **not** use autonomous agents, agent orchestration, agent
state machines, or agentic feedback loops. There is no component that
decides on its own what to do next. Every stage is a plain, explicit
function/service call made in a hard-coded sequence by ordinary Python
code:

```text
USER -> FLASK UI -> PYTHON APPLICATION
  -> SYSTEM ANALYSIS -> ASSET DISCOVERY -> THREAT MODELING
  -> STRIDE CLASSIFICATION -> RAG RETRIEVAL -> LLM SECURITY ANALYSIS
  -> ATTACK SCENARIO GENERATION -> SECURITY TEST GENERATION
  -> RULE-BASED VALIDATION -> HUMAN APPROVAL -> CONTROLLED TEST EXECUTION
  -> EVIDENCE COLLECTION -> RISK ANALYSIS -> REMEDIATION -> RETEST -> REPORT
```

The one place this pipeline "loops" is test generation: if Rule-Based
Validation marks a generated test INVALID, the pipeline sends it back to
the Security Test Generator for a **fixed, bounded** number of retries
(`MAX_RETRIES = 2`, a plain module constant in
`pipeline/security_analysis_pipeline.py`). Nothing decides on its own
whether to keep retrying — after the limit, the test stays INVALID for a
human to review.

### The LLM's role

The LLM is used for security analysis, threat description, attack
scenario generation, security test generation, and remediation
recommendations. The LLM does **not** decide which tool to call, decide
the next workflow step, autonomously execute actions, delegate tasks, or
maintain state. The Python application controls the workflow at every
step.

## Project structure

```text
threatmodel-platform/
├── app.py                  # Flask entrypoint — every route lives here
├── config.py                # env-driven settings (.env)
├── requirements.txt
│
├── pipeline/
│   └── security_analysis_pipeline.py   # the fixed, deterministic pipeline function
│
├── services/                # one module per pipeline step — plain service classes, not agents
│   ├── base.py                    # shared LLM/logging plumbing (feeds the pipeline page + activity log)
│   ├── system_analysis.py         # OpenAPI / manual / architecture-text / diagram input
│   ├── source_code_analysis.py    # deterministic static scan of an uploaded source .zip
│   ├── asset_discovery.py
│   ├── threat_modeling.py         # STRIDE + RAG grounding
│   ├── attack_scenario.py
│   ├── test_generation.py         # SecurityTestGenerator
│   ├── test_validation.py         # TestValidator — fully deterministic, no LLM call by design
│   ├── risk_analyzer.py           # RiskAnalyzer — reads threats from the DB, delegates scoring to security/risk_engine.py's pure math
│   └── report_generator.py        # PDF/JSON/CSV generation
│
├── ai/
│   ├── llm_client.py         # provider-agnostic (openai/azure/ollama/anthropic/mock), vision-capable
│   ├── prompts.py             # every prompt template, centralized
│   └── schemas.py             # lightweight system-model validation
│
├── rag/
│   ├── retriever.py            # Chroma-backed retrieval (optional dependency)
│   ├── corpus_browser.py       # browse the KB without needing chromadb installed
│   ├── ingest.py
│   └── knowledge_base/*.json   # OWASP / CWE / MITRE ATT&CK seed corpus
│
├── security/
│   ├── test_engine.py         # Controlled Test Execution Engine — the only code allowed on a network socket
│   ├── authorization.py       # the single choke point every execution must pass through
│   ├── allowlist.py
│   ├── evidence.py
│   ├── risk_engine.py         # pure scoring math + Security Posture Score formula
│   └── auth.py                # password hashing, session login/logout, RBAC decorators, account lockout
│
├── database/
│   ├── db.py                  # SQLite engine/session, auto-creates data/threatmodel.db
│   └── models.py               # 15-table schema
│
├── templates/ + static/        # Jinja2 + hand-written CSS + a little vanilla JS — no build step
├── reports/                     # generated PDF/JSON/CSV land here
├── data/                        # threatmodel.db lives here
│
├── demo_app/                    # intentionally vulnerable Flask app (optional practice target)
│   ├── app.py
│   └── openapi.yaml
│
└── tests/
```

## What's implemented

- **Fixed deterministic pipeline** (`pipeline/security_analysis_pipeline.py`)
  with a genuine, bounded retry policy for invalid-test regeneration — not
  an autonomous decision loop.
- **Provider-agnostic LLM client** (OpenAI / Azure OpenAI / Ollama /
  Anthropic / offline mock) with vision support for the diagram-upload
  input path — swap providers via one `.env` line, zero code changes.
- **RAG grounding**: threats never assert an OWASP/CWE/MITRE mapping the
  knowledge base didn't actually retrieve. If the vector store isn't
  installed, the UI says so explicitly ("RAG knowledge retrieval
  unavailable") rather than silently pretending RAG was used. A dedicated
  **RAG Source Explorer** page lets you browse/search the corpus and see
  exactly which threats cite each document.
- **Five system-input methods**: manual sample data, OpenAPI file
  upload/paste (with a real validation summary — actual parsed
  version/endpoint/schema/auth counts, never hard-coded), architecture-text
  upload/paste, source-code `.zip` upload (deterministic static scan — no
  LLM call, no code execution), and architecture-diagram image upload
  (requires a vision-capable LLM provider).
- **Rule-Based Validation** is fully deterministic (no LLM call) — checks
  endpoint presence, valid HTTP method, duplicate detection, and flags
  destructive-method tests for review.
- **Controlled Test Execution Engine**: hard-enforces an authorization
  gate + target allowlist (re-checked before *every single request*, not
  once per test), rate limiting, request caps, and only ever runs the safe
  test categories (authorization/authentication/input-validation/config
  checks) — there's no generic "run arbitrary payload" capability.
- **Remediation to Re-test workflow**: statuses are Open, In Remediation,
  Fixed, Accepted Risk, False Positive, Retest Required. Re-testing re-runs
  the exact same controlled test; a PASS marks it Fixed and captures a
  genuine before/after risk-reduction percentage. Risk scoring is based
  on each test's most recent execution, not "was it ever FAILED."
- **Threat-to-Test Traceability page**: the full Asset -> Threat -> STRIDE
  -> Attack Scenario -> Security Test -> Execution -> Evidence ->
  Remediation -> Risk chain, one row per test, every cell linking to its
  detail page.
- **Security Analysis Pipeline page**: real-time status per pipeline stage
  (Pending / Processing / Completed / Failed) and a Pipeline Activity Log —
  both read directly from the `pipeline_step_runs` table, not simulated.
- **Security Posture Score** (0-100) and **Test Coverage** metrics —
  calculated transparently from real data and explicitly labeled as a
  project-defined analytical score, not an industry certification.
- **User authentication and RBAC**: password hashing (Werkzeug PBKDF2),
  session-based login, per-account lockout after 5 failed attempts, USER
  and ADMIN roles enforced server-side on every route (a regular user
  hitting an admin URL directly gets a real 403, not a hidden link), and
  an always-visible Authorized Testing Indicator in the top bar showing
  whether the active project can run controlled tests right now.
- **Reports**: PDF (properly wrapped text, no overflow, page-numbered
  footer), JSON, and CSV — all generated from real database data.
- **Security hardening**: IDOR protection on every threat/test route, CSRF
  protection (Flask-WTF) on all state-changing forms, server-side upload
  size/type/content validation, hardened ZIP extraction (canonical-path
  traversal check + pre-extraction resource limits), and real image
  content validation via Pillow.
- **Demo app** (`demo_app/`): a small intentionally vulnerable Flask app
  with 6 seeded flaws — a safe, optional practice target, entirely separate
  from your own real system.

## Quickstart

**Windows:**
```powershell
.\scripts\setup-windows.ps1     # one-time
.\scripts\start-windows.ps1     # launches the platform
.\scripts\start-demo-app.ps1    # OPTIONAL, separate window: the vulnerable practice target
```

**macOS/Linux:**
```bash
bash scripts/setup.sh
bash scripts/start.sh
```

Then open **http://localhost:5000/**. Verify with:
```bash
python scripts/healthcheck.py
```

## Enabling real RAG vector search (optional)

By default RAG retrieval returns no context (threats generate normally,
just without OWASP/CWE/MITRE citations, and the UI honestly says
retrieval is unavailable). To enable real semantic search:
```bash
pip install chromadb sentence-transformers
```
That's the only step needed — the app automatically indexes the
OWASP/CWE/MITRE knowledge base into the vector store at startup (you'll
see `RAG knowledge base ready: N chunks indexed.` printed in the
terminal). No separate ingestion command required.

## Enabling diagram/architecture-image input (optional)

Requires a vision-capable LLM provider — `TM_LLM_PROVIDER=mock` cannot see
images. Set in `.env`:
```
TM_LLM_PROVIDER=anthropic
TM_LLM_MODEL=claude-sonnet-4-5
TM_LLM_API_KEY=sk-ant-...
```

## Demo walkthrough

1. Open http://localhost:5000/ — you'll land on **Sign In**. First run? Use
   the default admin: `admin` / `admin` (change
   this password immediately), or click **Create an account** to register
   a standard USER account.
2. Go to **Settings**, create a project, submit the authorization statement
   with your target's host in the allowlist (e.g. `localhost`). Watch the
   Authorized Testing Indicator in the top bar switch from amber to green.
3. Pick an input method and run the pipeline (or use the built-in manual
   sample data first, to see the flow before using real inputs).
4. Check **Dashboard**, **Asset Discovery**, **Security Pipeline** (live
   stage status + activity log), **Threat Modeling** -> a **Threat Detail**
   page. Note the separate **Retrieved Knowledge** (factual RAG citations)
   and **AI Analysis** (generated reasoning) panels. Approve -> execute a
   test; if it fails, log a remediation and re-test to see the before/after
   risk reduction.
5. Check **Knowledge Base** to browse the RAG corpus, and **Traceability**
   for the full click-through chain.
6. Download a report from **Reports**.
7. If you're an admin, check **User Management** (via the profile menu,
   top right) to see every registered account and its role.

## Safety design, enforced in code

- No test executes unless: `validation_status == VALID` AND `approved ==
  True` AND `project.authorized_for_active_testing == True` AND the target
  host is on the project's explicit allowlist (or is loopback/localhost).
- The allowlist check runs again before every single HTTP request inside
  a test, not once per test.
- Requests per test are capped, rate-limited, and time-boxed.
- Every threat/test route (approve, execute, remediate, mark-status,
  retest) verifies the test actually belongs to the supplied threat before
  acting -- cross-threat access returns 404, not silent success.
- All state-changing POST forms are CSRF-protected.
- Every upload path enforces server-side size limits, extension checks,
  and content validation (ZIP path-traversal + resource limits, real image
  decoding, OpenAPI parsing) -- the browser's `accept` attribute is a UX
  hint, never trusted as a security control.

## Running tests

```bash
pytest tests/ -v
```

`tests/test_pipeline_smoke.py` covers the full pipeline end-to-end (system
analysis -> risk analysis) with zero API keys and the risk-scoring
regression (a verified fix must lower the score). `tests/test_security.py`
covers IDOR protection, CSRF enforcement, and upload/authorization
hardening. `tests/test_auth.py` covers registration, login/logout,
generic error messages, account lockout, and RBAC enforcement (a regular
user genuinely cannot reach an admin route). 26 tests total, 0 warnings.

## Not yet built

- Password reset / "forgot password" flow (accounts are recoverable only
  via an administrator in this build)
- Full multi-tenant project isolation (any logged-in user can currently
  open any project via its cookie-tracked ID; RBAC governs *administrative
  functions*, not per-project ownership boundaries)
- Evaluation module (precision/recall harness against the demo app's
  seeded vulnerabilities)
- OWASP ZAP integration option for the execution engine
