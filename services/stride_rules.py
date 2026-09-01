"""
Deterministic STRIDE-per-asset-type rule library (Section 8/25 -
"deterministic security rules" alongside LLM reasoning).

This is the well-known "STRIDE-per-element" pattern: certain asset types are
characteristically exposed to certain STRIDE categories. It is used two ways:
  1. As a fallback so the platform produces a real, non-empty threat model
     even with zero LLM calls (mock/offline mode, CI, grading).
  2. As a candidate list the LLM-backed ThreatModelingService is asked to
     confirm, refine, or discard for the *specific* system at hand — so the
     LLM is doing judgment/prioritization, not conjuring categories from
     nothing.
"""
from __future__ import annotations

from dataclasses import dataclass

from database.models import AssetType, STRIDECategory


@dataclass
class ThreatRule:
    stride: STRIDECategory
    title: str
    description: str
    likelihood: str
    impact: str
    mitigation: str
    rag_query: str  # what to search the knowledge base for


RULES_BY_ASSET_TYPE: dict[AssetType, list[ThreatRule]] = {
    AssetType.API: [
        ThreatRule(
            STRIDECategory.SPOOFING, "Weak or Missing API Authentication",
            "The API may accept requests without robustly verifying caller identity, allowing an "
            "attacker to impersonate a legitimate user or service.",
            "Medium", "High",
            "Require signed, short-lived tokens on every endpoint and reject unauthenticated requests by default.",
            "broken authentication API",
        ),
        ThreatRule(
            STRIDECategory.ELEVATION_OF_PRIVILEGE, "Broken Object/Function Level Authorization",
            "An authenticated user may be able to access another user's resources or invoke "
            "administrative functions by manipulating identifiers or calling routes directly.",
            "High", "High",
            "Enforce server-side, deny-by-default authorization checks scoped to both the object and the function for every request.",
            "unauthorized access to another user's data or administrative functions due to missing object and function level authorization checks",
        ),
        ThreatRule(
            STRIDECategory.TAMPERING, "Mass Assignment on Object Properties",
            "The API may bind client-supplied JSON directly to internal models, allowing an attacker "
            "to set fields (e.g. role, balance) they should not control.",
            "Medium", "High",
            "Allowlist writable properties per role instead of binding arbitrary request bodies to internal models.",
            "broken object property level authorization mass assignment",
        ),
        ThreatRule(
            STRIDECategory.DENIAL_OF_SERVICE, "Unrestricted Resource Consumption",
            "Without rate limiting, pagination caps, or payload size limits, an attacker can exhaust "
            "server or database resources.",
            "Medium", "Medium",
            "Apply per-client rate limits, request size caps, and query timeouts at the gateway.",
            "unrestricted resource consumption rate limiting",
        ),
        ThreatRule(
            STRIDECategory.INFORMATION_DISCLOSURE, "Verbose Errors or Misconfiguration",
            "Default error handlers or debug configurations may leak stack traces, internal paths, "
            "or existence information about resources.",
            "Medium", "Medium",
            "Disable verbose error output in production and return uniform error responses.",
            "security misconfiguration verbose error",
        ),
    ],
    AssetType.AUTH_SERVICE: [
        ThreatRule(
            STRIDECategory.SPOOFING, "Credential Stuffing / Brute Force",
            "Without lockouts or rate limiting on login, an attacker can attempt large volumes of "
            "credential guesses.",
            "High", "High",
            "Implement progressive lockouts, CAPTCHA, and rate limiting on authentication endpoints.",
            "broken authentication credential stuffing",
        ),
        ThreatRule(
            STRIDECategory.REPUDIATION, "Insufficient Authentication Logging",
            "Login and token-issuance events may not be logged with enough detail to reconstruct who "
            "authenticated as whom, hindering incident response.",
            "Low", "Medium",
            "Log authentication events with timestamp, source, outcome, and correlate with a request ID.",
            "audit logging authentication",
        ),
    ],
    AssetType.DATABASE: [
        ThreatRule(
            STRIDECategory.TAMPERING, "SQL/NoSQL Injection via Upstream API",
            "If the API layer does not parameterize queries, an attacker may be able to inject query "
            "syntax that alters the intended database operation.",
            "Medium", "Critical",
            "Use parameterized queries/ORMs exclusively and validate input types before query construction.",
            "sql injection improper neutralization",
        ),
        ThreatRule(
            STRIDECategory.INFORMATION_DISCLOSURE, "Overly Broad Database Access",
            "A compromised application credential with excessive database privileges could expose far "
            "more data than the application itself ever needs to touch.",
            "Low", "Critical",
            "Apply least-privilege database roles scoped to only the tables/operations each service needs.",
            "least privilege access control",
        ),
    ],
    AssetType.PAYMENT_SERVICE: [
        ThreatRule(
            STRIDECategory.TAMPERING, "Price/Amount Tampering",
            "If payment amount or currency is trusted from client input rather than recomputed "
            "server-side, an attacker could alter the charged amount.",
            "Medium", "Critical",
            "Always recompute chargeable amounts server-side from authoritative order data.",
            "business logic tampering payment",
        ),
        ThreatRule(
            STRIDECategory.REPUDIATION, "Missing Transaction Audit Trail",
            "Without immutable transaction logging, disputes about whether a payment or refund "
            "occurred cannot be resolved.",
            "Low", "High",
            "Maintain append-only, tamper-evident transaction logs.",
            "audit logging transaction integrity",
        ),
    ],
    AssetType.WEB_APPLICATION: [
        ThreatRule(
            STRIDECategory.INFORMATION_DISCLOSURE, "Sensitive Data Exposure in Client Responses",
            "Responses to the browser may include more fields than the UI needs, exposing internal "
            "or other-users' data to inspection.",
            "Medium", "Medium",
            "Return only the fields the current view requires (DTO/response shaping) instead of full internal objects.",
            "excessive data exposure API response object properties over-fetching",
        ),
        ThreatRule(
            STRIDECategory.SPOOFING, "Session Fixation / Insufficient Session Expiry",
            "Long-lived or predictable session identifiers increase the window an attacker has to "
            "reuse a stolen session.",
            "Low", "Medium",
            "Rotate session identifiers on privilege change and enforce a bounded session lifetime.",
            "session expiration session fixation",
        ),
    ],
    AssetType.EXTERNAL_API: [
        ThreatRule(
            STRIDECategory.TAMPERING, "Server-Side Request Forgery via External Integration",
            "If the application fetches a URL supplied through an external integration without "
            "validating the destination, an attacker may redirect the request to internal infrastructure.",
            "Low", "High",
            "Allowlist destination hosts/schemes for any server-initiated outbound request.",
            "server side request forgery",
        ),
    ],
    AssetType.STORAGE: [
        ThreatRule(
            STRIDECategory.INFORMATION_DISCLOSURE, "Misconfigured Object Storage Permissions",
            "Storage buckets/objects configured with overly permissive access policies may be readable "
            "by unintended parties.",
            "Medium", "High",
            "Apply least-privilege bucket policies and default-deny public access.",
            "security misconfiguration access control storage",
        ),
    ],
}

DEFAULT_RULES: list[ThreatRule] = [
    ThreatRule(
        STRIDECategory.ELEVATION_OF_PRIVILEGE, "Missing Authorization Check",
        "This asset's access-control enforcement could not be confirmed from the supplied input; "
        "treat as a candidate authorization gap pending review.",
        "Medium", "Medium",
        "Confirm an explicit, server-side authorization check exists for every operation on this asset.",
        "improper access control",
    ),
]
