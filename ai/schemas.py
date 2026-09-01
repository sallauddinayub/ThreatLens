"""
Lightweight schema documentation + validation for the structured JSON
objects that pass between agents. Deliberately not a heavyweight pydantic
model layer — the goal here is a real, cheap sanity check that catches an
LLM (or a hand-edited JSON textarea on the diagram/source-code review step)
returning a malformed system model BEFORE it's persisted to the database
and silently produces zero assets/threats downstream.
"""
from __future__ import annotations

VALID_ASSET_TYPES = {
    "User", "Admin", "Web Application", "API", "Authentication Service",
    "Database", "Payment Service", "External API", "Cloud Service",
    "Monitoring Service", "Storage",
}

SYSTEM_MODEL_TOP_LEVEL_KEYS = {
    "assets", "users", "services", "databases", "external_entities",
    "trust_boundaries", "data_flows", "authentication",
}


def validate_system_model(model: dict) -> list[str]:
    """
    Returns a list of human-readable problems found in a system-model dict.
    An empty list means the model is structurally usable (not that it's
    semantically correct — that's what human review of the extracted model
    is for, on the diagram/source-code input paths).
    """
    errors: list[str] = []

    if not isinstance(model, dict):
        return ["Top-level system model must be a JSON object."]

    unknown_keys = set(model.keys()) - SYSTEM_MODEL_TOP_LEVEL_KEYS
    if unknown_keys:
        errors.append(f"Unrecognized top-level keys will be ignored: {', '.join(sorted(unknown_keys))}")

    for list_key in ("assets", "users", "services", "databases", "external_entities",
                      "trust_boundaries", "data_flows", "authentication"):
        if list_key in model and not isinstance(model[list_key], list):
            errors.append(f"'{list_key}' must be a list, got {type(model[list_key]).__name__}.")

    for i, asset in enumerate(model.get("assets") or []):
        if not isinstance(asset, dict):
            errors.append(f"assets[{i}] must be an object.")
            continue
        if not asset.get("name"):
            errors.append(f"assets[{i}] is missing a 'name'.")
        asset_type = asset.get("asset_type")
        if asset_type and asset_type not in VALID_ASSET_TYPES:
            errors.append(
                f"assets[{i}].asset_type '{asset_type}' is not a recognized type "
                f"(will be treated as 'Web Application'). Valid types: {', '.join(sorted(VALID_ASSET_TYPES))}"
            )

    for i, flow in enumerate(model.get("data_flows") or []):
        if not isinstance(flow, dict):
            errors.append(f"data_flows[{i}] must be an object.")
            continue
        if not flow.get("source") or not flow.get("destination"):
            errors.append(f"data_flows[{i}] is missing 'source' or 'destination'.")

    if not model.get("assets"):
        errors.append("No assets were extracted — the threat model will be empty. Consider adding assets manually.")

    return errors
