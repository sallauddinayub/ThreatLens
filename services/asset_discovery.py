from __future__ import annotations

from typing import Any

from services.base import BaseSecurityStep
from database.models import Asset, AssetType, DataFlow, ProjectStage, TrustBoundary

_TYPE_MAP = {t.value.lower(): t for t in AssetType}


def _coerce_asset_type(raw: str) -> AssetType:
    if not raw:
        return AssetType.WEB_APPLICATION
    key = raw.strip().lower()
    if key in _TYPE_MAP:
        return _TYPE_MAP[key]
    # loose keyword matching so LLM synonyms ("db", "backend api") still resolve
    if "db" in key or "database" in key or "storage" in key and "cloud" not in key:
        return AssetType.DATABASE
    if "auth" in key:
        return AssetType.AUTH_SERVICE
    if "payment" in key or "billing" in key:
        return AssetType.PAYMENT_SERVICE
    if "admin" in key:
        return AssetType.ADMIN
    if "external" in key:
        return AssetType.EXTERNAL_API
    if "monitor" in key or "logging" in key:
        return AssetType.MONITORING_SERVICE
    if "cloud" in key:
        return AssetType.CLOUD_SERVICE
    if "api" in key:
        return AssetType.API
    if "user" in key:
        return AssetType.USER
    return AssetType.WEB_APPLICATION


class AssetDiscoveryService(BaseSecurityStep):
    """
    Builds the persisted asset graph (Section 6/7) from the System Analysis
    Service's output. Deterministic by design — asset cataloguing doesn't need
    LLM creativity, just faithful conversion of the extracted model into
    graph nodes/edges with stable IDs the UI can render.
    """

    name = "Asset Discovery"
    stage = ProjectStage.ASSET_DISCOVERY

    def run(self, project_id: str, context: dict[str, Any]) -> dict[str, Any]:
        system_model: dict = context["system_model"]

        name_to_asset: dict[str, Asset] = {}

        for a in system_model.get("assets", []):
            asset = Asset(
                project_id=project_id,
                name=a.get("name", "Unnamed Asset"),
                asset_type=_coerce_asset_type(a.get("asset_type", "")),
                technology=a.get("technology"),
                criticality=a.get("criticality", "Medium"),
                trust_zone=a.get("trust_zone"),
                sensitive_data=a.get("sensitive_data", []),
            )
            self.db.add(asset)
            name_to_asset[asset.name] = asset

        # users, services, databases from the model become assets too if not already captured
        for u in system_model.get("users", []):
            nm = u.get("name", "User")
            if nm not in name_to_asset:
                asset = Asset(project_id=project_id, name=nm, asset_type=AssetType.USER, criticality="Low")
                self.db.add(asset)
                name_to_asset[nm] = asset

        for s in system_model.get("services", []):
            nm = s.get("name", "Service")
            if nm not in name_to_asset:
                asset = Asset(project_id=project_id, name=nm, asset_type=AssetType.API,
                               technology=s.get("technology"), criticality="High")
                self.db.add(asset)
                name_to_asset[nm] = asset

        for d in system_model.get("databases", []):
            nm = d.get("name", "Database")
            if nm not in name_to_asset:
                asset = Asset(project_id=project_id, name=nm, asset_type=AssetType.DATABASE,
                               technology=d.get("technology"), criticality="Critical")
                self.db.add(asset)
                name_to_asset[nm] = asset

        for e in system_model.get("external_entities", []):
            nm = e.get("name", "External Entity")
            if nm not in name_to_asset:
                asset = Asset(project_id=project_id, name=nm, asset_type=AssetType.EXTERNAL_API, criticality="Medium")
                self.db.add(asset)
                name_to_asset[nm] = asset

        self.db.flush()  # get IDs before wiring connections/data flows

        for tb in system_model.get("trust_boundaries", []):
            asset_ids = [name_to_asset[n].id for n in tb.get("assets", []) if n in name_to_asset]
            self.db.add(TrustBoundary(
                project_id=project_id,
                name=tb.get("name", "Trust Boundary"),
                description=tb.get("description"),
                asset_ids=asset_ids,
            ))

        for df in system_model.get("data_flows", []):
            src = name_to_asset.get(df.get("source"))
            dst = name_to_asset.get(df.get("destination"))
            crosses = bool(src and dst and src.trust_zone != dst.trust_zone)
            self.db.add(DataFlow(
                project_id=project_id,
                source_asset_id=src.id if src else None,
                destination_asset_id=dst.id if dst else None,
                description=df.get("description"),
                protocol=df.get("protocol"),
                data_classification=df.get("data_classification"),
                crosses_trust_boundary=crosses,
            ))
            if src and dst:
                src.connections = list(set((src.connections or []) + [dst.id]))

        self.db.commit()

        return {
            "asset_ids": {name: a.id for name, a in name_to_asset.items()},
            "_summary": {"assets_created": len(name_to_asset)},
            "_reasoning": "Asset graph built deterministically from the System Analysis Service's structured output; "
                          "no LLM inference used at this stage.",
        }
