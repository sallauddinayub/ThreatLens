from __future__ import annotations

from typing import Any

from services.base import BaseSecurityStep
from ai.prompts import THREAT_MODELING_REFINEMENT_PROMPT
from services.stride_rules import DEFAULT_RULES, RULES_BY_ASSET_TYPE, ThreatRule
from database.models import Asset, ProjectStage, Threat
from rag.retriever import SecurityKnowledgeRetriever

class ThreatModelingService(BaseSecurityStep):
    name = "Threat Modeling"
    stage = ProjectStage.THREAT_MODELING

    def __init__(self, db, llm=None, retriever: SecurityKnowledgeRetriever | None = None):
        super().__init__(db, llm)
        self.retriever = retriever or SecurityKnowledgeRetriever()

    def run(self, project_id: str, context: dict[str, Any]) -> dict[str, Any]:
        assets: list[Asset] = self.db.query(Asset).filter(Asset.project_id == project_id).all()
        created_threats: list[Threat] = []
        counter = 1

        for asset in assets:
            candidate_rules = RULES_BY_ASSET_TYPE.get(asset.asset_type, DEFAULT_RULES)

            if self.llm.settings.llm_provider == "mock":
                threats_data = self._deterministic(asset, candidate_rules)
            else:
                threats_data = self._llm_refined(asset, candidate_rules)

            for t in threats_data:
                display_id = f"TH-{counter:03d}"
                counter += 1
                threat = Threat(
                    project_id=project_id,
                    display_id=display_id,
                    title=t["title"],
                    description=t["description"],
                    affected_asset_id=asset.id,
                    stride_category=t["stride_category"],
                    likelihood=t["likelihood"],
                    impact=t["impact"],
                    confidence=t.get("confidence", 0.6),
                    recommended_mitigation=t.get("recommended_mitigation"),
                    owasp_category=t.get("owasp_category"),
                    cwe_id=t.get("cwe_id"),
                    mitre_attack_technique=t.get("mitre_attack_technique"),
                    rag_sources=t.get("rag_sources", []),
                    reasoning_summary=t.get("reasoning_summary"),
                )
                self.db.add(threat)
                created_threats.append(threat)

        self.db.commit()

        return {
            "threat_ids": [t.id for t in created_threats],
            "_summary": {"threats_created": len(created_threats), "assets_analyzed": len(assets)},
            "_reasoning": f"Generated threats for {len(assets)} assets using STRIDE-per-asset-type rules"
                          f"{' refined by LLM against RAG context' if self.llm.settings.llm_provider != 'mock' else ' (deterministic mode)'}.",
        }

    # -- strategies ---------------------------------------------------------

    def _deterministic(self, asset: Asset, rules: list[ThreatRule]) -> list[dict]:
        results = []
        for rule in rules:
            chunks = self.retriever.retrieve(rule.rag_query, k=2)
            sources = [c.to_citation() for c in chunks]
            owasp = next((c.identifier for c in chunks if c.source == "OWASP"), None)
            cwe = next((c.identifier for c in chunks if c.source == "CWE"), None)
            mitre = next((c.identifier for c in chunks if c.source == "MITRE ATT&CK"), None)
            results.append({
                "title": f"{rule.title} - {asset.name}",
                "description": f"{rule.description} (Asset: {asset.name}, type: {asset.asset_type.value}, "
                                f"criticality: {asset.criticality}.)",
                "stride_category": rule.stride,
                "likelihood": rule.likelihood,
                "impact": rule.impact,
                "confidence": 0.55,  # rule-based, not system-specific confirmation
                "recommended_mitigation": rule.mitigation,
                "owasp_category": owasp,
                "cwe_id": cwe,
                "mitre_attack_technique": mitre,
                "rag_sources": sources,
                "reasoning_summary": (
                    f"Applied deterministic STRIDE-per-asset-type rule for asset type "
                    f"'{asset.asset_type.value}'. This rule fires for this category regardless of the "
                    f"specific system; run with an LLM provider configured for system-specific refinement."
                ),
            })
        return results

    def _llm_refined(self, asset: Asset, rules: list[ThreatRule]) -> list[dict]:
        candidates = [
            {
                "title": r.title, "description": r.description, "stride_category": r.stride.value,
                "likelihood": r.likelihood, "impact": r.impact, "mitigation": r.mitigation,
            }
            for r in rules
        ]
        chunks = []
        for r in rules:
            chunks.extend(self.retriever.retrieve(r.rag_query, k=2))
        context_block = self.retriever.format_context(chunks)

        user_prompt = (
            f"ASSET:\nname={asset.name}\ntype={asset.asset_type.value}\n"
            f"technology={asset.technology}\ncriticality={asset.criticality}\ntrust_zone={asset.trust_zone}\n\n"
            f"CANDIDATE_THREATS:\n{candidates}\n\nRETRIEVED_CONTEXT:\n{context_block}"
        )
        resp = self.llm.complete(THREAT_MODELING_REFINEMENT_PROMPT, user_prompt)
        data = resp.json()
        out = []
        for t in data.get("threats", []):
            out.append({**t, "rag_sources": [c.to_citation() for c in chunks]})
        return out
