"""
RAG Source Explorer backend.

Deliberately reads the corpus JSON files directly from disk rather than
going through SecurityKnowledgeRetriever/Chroma — that keeps the Explorer
usable even in the lightweight install (no chromadb/sentence-transformers),
since browsing the knowledge base doesn't require vector search, only
listing/filtering/searching plain text. Semantic retrieval for actual
threat-modeling still goes through the vector store when it's installed;
this module is purely for human inspection of what's in the corpus.

Document IDs use the same "{filename}::{index}" scheme as
SecurityKnowledgeRetriever.ingest_corpus so the two stay consistent if
someone cross-references one against the other.
"""
from __future__ import annotations

import glob
import json
import os

from config import get_settings


def _corpus_dir() -> str:
    settings = get_settings()
    # settings.knowledge_base_dir is relative to the backend working directory
    return settings.knowledge_base_dir


def load_all_documents() -> list[dict]:
    """Returns every document in the corpus with a stable id, sorted by source then title."""
    docs = []
    corpus_dir = _corpus_dir()
    if not os.path.isdir(corpus_dir):
        return docs

    for path in sorted(glob.glob(os.path.join(corpus_dir, "*.json"))):
        with open(path, "r", encoding="utf-8") as f:
            entries = json.load(f)
        for i, entry in enumerate(entries):
            docs.append({
                "id": f"{os.path.basename(path)}::{i}",
                "source": entry.get("source", "unknown"),
                "title": entry.get("title", ""),
                "identifier": entry.get("identifier") or None,
                "url": entry.get("url") or None,
                "content": entry.get("content", ""),
            })

    docs.sort(key=lambda d: (d["source"], d["title"]))
    return docs


def get_document(doc_id: str) -> dict | None:
    for doc in load_all_documents():
        if doc["id"] == doc_id:
            return doc
    return None


def filter_documents(docs: list[dict], source: str = "All", query: str = "") -> list[dict]:
    filtered = docs if source == "All" else [d for d in docs if d["source"] == source]
    if query.strip():
        words = query.strip().lower().split()
        filtered = [
            d for d in filtered
            if all(
                w in d["title"].lower() or w in (d["identifier"] or "").lower() or w in d["content"].lower()
                for w in words
            )
        ]
    return filtered


def find_citing_threats(threats: list, doc: dict) -> list:
    """
    Cross-references a knowledge-base document against a project's threats.
    Matches on the threat's own owasp_category/cwe_id/mitre_attack_technique
    fields (the mapping actually persisted per Section 21) OR on the
    identifier/title recorded in a threat's rag_sources citation list —
    covers threats generated both with and without an explicit standards
    mapping field populated.
    """
    citing = []
    identifier = (doc.get("identifier") or "").lower()
    title = doc["title"].lower()

    for t in threats:
        direct_fields = [
            (t.owasp_category or "").lower(),
            (t.cwe_id or "").lower(),
            (t.mitre_attack_technique or "").lower(),
        ]
        if identifier and identifier in direct_fields:
            citing.append(t)
            continue

        for src in (t.rag_sources or []):
            src_identifier = (src.get("identifier") or "").lower()
            src_title = (src.get("title") or "").lower()
            if (identifier and src_identifier == identifier) or (src_title == title):
                citing.append(t)
                break

    return citing
