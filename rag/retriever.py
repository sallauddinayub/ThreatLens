"""
RAG pipeline (Section 9):

    Threat Modeling -> Retriever -> Relevant Security Documents -> LLM -> Grounded Threat Analysis

Documents are chunked, embedded, and stored in Chroma. Every retrieval
returns the source document's id/title/url alongside the text so agents can
attach `rag_sources` to a Threat and never assert an OWASP/CWE/MITRE mapping
without a retrieved source backing it.
"""
from __future__ import annotations

import glob
import json
import logging
import os
from dataclasses import dataclass, field

from config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class RetrievedChunk:
    text: str
    title: str
    source: str
    identifier: str | None = None
    url: str | None = None
    score: float = 0.0

    def to_citation(self) -> dict:
        return {
            "title": self.title,
            "source": self.source,
            "identifier": self.identifier,
            "url": self.url,
        }


class SecurityKnowledgeRetriever:
    """Thin wrapper around Chroma so agents don't touch vector-store internals."""

    def __init__(self):
        self.settings = get_settings()
        self._collection = None

    # -- lazy init so `mock`/offline dev doesn't require chromadb installed --
    def _get_collection(self):
        if self._collection is not None:
            return self._collection

        import chromadb
        from chromadb.utils import embedding_functions

        client = chromadb.PersistentClient(path=self.settings.vector_store_dir)

        if self.settings.embedding_provider == "sentence-transformers":
            ef = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=self.settings.embedding_model
            )
        else:
            ef = embedding_functions.OpenAIEmbeddingFunction(
                api_key=self.settings.llm_api_key, model_name="text-embedding-3-small"
            )

        self._collection = client.get_or_create_collection(
            name="security_knowledge_base", embedding_function=ef
        )
        return self._collection

    def ingest_corpus(self, corpus_dir: str | None = None) -> int:
        """
        Load JSON documents from `corpus_dir` (default: settings.knowledge_base_dir).
        Each file is a list of {source, title, identifier, url, content}.
        Returns the number of chunks ingested.
        """
        corpus_dir = corpus_dir or self.settings.knowledge_base_dir
        collection = self._get_collection()

        count = 0
        for path in glob.glob(os.path.join(corpus_dir, "*.json")):
            with open(path, "r", encoding="utf-8") as f:
                docs = json.load(f)
            ids, texts, metadatas = [], [], []
            for i, doc in enumerate(docs):
                doc_id = f"{os.path.basename(path)}::{i}"
                ids.append(doc_id)
                texts.append(doc["content"])
                metadatas.append(
                    {
                        "source": doc.get("source", "unknown"),
                        "title": doc.get("title", ""),
                        "identifier": doc.get("identifier", ""),
                        "url": doc.get("url", ""),
                    }
                )
            if ids:
                collection.upsert(ids=ids, documents=texts, metadatas=metadatas)
                count += len(ids)
        logger.info("Ingested %s knowledge chunks from %s", count, corpus_dir)
        return count

    def retrieve(self, query: str, k: int | None = None) -> list[RetrievedChunk]:
        k = k or self.settings.rag_top_k
        try:
            collection = self._get_collection()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Vector store unavailable (%s); returning no RAG context. "
                            "Threats will be generated WITHOUT standards mapping.", exc)
            return []

        results = collection.query(query_texts=[query], n_results=k)
        chunks: list[RetrievedChunk] = []
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        dists = results.get("distances", [[]])[0] if results.get("distances") else [0.0] * len(docs)
        for text, meta, dist in zip(docs, metas, dists):
            chunks.append(
                RetrievedChunk(
                    text=text,
                    title=meta.get("title", ""),
                    source=meta.get("source", "unknown"),
                    identifier=meta.get("identifier") or None,
                    url=meta.get("url") or None,
                    score=1.0 - dist,
                )
            )
        return chunks

    def format_context(self, chunks: list[RetrievedChunk]) -> str:
        if not chunks:
            return "NO_RETRIEVED_CONTEXT — do not assert any OWASP/CWE/MITRE mapping."
        blocks = []
        for c in chunks:
            header = f"[{c.source}{' ' + c.identifier if c.identifier else ''}] {c.title}"
            blocks.append(f"{header}\n{c.text}")
        return "\n\n---\n\n".join(blocks)
