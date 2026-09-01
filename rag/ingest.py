"""
Standalone knowledge-base ingestion. Run directly:

    python -m rag.ingest

or import ingest_knowledge_base() from application code (the Flask app
calls this once at startup if the vector store is empty). This is a thin
wrapper — the actual chunking/embedding/upsert logic lives in
SecurityKnowledgeRetriever, since that class already owns the Chroma
collection lifecycle and this script would otherwise just duplicate it.
"""
from __future__ import annotations

import logging

from rag.retriever import SecurityKnowledgeRetriever

logger = logging.getLogger(__name__)


def ingest_knowledge_base() -> int:
    retriever = SecurityKnowledgeRetriever()
    count = retriever.ingest_corpus()
    logger.info("Ingested %s knowledge base chunks.", count)
    return count


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    n = ingest_knowledge_base()
    print(f"Ingested {n} knowledge base chunks.")
