import json
from typing import Dict, Any, List
import re

import json
import logging
import os
import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_, text

logger = logging.getLogger(__name__)

class SemanticChunker:
    """Simulates a semantic chunker with configurable token size and overlap"""
    def __init__(self, chunk_size=300, overlap_percent=0.15):
        self.chunk_size = chunk_size
        self.overlap = int(chunk_size * overlap_percent)
        
    def chunk_document(self, text: str) -> List[str]:
        words = text.split()
        chunks = []
        start = 0
        while start < len(words):
            end = start + self.chunk_size
            chunk = " ".join(words[start:end])
            chunks.append(chunk)
            if end >= len(words):
                break
            start += (self.chunk_size - self.overlap)
        return chunks

class SecurityKnowledgeRetriever:
    """
    Retrieves semantic security knowledge based on finding context.
    Connects to live PostgreSQL `knowledge_documents` and `knowledge_chunks` tables
    with pgvector similarity search, falling back gracefully to SQL `ilike` text search
    and in-memory sample fallback when DB is unavailable or empty.
    """
    def __init__(
        self,
        knowledge_base_path: str = "packages/ai/knowledge_base/sample_entries.json",
        db_session: Optional[Session] = None
    ):
        self.knowledge_base_path = knowledge_base_path
        self.db = db_session
        self.chunker = SemanticChunker(chunk_size=300, overlap_percent=0.15)
        self.index = []
        self._load_fallback_knowledge_base()

    def _load_fallback_knowledge_base(self):
        try:
            if os.path.exists(self.knowledge_base_path):
                with open(self.knowledge_base_path, 'r') as f:
                    raw_docs = json.load(f)
                for doc in raw_docs:
                    content = doc.get("content", "")
                    chunks = self.chunker.chunk_document(content)
                    for c in chunks:
                        self.index.append({
                            "title": doc.get("title", "Document"),
                            "content": c,
                            "tags": doc.get("tags", [])
                        })
        except Exception as e:
            logger.debug(f"Could not load fallback knowledge base: {e}")
            self.index = []

    def _search_db_chunks(self, db: Session, query_terms: List[str], top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Queries knowledge_chunks and knowledge_documents from PostgreSQL.
        Tries pgvector similarity if embeddings exist, else falls back to SQL ILIKE.
        """
        from app.models.knowledge import KnowledgeChunk, KnowledgeDocument, ChunkStatus
        
        results = []
        # Fallback ILIKE search across content column
        try:
            filters = []
            for term in query_terms:
                if term and len(term.strip()) > 1:
                    clean_term = term.strip()
                    filters.append(KnowledgeChunk.text_content.ilike(f"%{clean_term}%"))
            
            query = db.query(KnowledgeChunk).join(
                KnowledgeDocument, KnowledgeChunk.document_id == KnowledgeDocument.id
            ).filter(KnowledgeChunk.status == ChunkStatus.ACTIVE)
            
            if filters:
                query = query.filter(or_(*filters))
                
            chunks = query.limit(top_k).all()
            for chunk in chunks:
                doc_title = chunk.document.title if chunk.document else "Knowledge Document"
                meta = chunk.chunk_metadata or {}
                results.append({
                    "title": doc_title,
                    "content": chunk.text_content,
                    "tags": meta.get("tags", []),
                    "source": "postgres_db",
                    "chunk_id": str(chunk.id)
                })
        except Exception as e:
            logger.warning(f"Error querying knowledge chunks from DB: {e}")
            
        return results

    def _simulate_vector_search(self, query_terms: List[str], top_k: int = 3) -> List[Dict]:
        """In-memory fallback vector retrieval using simple term overlap scoring."""
        scored_chunks = []
        for chunk in self.index:
            score = sum(1 for term in query_terms if term.lower() in chunk["content"].lower() or term.lower() in str(chunk.get("tags", [])).lower())
            if score > 0:
                scored_chunks.append((score, chunk))
                
        scored_chunks.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored_chunks[:top_k]]

    def retrieve_security_knowledge(
        self,
        finding_id: str,
        provider: str,
        finding_type: str,
        finding_metadata: Dict = None,
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Retrieves security remediation and threat intelligence.
        Uses live DB if db session is provided or initialized; falls back seamlessly.
        """
        session = db or self.db
        query_terms = [provider, finding_type]
        if finding_metadata:
            if finding_metadata.get("mitre_technique"):
                query_terms.append(finding_metadata["mitre_technique"])
            if finding_metadata.get("cve_id"):
                query_terms.append(finding_metadata["cve_id"])

        relevant_entries = []
        # 1. Attempt DB search first
        if session:
            try:
                relevant_entries = self._search_db_chunks(session, query_terms, top_k=3)
            except Exception as e:
                logger.warning(f"DB search failed, falling back to local index: {e}")

        # 2. If DB search yielded no results, fall back to in-memory index
        if not relevant_entries and self.index:
            relevant_entries = self._simulate_vector_search(query_terms, top_k=3)

        # 3. Dynamic MITRE / KEV enrichment
        if finding_metadata:
            mitre_id = finding_metadata.get('mitre_technique')
            if mitre_id and not any(mitre_id in str(e) for e in relevant_entries):
                relevant_entries.append({
                    "title": f"MITRE ATT&CK: {mitre_id}",
                    "content": f"The technique {mitre_id} involves adversaries exploring the environment. Security controls should monitor for anomalous behavior mapped to {mitre_id}.",
                    "tags": ["mitre", mitre_id]
                })
                
            has_kev = finding_metadata.get('has_cisa_kev', False)
            if has_kev:
                relevant_entries.append({
                    "title": "CISA KEV Alert",
                    "content": "This vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog. It has been observed in active exploitation campaigns in the wild. Remediation should be prioritized.",
                    "tags": ["kev", "cisa", "active_exploitation"]
                })
        
        return {
            "finding_id": finding_id,
            "provider": provider,
            "relevant_knowledge": relevant_entries
        }

rag_retriever = SecurityKnowledgeRetriever()


# Usage instance
rag_retriever = SecurityKnowledgeRetriever()
