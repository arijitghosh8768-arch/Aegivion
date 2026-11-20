"""Security knowledge retrieval for the Aegivion AI Copilot.

The retriever resolves *why a finding matters* from an approved security
knowledge base. It never invents detections or evidence: findings come from the
detection engines, knowledge comes from ingested documents.

Retrieval order (first non-empty result wins):

1. **pgvector similarity** - cosine distance over ``knowledge_chunks.embedding``
   using the same embedding model that produced the stored vectors.
2. **Lexical PostgreSQL search** - ``ILIKE`` over chunk text, used when no
   embeddings exist or the vector extension is unavailable.
3. **In-memory fallback** - the curated ``sample_entries.json`` knowledge base,
   used when no database session is available.

Tenant isolation
----------------
Every database query is constrained to knowledge the caller may see:

* ``ORGANIZATION`` scoped chunks only when they belong to the caller's org.
* ``GLOBAL`` / ``SYSTEM`` chunks are shared and visible to everyone.

Without an organization id, only shared knowledge is reachable. This prevents
cross-tenant disclosure through the Copilot.
"""

import json
import logging
import os
import re
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

MAX_RETRIEVED_CONTENT_CHARS = 4_000
DEFAULT_TOP_K = 3

# Resolve the curated knowledge base relative to this module so retrieval does
# not depend on the process working directory (it previously came back empty
# whenever the API was started from packages/backend).
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_MODULE_KB_PATH = os.path.join(os.path.dirname(_MODULE_DIR), "knowledge_base", "sample_entries.json")

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    {
        "the", "and", "for", "are", "was", "were", "with", "from", "that", "this",
        "how", "why", "what", "when", "who", "does", "did", "should", "could", "would",
        "can", "you", "your", "not", "but", "its", "into", "over", "they", "have",
        "has", "been", "will", "our", "all", "any", "use", "using", "about",
    }
)


def _tokenize(text: Any) -> set:
    """Lowercase word tokens, dropping stopwords and single characters."""
    return {
        token
        for token in _TOKEN_RE.findall(str(text or "").lower())
        if len(token) > 1 and token not in _STOPWORDS
    }

# Delimiter break-out attempts and instruction-override phrasing. Retrieved
# documents are untrusted input, so these are neutralized before the text ever
# reaches a prompt.
_DELIMITER_TAGS = re.compile(
    r"<\s*/?\s*(?:system|instruction|instructions|prompt|evidence|user_data|untrusted)[^>]*>",
    re.IGNORECASE,
)
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"new\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"\bsystem\s*:", re.IGNORECASE),
    re.compile(r"admin\s+override", re.IGNORECASE),
    re.compile(r"reveal\s+(?:your\s+)?(?:system\s+prompt|instructions)", re.IGNORECASE),
]


def sanitize_untrusted_text(text: Any, max_chars: int = MAX_RETRIEVED_CONTENT_CHARS) -> str:
    """Neutralize control characters, delimiter break-outs and injection phrasing."""
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    text = _CONTROL_CHARS.sub("", text)
    text = _DELIMITER_TAGS.sub("[STRIPPED_TAG]", text)
    for pattern in _INJECTION_PATTERNS:
        text = pattern.sub("[DEFANGED_INSTRUCTION]", text)
    return text[:max_chars].strip()


def _coerce_uuid(value: Any) -> Optional[uuid.UUID]:
    """Best-effort UUID coercion so org ids compare correctly on PostgreSQL."""
    if value is None or isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


class SemanticChunker:
    """Word-window chunker with configurable size and overlap."""

    def __init__(self, chunk_size: int = 300, overlap_percent: float = 0.15):
        self.chunk_size = chunk_size
        self.overlap = int(chunk_size * overlap_percent)

    def chunk_document(self, text: str) -> List[str]:
        words = (text or "").split()
        if not words:
            return []
        chunks: List[str] = []
        start = 0
        while start < len(words):
            end = start + self.chunk_size
            chunks.append(" ".join(words[start:end]))
            if end >= len(words):
                break
            start += self.chunk_size - self.overlap
        return chunks


class SecurityKnowledgeRetriever:
    """Retrieves evidence-grounded security knowledge for a finding."""

    def __init__(
        self,
        knowledge_base_path: str = "packages/ai/knowledge_base/sample_entries.json",
        db_session: Optional[Session] = None,
        embedding_model: str = "bge-small-en-v1.5",
    ):
        self.knowledge_base_path = knowledge_base_path
        self.db = db_session
        self.embedding_model = embedding_model
        self.chunker = SemanticChunker(chunk_size=300, overlap_percent=0.15)
        self.index: List[Dict[str, Any]] = []
        self._embedder: Any = None
        self._embedder_resolved = False
        self._load_fallback_knowledge_base()

    # ------------------------------------------------------------------
    # curated fallback knowledge base
    # ------------------------------------------------------------------
    def _load_fallback_knowledge_base(self) -> None:
        """Load the curated JSON knowledge base.

        Accepts both the ``title``/``content`` schema and the curated
        ``topic``/``context`` schema used by ``sample_entries.json``. Reading a
        single schema previously produced an empty index.
        """
        self.index = []
        if self.knowledge_base_path is None:
            # Explicitly disabled (used when only database knowledge is wanted).
            return
        try:
            path = self.knowledge_base_path
            if not os.path.exists(path) and os.path.exists(_MODULE_KB_PATH):
                path = _MODULE_KB_PATH
            if not os.path.exists(path):
                logger.debug("Knowledge base not found at %s", self.knowledge_base_path)
                return

            with open(path, "r", encoding="utf-8") as handle:
                raw_docs = json.load(handle)

            for doc in raw_docs:
                if not isinstance(doc, dict):
                    continue
                title = doc.get("title") or doc.get("topic") or "Document"
                content = doc.get("content") or doc.get("context") or ""
                # Curated entries carry their remediation guidance separately.
                remediation = doc.get("remediation_terraform")
                if remediation:
                    content = f"{content}\n\nRemediation: {remediation}"

                tags = doc.get("tags")
                if not isinstance(tags, list):
                    tags = []
                if doc.get("resource_type"):
                    tags = list(tags) + [str(doc["resource_type"])]
                if doc.get("id"):
                    tags = list(tags) + [str(doc["id"])]

                for chunk in self.chunker.chunk_document(content):
                    self.index.append(
                        {
                            "title": title,
                            "content": chunk,
                            "tags": [str(tag) for tag in tags],
                            "source_uri": doc.get("source_uri") or f"kb://{doc.get('id', 'unknown')}",
                            "chunk_index": len(self.index),
                        }
                    )
        except Exception as exc:
            logger.warning("Could not load fallback knowledge base: %s", exc)
            self.index = []

    # ------------------------------------------------------------------
    # query embedding
    # ------------------------------------------------------------------
    def _get_embedder(self) -> Any:
        if self._embedder_resolved:
            return self._embedder
        self._embedder_resolved = True
        try:
            from app.services.embedding_service import get_embedding_service

            service = get_embedding_service()
            # Use the vector-space identifier recorded on chunks so vectors from
            # different embedding models are never compared.
            self.embedding_model = getattr(service, "vector_model_id", self.embedding_model)
            self._embedder = service
        except Exception as exc:
            logger.debug("Query embedding unavailable: %s", exc)
            self._embedder = None
        return self._embedder

    def _embed_query(self, query_text: str) -> Optional[List[float]]:
        if not query_text or not query_text.strip():
            return None
        embedder = self._get_embedder()
        if embedder is None:
            return None
        try:
            vectors = embedder.embed_chunks([query_text])
            if not vectors or not vectors[0]:
                return None
            return list(vectors[0])
        except Exception as exc:
            logger.warning("Query embedding failed; skipping vector search: %s", exc)
            return None

    # ------------------------------------------------------------------
    # database retrieval
    # ------------------------------------------------------------------
    @staticmethod
    def _visibility_clause(organization_id: Optional[Any]):
        """Filter expression enforcing tenant isolation at the SQL level."""
        from app.models.knowledge import KnowledgeChunk, KnowledgeScope

        shared = KnowledgeChunk.scope.in_(
            [KnowledgeScope.GLOBAL, KnowledgeScope.SYSTEM]
        )
        org_uuid = _coerce_uuid(organization_id)
        if org_uuid is None:
            return shared
        own_org = and_(
            KnowledgeChunk.scope == KnowledgeScope.ORGANIZATION,
            KnowledgeChunk.organization_id == org_uuid,
        )
        return or_(own_org, shared)

    def build_vector_query(self, db: Session, query_vector: List[float],
                           organization_id: Optional[Any], limit: int):
        """Build the cosine-similarity query (tenant scoped, model matched).

        Exposed separately so the generated SQL can be verified without a live
        pgvector extension.
        """
        from app.models.knowledge import ChunkStatus, KnowledgeChunk, KnowledgeDocument

        distance = KnowledgeChunk.embedding.cosine_distance(query_vector)
        return (
            db.query(KnowledgeChunk, KnowledgeDocument)
            .add_columns(distance.label("distance"))
            .join(KnowledgeDocument, KnowledgeChunk.document_id == KnowledgeDocument.id)
            .filter(KnowledgeChunk.status == ChunkStatus.ACTIVE)
            .filter(KnowledgeChunk.embedding.isnot(None))
            .filter(KnowledgeChunk.embedding_model == self.embedding_model)
            .filter(self._visibility_clause(organization_id))
            .order_by(distance)
            .limit(limit)
        )

    @staticmethod
    def _tags_match(entry_tags: Any, wanted: List[str]) -> bool:
        if not wanted:
            return True
        if not isinstance(entry_tags, list):
            return False
        available = {str(tag).lower() for tag in entry_tags}
        return any(tag.lower() in available for tag in wanted)

    def _search_db_chunks_vector(
        self,
        db: Session,
        query_vector: List[float],
        organization_id: Optional[Any],
        tags: Optional[List[str]],
        top_k: int,
    ) -> Optional[List[Dict[str, Any]]]:
        """Cosine-similarity search. Returns ``None`` when the path is unusable."""
        from app.models.knowledge import ChunkStatus, KnowledgeChunk, KnowledgeDocument

        limit = top_k * 4 if tags else top_k
        try:
            # Savepoint so a failed vector query (e.g. extension unavailable)
            # does not poison the caller's transaction.
            with db.begin_nested():
                rows = self.build_vector_query(
                    db, query_vector, organization_id, limit
                ).all()
        except Exception as exc:
            logger.warning(
                "pgvector search unavailable, falling back to lexical search: %s", exc
            )
            return None

        results: List[Dict[str, Any]] = []
        for chunk, document, distance_value in rows:
            metadata = chunk.chunk_metadata or {}
            if not self._tags_match(metadata.get("tags"), tags or []):
                continue
            results.append(
                {
                    "title": document.title,
                    "content": chunk.text_content,
                    "tags": metadata.get("tags", []),
                    "source": "pgvector",
                    "source_uri": document.source_uri,
                    "authority": getattr(document.authority, "value", str(document.authority)),
                    "chunk_id": str(chunk.id),
                    "chunk_index": chunk.chunk_index,
                    "score": round(1.0 - float(distance_value), 6),
                    "trusted": False,
                }
            )
            if len(results) >= top_k:
                break
        return results

    def _search_db_chunks(
        self,
        db: Session,
        query_terms: List[str],
        top_k: int = DEFAULT_TOP_K,
        organization_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Lexical ``ILIKE`` search, tenant-scoped and metadata filtered."""
        from app.models.knowledge import ChunkStatus, KnowledgeChunk, KnowledgeDocument

        filters = [
            KnowledgeChunk.text_content.ilike(f"%{term.strip()}%")
            for term in query_terms
            if term and len(term.strip()) > 1
        ]
        if not filters:
            return []

        limit = top_k * 4 if tags else top_k
        try:
            with db.begin_nested():
                rows = (
                    db.query(KnowledgeChunk, KnowledgeDocument)
                    .join(KnowledgeDocument, KnowledgeChunk.document_id == KnowledgeDocument.id)
                    .filter(KnowledgeChunk.status == ChunkStatus.ACTIVE)
                    .filter(self._visibility_clause(organization_id))
                    .filter(or_(*filters))
                    .limit(limit)
                    .all()
                )
        except Exception as exc:
            logger.warning("Error querying knowledge chunks from DB: %s", exc)
            return []

        results: List[Dict[str, Any]] = []
        for chunk, document in rows:
            metadata = chunk.chunk_metadata or {}
            if not self._tags_match(metadata.get("tags"), tags or []):
                continue
            results.append(
                {
                    "title": document.title,
                    "content": chunk.text_content,
                    "tags": metadata.get("tags", []),
                    "source": "postgres_db",
                    "source_uri": document.source_uri,
                    "authority": getattr(document.authority, "value", str(document.authority)),
                    "chunk_id": str(chunk.id),
                    "chunk_index": chunk.chunk_index,
                    "trusted": False,
                }
            )
            if len(results) >= top_k:
                break
        return results

    # ------------------------------------------------------------------
    # in-memory fallback
    # ------------------------------------------------------------------
    def _simulate_vector_search(
        self, query_terms: List[str], top_k: int = DEFAULT_TOP_K, tags: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Lexical overlap scoring over the curated in-memory knowledge base."""
        query_tokens = _tokenize(" ".join(str(term) for term in query_terms if term))
        if not query_tokens:
            return []

        scored = []
        for chunk in self.index:
            if not self._tags_match(chunk.get("tags"), tags or []):
                continue
            content_tokens = _tokenize(chunk.get("content"))
            tag_tokens = _tokenize(" ".join(map(str, chunk.get("tags", []))))
            overlap = len(query_tokens & (content_tokens | tag_tokens))
            if overlap == 0:
                continue
            # Metadata matches are a strong signal: the curator tagged the doc.
            tag_boost = 0.5 * len(query_tokens & tag_tokens)
            scored.append((overlap + tag_boost, chunk))

        scored.sort(key=lambda item: item[0], reverse=True)
        results: List[Dict[str, Any]] = []
        for score, chunk in scored[:top_k]:
            entry = dict(chunk)
            entry.update({"source": "in_memory_fallback", "score": float(score), "trusted": False})
            results.append(entry)
        return results

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    @staticmethod
    def _build_query_terms(
        provider: str, finding_type: str, finding_metadata: Optional[Dict[str, Any]]
    ) -> List[str]:
        terms: List[str] = []
        for value in (provider, finding_type):
            if value:
                terms.append(str(value))
        if finding_metadata:
            for key in ("mitre_technique", "cve_id"):
                value = finding_metadata.get(key)
                if value:
                    terms.append(str(value))
        return terms

    @staticmethod
    def _build_citations(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        citations = []
        for entry in entries:
            if entry.get("synthesized"):
                continue
            citations.append(
                {
                    "source": entry.get("source", "unknown"),
                    "title": entry.get("title", "Knowledge Document"),
                    "source_uri": entry.get("source_uri"),
                    "chunk_id": entry.get("chunk_id"),
                }
            )
        return citations

    def retrieve_security_knowledge(
        self,
        finding_id: str,
        provider: str,
        finding_type: str,
        finding_metadata: Dict = None,
        db: Optional[Session] = None,
        *,
        organization_id: Optional[Any] = None,
        top_k: int = DEFAULT_TOP_K,
        tags: Optional[List[str]] = None,
        include_synthetic_enrichment: bool = True,
        query_text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieve remediation and threat-context knowledge for a finding.

        Returns a dict with ``relevant_knowledge`` (possibly empty) plus
        ``retrieval_status``, ``retrieval_source`` and ``citations``.
        """
        session = db or self.db
        query_terms = self._build_query_terms(provider, finding_type, finding_metadata)
        # A free-text question (Copilot) must influence the retrieval query;
        # otherwise every chat request searches for the same generic terms.
        if query_text and query_text.strip():
            query_terms.append(query_text.strip())
        query_text = " ".join(query_terms)

        entries: List[Dict[str, Any]] = []
        source = "none"

        if session is not None:
            query_vector = self._embed_query(query_text)
            if query_vector is not None:
                vector_hits = self._search_db_chunks_vector(
                    session, query_vector, organization_id, tags, top_k
                )
                if vector_hits:
                    entries = vector_hits
                    source = "pgvector"
            if not entries:
                lexical_hits = self._search_db_chunks(
                    session, query_terms, top_k=top_k, organization_id=organization_id, tags=tags
                )
                if lexical_hits:
                    entries = lexical_hits
                    source = "postgres_lexical"

        if not entries and self.index:
            fallback_hits = self._simulate_vector_search(query_terms, top_k=top_k, tags=tags)
            if fallback_hits:
                entries = fallback_hits
                source = "in_memory_fallback"

        # Retrieved documents are untrusted: sanitize before they can reach a prompt.
        entries = [
            {
                **entry,
                "content": sanitize_untrusted_text(entry.get("content", "")),
                "title": sanitize_untrusted_text(entry.get("title", "Knowledge Document"), 300),
                "trusted": False,
            }
            for entry in entries
        ]

        if include_synthetic_enrichment and finding_metadata:
            entries.extend(self._synthetic_enrichment(finding_metadata, entries))

        return {
            "finding_id": finding_id,
            "provider": provider,
            "relevant_knowledge": entries,
            "retrieval_status": "ok" if entries else "no_results",
            "retrieval_source": source,
            "citations": self._build_citations(entries),
            "organization_id": str(organization_id) if organization_id else None,
        }

    @staticmethod
    def _synthetic_enrichment(
        finding_metadata: Dict[str, Any], existing: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Framework reference notes derived from finding metadata.

        These are explicitly flagged ``synthesized`` and are excluded from
        citations: they are a pointer to a public framework reference, not a
        retrieved knowledge document, and must never be presented as a source.
        """
        additions: List[Dict[str, Any]] = []

        mitre_id = finding_metadata.get("mitre_technique")
        if mitre_id and not any(mitre_id in str(entry) for entry in existing):
            additions.append(
                {
                    "title": f"MITRE ATT&CK: {mitre_id}",
                    "content": (
                        f"The technique {mitre_id} is a public MITRE ATT&CK reference. "
                        "Consult https://attack.mitre.org for authoritative detection "
                        "and mitigation guidance."
                    ),
                    "tags": ["mitre", mitre_id],
                    "source": "framework_reference",
                    "synthesized": True,
                    "trusted": False,
                }
            )

        if finding_metadata.get("has_cisa_kev"):
            additions.append(
                {
                    "title": "CISA KEV Alert",
                    "content": (
                        "This vulnerability is listed in the CISA Known Exploited "
                        "Vulnerabilities catalog. Consult https://www.cisa.gov/known-exploited-vulnerabilities-catalog "
                        "for the authoritative entry."
                    ),
                    "tags": ["kev", "cisa", "active_exploitation"],
                    "source": "framework_reference",
                    "synthesized": True,
                    "trusted": False,
                }
            )

        return additions


# Single shared retriever instance used by the API layer.
rag_retriever = SecurityKnowledgeRetriever()
