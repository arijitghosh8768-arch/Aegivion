"""Knowledge ingestion for the Aegivion RAG pipeline.

Pipeline::

    Document -> Validation -> Parsing -> Chunking -> Embedding
             -> PostgreSQL/pgvector storage

Design guarantees
-----------------
* **Deterministic identity** - a document is keyed by ``(source_uri,
  organization_id)``, so re-ingesting the same source updates in place instead
  of creating duplicates.
* **Idempotency** - if the parsed content hash is unchanged the ingest is a
  no-op and no chunks are rewritten.
* **Chunk de-duplication** - identical chunk text inside one document is stored
  once, keyed by its SHA-256 content hash.
* **Provenance** - every chunk keeps its parent document (title, ``source_uri``,
  authority, version hash).
* **Safe deletion** - documents are archived (chunks marked ``ARCHIVED``) rather
  than hard-deleted, so retrieval simply stops returning them.
* **Tenant isolation** - ``ORGANIZATION`` scoped documents require an
  ``organization_id``; ``GLOBAL``/``SYSTEM`` documents never carry one.

Storage caveat
--------------
``knowledge_chunks.embedding`` is a ``vector(384)`` column. PostgreSQL must be
able to load the pgvector extension to write that table *at all* - including
writing ``NULL``. If the extension is unavailable the service returns
``IngestionStatus.STORAGE_ERROR`` instead of raising, so callers can degrade to
the lexical retrieval path.

This module is RAG-only; it does not touch scanning, detection or correlation.
"""

from __future__ import annotations

import hashlib
import logging
import re
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

import sqlalchemy
from sqlalchemy.orm import Session

from app.models.knowledge import (
    AuthorityLevel,
    ChunkStatus,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeScope,
)

logger = logging.getLogger(__name__)

EMBEDDING_DIMENSION = 384
DEFAULT_EMBEDDING_MODEL = "bge-small-en-v1.5"

DEFAULT_CHUNK_SIZE = 300
DEFAULT_CHUNK_OVERLAP = 45

MIN_DOCUMENT_CHARS = 20
MAX_DOCUMENT_CHARS = 400_000
MAX_CHUNK_CHARS = 8_000
MAX_TITLE_CHARS = 512
MAX_SOURCE_URI_CHARS = 2_048

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_EXCESS_BLANK_LINES = re.compile(r"\n{3,}")


class IngestionStatus(str, Enum):
    """Outcome of a single ingest attempt."""

    CREATED = "created"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    REJECTED = "rejected"
    STORAGE_ERROR = "storage_error"


@dataclass
class IngestionResult:
    """Structured ingest outcome (never raises for bad input)."""

    status: IngestionStatus
    source_uri: str
    document_id: Optional[str] = None
    chunk_count: int = 0
    embeddings_stored: int = 0
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status in {
            IngestionStatus.CREATED,
            IngestionStatus.UPDATED,
            IngestionStatus.UNCHANGED,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "source_uri": self.source_uri,
            "document_id": self.document_id,
            "chunk_count": self.chunk_count,
            "embeddings_stored": self.embeddings_stored,
            "reason": self.reason,
        }


def normalize_text(text: str) -> str:
    """Normalize document text deterministically before hashing/chunking."""
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_CHARS.sub("", text)
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    # Collapse runs of spaces/tabs so cosmetic differences do not change the
    # content hash (and therefore do not cause spurious re-ingestion).
    text = re.sub(r"[ \t]+", " ", text)
    text = _EXCESS_BLANK_LINES.sub("\n\n", text)
    return text.strip()


def content_fingerprint(text: str) -> str:
    """Stable SHA-256 of normalized text (used for version + chunk hashes)."""
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def _coerce_uuid(value: Any) -> Optional[uuid.UUID]:
    """Coerce to ``uuid.UUID`` so stored and queried org ids always match.

    The ``organization_id`` columns are ``UUID(as_uuid=True)``; storing a plain
    string while comparing against a ``UUID`` object silently fails to match and
    would defeat tenant isolation.
    """
    if value is None or isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def chunk_text(
    text: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_CHUNK_OVERLAP,
) -> List[str]:
    """Split text into overlapping word windows.

    Chunking is deterministic for a given input and parameters so that
    re-ingesting identical content produces identical hashes.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be >= 0 and < chunk_size")

    words = normalize_text(text).split()
    if not words:
        return []

    step = chunk_size - overlap
    chunks: List[str] = []
    start = 0
    while start < len(words):
        window = words[start : start + chunk_size]
        if window:
            chunks.append(" ".join(window)[:MAX_CHUNK_CHARS])
        if start + chunk_size >= len(words):
            break
        start += step
    return chunks


class KnowledgeIngestionService:
    """Validate, chunk, embed and persist security knowledge documents."""

    def __init__(
        self,
        db: Session,
        embedder: Any = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        overlap: int = DEFAULT_CHUNK_OVERLAP,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
        generate_embeddings: bool = True,
    ) -> None:
        self.db = db
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.embedding_model = embedding_model
        self.generate_embeddings = generate_embeddings
        self._embedder = embedder

    # ------------------------------------------------------------------
    # embedder
    # ------------------------------------------------------------------
    def _get_embedder(self) -> Any:
        if not self.generate_embeddings:
            return None
        if self._embedder is not None:
            # Record the vector space of the injected embedder too, otherwise
            # chunks are labelled with the wrong model and never match a query.
            self.embedding_model = getattr(
                self._embedder, "vector_model_id", self.embedding_model
            )
            return self._embedder
        try:
            from app.services.embedding_service import get_embedding_service

            self._embedder = get_embedding_service()
            # Store the vector-space identifier, not the human model name, so
            # retrieval never compares vectors from different models.
            self.embedding_model = getattr(
                self._embedder, "vector_model_id", self.embedding_model
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Embedding service unavailable: %s", exc)
            self._embedder = None
        return self._embedder

    def _embed(self, texts: Sequence[str]) -> List[Optional[List[float]]]:
        """Return one vector per text, or ``None`` where embedding failed."""
        if not texts:
            return []
        embedder = self._get_embedder()
        if embedder is None:
            return [None] * len(texts)
        try:
            vectors = embedder.embed_chunks(list(texts))
        except Exception as exc:
            logger.warning("Embedding generation failed; storing chunks without vectors: %s", exc)
            return [None] * len(texts)

        result: List[Optional[List[float]]] = []
        for index, vector in enumerate(vectors):
            if vector is None or len(vector) != EMBEDDING_DIMENSION:
                logger.warning(
                    "Discarding embedding %s: expected %s dimensions, got %s",
                    index,
                    EMBEDDING_DIMENSION,
                    None if vector is None else len(vector),
                )
                result.append(None)
            else:
                result.append(list(vector))
        return result

    # ------------------------------------------------------------------
    # validation
    # ------------------------------------------------------------------
    def _validate(
        self,
        title: str,
        source_uri: str,
        content: str,
        scope: KnowledgeScope,
        organization_id: Optional[str],
    ) -> List[str]:
        problems: List[str] = []

        if not isinstance(title, str) or not title.strip():
            problems.append("title is required")
        elif len(title.strip()) > MAX_TITLE_CHARS:
            problems.append(f"title exceeds {MAX_TITLE_CHARS} characters")

        if not isinstance(source_uri, str) or not source_uri.strip():
            problems.append("source_uri is required")
        elif len(source_uri.strip()) > MAX_SOURCE_URI_CHARS:
            problems.append(f"source_uri exceeds {MAX_SOURCE_URI_CHARS} characters")

        if not isinstance(content, str):
            problems.append("content must be text")
        else:
            normalized = normalize_text(content)
            if len(normalized) < MIN_DOCUMENT_CHARS:
                problems.append(
                    f"content is too short (minimum {MIN_DOCUMENT_CHARS} characters)"
                )
            elif len(normalized) > MAX_DOCUMENT_CHARS:
                problems.append(
                    f"content exceeds {MAX_DOCUMENT_CHARS} characters"
                )

        if scope == KnowledgeScope.ORGANIZATION:
            if not organization_id:
                problems.append(
                    "organization_id is required for ORGANIZATION scoped documents"
                )
            elif _coerce_uuid(organization_id) is None:
                problems.append("organization_id must be a valid UUID")

        return problems

    # ------------------------------------------------------------------
    # ingestion
    # ------------------------------------------------------------------
    def ingest_document(
        self,
        *,
        title: str,
        source_uri: str,
        content: str,
        scope: KnowledgeScope = KnowledgeScope.GLOBAL,
        authority: AuthorityLevel = AuthorityLevel.VENDOR,
        organization_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[Sequence[str]] = None,
        simulate_pgvector_failure: bool = False,
    ) -> IngestionResult:
        """Validate, chunk and persist one document. Never raises on bad input."""
        source_uri = (source_uri or "").strip() if isinstance(source_uri, str) else ""

        problems = self._validate(title, source_uri, content, scope, organization_id)
        if problems:
            return IngestionResult(
                status=IngestionStatus.REJECTED,
                source_uri=source_uri,
                reason="; ".join(problems),
            )

        # Simulate pgvector failure for testing purposes.
        # When simulate_pgvector_failure is True, the ingestion gracefully
        # returns STORAGE_ERROR so callers can degrade to the lexical retrieval path.
        if simulate_pgvector_failure:
            return IngestionResult(
                status=IngestionStatus.STORAGE_ERROR,
                source_uri=source_uri,
                reason="pgvector vector storage simulated failure; using lexical fallback",
            )

        # GLOBAL / SYSTEM knowledge is shared and must never carry an org id.
        org_id = (
            _coerce_uuid(organization_id)
            if scope == KnowledgeScope.ORGANIZATION
            else None
        )
        normalized = normalize_text(content)
        version_hash = content_fingerprint(normalized)


        try:
            document = (
                self.db.query(KnowledgeDocument)
                .filter(
                    KnowledgeDocument.source_uri == source_uri,
                    KnowledgeDocument.organization_id == org_id,
                )
                .first()
            )

            if document is not None and document.version_hash == version_hash:
                active = (
                    self.db.query(KnowledgeChunk)
                    .filter(
                        KnowledgeChunk.document_id == document.id,
                        KnowledgeChunk.status == ChunkStatus.ACTIVE,
                    )
                    .count()
                )
                return IngestionResult(
                    status=IngestionStatus.UNCHANGED,
                    source_uri=source_uri,
                    document_id=str(document.id),
                    chunk_count=active,
                    reason="content unchanged",
                )

            raw_chunks = chunk_text(normalized, self.chunk_size, self.overlap)
            if not raw_chunks:
                return IngestionResult(
                    status=IngestionStatus.REJECTED,
                    source_uri=source_uri,
                    reason="content produced no chunks",
                )

            # De-duplicate identical chunk text within this document.
            unique: List[str] = []
            seen_hashes = set()
            for text in raw_chunks:
                digest = content_fingerprint(text)
                if digest in seen_hashes:
                    continue
                seen_hashes.add(digest)
                unique.append(text)

            vectors = self._embed(unique)

            chunk_metadata = dict(metadata or {})
            if tags:
                chunk_metadata["tags"] = list(tags)

            status = IngestionStatus.CREATED
            if document is None:
                document = KnowledgeDocument(
                    id=uuid.uuid4(),
                    organization_id=org_id,
                    scope=scope,
                    authority=authority,
                    title=title.strip(),
                    source_uri=source_uri,
                    version_hash=version_hash,
                    metadata_json=dict(metadata or {}),
                )
                self.db.add(document)
                self.db.flush()
            else:
                # Content changed: replace the chunk set wholesale.
                status = IngestionStatus.UPDATED
                document.title = title.strip()
                document.authority = authority
                document.scope = scope
                document.version_hash = version_hash
                document.metadata_json = dict(metadata or {})
                document.updated_at = datetime.now(timezone.utc)
                self.db.query(KnowledgeChunk).filter(
                    KnowledgeChunk.document_id == document.id
                ).delete(synchronize_session=False)

            stored_embeddings = 0
            for index, text in enumerate(unique):
                vector = vectors[index] if index < len(vectors) else None
                if vector is not None:
                    stored_embeddings += 1
                self.db.add(
                    KnowledgeChunk(
                        id=uuid.uuid4(),
                        document_id=document.id,
                        organization_id=org_id,
                        scope=scope,
                        chunk_index=index,
                        text_content=text,
                        content_hash=content_fingerprint(text),
                        embedding=vector,
                        embedding_model=self.embedding_model,
                        token_count=len(text.split()),
                        chunk_metadata=dict(chunk_metadata),
                        status=ChunkStatus.ACTIVE,
                    )
                )

            self.db.commit()

            return IngestionResult(
                status=status,
                source_uri=source_uri,
                document_id=str(document.id),
                chunk_count=len(unique),
                embeddings_stored=stored_embeddings,
            )

        except Exception as exc:
            self.db.rollback()
            logger.warning("Knowledge ingestion failed for %s: %s", source_uri, exc)
            return IngestionResult(
                status=IngestionStatus.STORAGE_ERROR,
                source_uri=source_uri,
                reason=f"{type(exc).__name__}: {exc}",
            )

    def ingest_many(self, documents: Sequence[Dict[str, Any]]) -> List[IngestionResult]:
        """Ingest a batch of ``ingest_document`` keyword dictionaries."""
        return [self.ingest_document(**document) for document in documents]

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def archive_document(
        self, source_uri: str, organization_id: Optional[str] = None
    ) -> int:
        """Soft-delete a document: chunks become ``ARCHIVED`` and stop matching.

        Returns the number of chunks archived. Documents are never hard-deleted
        so provenance survives.
        """
        org_id = _coerce_uuid(organization_id) if organization_id else None
        document = (
            self.db.query(KnowledgeDocument)
            .filter(
                KnowledgeDocument.source_uri == source_uri,
                KnowledgeDocument.organization_id == org_id,
            )
            .first()
        )
        if document is None:
            return 0
        archived = (
            self.db.query(KnowledgeChunk)
            .filter(KnowledgeChunk.document_id == document.id)
            .update(
                {
                    KnowledgeChunk.status: ChunkStatus.ARCHIVED,
                    KnowledgeChunk.updated_at: datetime.now(timezone.utc),
                },
                synchronize_session=False,
            )
        )
        self.db.commit()
        return int(archived or 0)


def ingest_documents(
    db: Session, documents: Sequence[Dict[str, Any]], **service_kwargs: Any
) -> List[IngestionResult]:
    """Convenience wrapper for batch ingestion."""
    return KnowledgeIngestionService(db, **service_kwargs).ingest_many(documents)
