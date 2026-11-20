"""PostgreSQL/pgvector storage tests for the RAG pipeline.

These run against ``TEST_DATABASE_URL`` - the dedicated ``aegivion_test``
database - and never touch the application or RAG production database.

Isolation strategy
------------------
* Ingestion tests must prove *durability*, so they commit for real and then
  delete exactly the rows they created (matched by a unique ``source_uri``).
* Retrieval tests run inside a test-owned outer transaction using
  ``join_transaction_mode="create_savepoint"``; the outer transaction is rolled
  back, so nothing they write can survive into another test.

The suite is environment-aware: when the pgvector extension cannot execute -
for example when ``vector.dll`` is blocked by a Windows Application Control
policy - the storage tests skip with that exact reason, while the degradation
test asserts that ingestion fails *gracefully* instead of raising.
"""

import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.models.knowledge import (
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeScope,
)
from app.services.embedding_service import HashingEmbeddingService
from app.services.knowledge_ingestion import IngestionStatus, KnowledgeIngestionService
from ai.services.rag import SecurityKnowledgeRetriever

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
EMBEDDING_DIMENSION = 384
SOURCE_PREFIX = "kb://pytest"

_PROBE_CACHE = {}


def _pg_url():
    """Force the psycopg2 driver; the bare ``postgresql://`` scheme resolves to
    psycopg (v3), which this project does not install."""
    if not TEST_DATABASE_URL:
        return TEST_DATABASE_URL
    if TEST_DATABASE_URL.startswith("postgresql+psycopg2://"):
        return TEST_DATABASE_URL
    return TEST_DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)


def _database_name():
    return (TEST_DATABASE_URL or "").rsplit("/", 1)[-1].split("?", 1)[0]


def _probe_pgvector():
    """Return ``(available, detail)`` for the pgvector extension."""
    if "result" in _PROBE_CACHE:
        return _PROBE_CACHE["result"]

    if not TEST_DATABASE_URL or not TEST_DATABASE_URL.startswith("postgresql"):
        result = (False, "TEST_DATABASE_URL is not configured for PostgreSQL")
    else:
        engine = None
        try:
            engine = create_engine(_pg_url())
            with engine.connect() as conn:
                conn.execute(text("SELECT '[1,2,3]'::vector"))
            result = (True, "pgvector available")
        except Exception as exc:  # noqa: BLE001 - report the environment verbatim
            detail = str(exc).splitlines()[0][:240] if str(exc) else type(exc).__name__
            result = (False, f"{type(exc).__name__}: {detail}")
        finally:
            if engine is not None:
                engine.dispose()

    _PROBE_CACHE["result"] = result
    return result


VECTOR_AVAILABLE, VECTOR_DETAIL = _probe_pgvector()

requires_pgvector = pytest.mark.skipif(
    not VECTOR_AVAILABLE, reason=f"pgvector unusable in this environment - {VECTOR_DETAIL}"
)


def _engine():
    return create_engine(_pg_url())


def _delete_rows(engine, source_uri):
    """Delete only the documents (and cascaded chunks) this test created."""
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM knowledge_documents WHERE source_uri = :uri"),
            {"uri": source_uri},
        )


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def committed_session():
    """A real, committing session with scoped cleanup of its own rows.

    Used where durability must be proven from an independent connection.
    """
    engine = _engine()
    session = Session(bind=engine)
    created = []

    def track(source_uri):
        created.append(source_uri)
        return source_uri

    try:
        yield session, engine, track
    finally:
        session.close()
        for source_uri in created:
            try:
                _delete_rows(engine, source_uri)
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
        engine.dispose()


@pytest.fixture
def savepoint_session():
    """Session inside a test-owned outer transaction that is always rolled back."""
    engine = _engine()
    connection = engine.connect()
    outer = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session, engine
    finally:
        session.close()
        outer.rollback()
        connection.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Test A - ingestion persists real rows and real 384D vectors
# ---------------------------------------------------------------------------
@requires_pgvector
def test_ingest_persists_documents_and_chunks_to_postgres(committed_session):
    db, engine, track = committed_session
    source_uri = track(f"{SOURCE_PREFIX}/{uuid.uuid4()}")

    service = KnowledgeIngestionService(db, embedder=HashingEmbeddingService())
    result = service.ingest_document(
        title="PostgreSQL RAG storage check",
        source_uri=source_uri,
        content=(
            "aws s3 bucket public access block guidance used to verify that "
            "documents and chunks are persisted to PostgreSQL with embeddings."
        ),
        tags=["s3", "aws"],
    )

    assert result.status == IngestionStatus.CREATED
    assert result.chunk_count >= 1
    assert result.embeddings_stored == result.chunk_count
    db.close()

    # Read back over an independent connection: proves the rows were committed.
    with engine.connect() as conn:
        stored = conn.execute(
            text(
                "SELECT count(*) FROM knowledge_documents "
                "WHERE source_uri = :uri"
            ),
            {"uri": source_uri},
        ).scalar()
        assert stored == 1

        chunk_count, embedded, dimensions = conn.execute(
            text(
                "SELECT count(*), "
                "       count(*) FILTER (WHERE c.embedding IS NOT NULL), "
                "       min(vector_dims(c.embedding)) "
                "FROM knowledge_chunks c "
                "JOIN knowledge_documents d ON d.id = c.document_id "
                "WHERE d.source_uri = :uri"
            ),
            {"uri": source_uri},
        ).one()

    assert chunk_count == result.chunk_count
    assert embedded == result.chunk_count
    assert dimensions == EMBEDDING_DIMENSION

    # The physical column really is vector(384), not an array fallback.
    with engine.connect() as conn:
        udt, typmod = conn.execute(
            text(
                "SELECT a.atttypid::regtype::text, a.atttypmod "
                "FROM pg_attribute a "
                "WHERE a.attrelid = 'knowledge_chunks'::regclass "
                "  AND a.attname = 'embedding'"
            )
        ).one()
    assert udt == "vector"
    assert typmod == EMBEDDING_DIMENSION

    # Re-ingesting identical content is idempotent: no duplicate chunks.
    db2 = Session(bind=engine)
    try:
        again = KnowledgeIngestionService(
            db2, embedder=HashingEmbeddingService()
        ).ingest_document(
            title="PostgreSQL RAG storage check",
            source_uri=source_uri,
            content=(
                "aws s3 bucket public access block guidance used to verify that "
                "documents and chunks are persisted to PostgreSQL with embeddings."
            ),
            tags=["s3", "aws"],
        )
        assert again.status == IngestionStatus.UNCHANGED
        assert again.chunk_count == result.chunk_count
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# Test B - real cosine-distance retrieval through SecurityKnowledgeRetriever
# ---------------------------------------------------------------------------
@requires_pgvector
def test_vector_similarity_search_returns_the_relevant_chunk(savepoint_session):
    db, engine = savepoint_session
    suffix = uuid.uuid4()

    service = KnowledgeIngestionService(db, embedder=HashingEmbeddingService())
    service.ingest_document(
        title="Vector search target",
        source_uri=f"{SOURCE_PREFIX}/{suffix}-target",
        content=(
            "aws s3 bucket public access block prevents accidental data "
            "exposure by rejecting public ACLs and public policies."
        ),
        tags=["s3"],
    )
    service.ingest_document(
        title="Unrelated vector noise",
        source_uri=f"{SOURCE_PREFIX}/{suffix}-noise",
        content=(
            "aws iam access key rotation schedule for long lived credentials "
            "and multi factor authentication enforcement."
        ),
        tags=["iam"],
    )

    retriever = SecurityKnowledgeRetriever(
        knowledge_base_path=None, db_session=db
    )
    # These chunks were embedded by the deterministic hashing backend, so query
    # with that same vector space instead of whatever model this machine has.
    retriever._embedder = HashingEmbeddingService()
    retriever._embedder_resolved = True
    retriever.embedding_model = "aegivion-hashing-v1"
    result = retriever.retrieve_security_knowledge(
        "finding-1", "aws", "s3 public access block", None, db=db
    )

    assert result["retrieval_source"] == "pgvector"
    assert result["relevant_knowledge"]
    top = result["relevant_knowledge"][0]
    assert top["source"] == "pgvector"
    assert top["title"] == "Vector search target"
    assert 0.0 <= top["score"] <= 1.0
    assert top["chunk_id"]

    # The ordering really is cosine distance ascending in PostgreSQL.
    distance_query = retriever.build_vector_query(
        db, retriever._embed_query("aws s3 public access block"), None, 2
    )
    distances = [float(row[-1]) for row in distance_query.all()]
    assert distances == sorted(distances)
    assert distances[0] <= distances[-1]


# ---------------------------------------------------------------------------
# Test C - tenant isolation at the database query level
# ---------------------------------------------------------------------------
@requires_pgvector
def test_tenant_isolation_is_enforced_by_the_database_query(savepoint_session):
    db, engine = savepoint_session
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    suffix = uuid.uuid4()

    service = KnowledgeIngestionService(db, embedder=HashingEmbeddingService())
    service.ingest_document(
        title="Org A only knowledge",
        source_uri=f"{SOURCE_PREFIX}/{suffix}-a",
        content=(
            "aws s3 bucket policy that belongs only to organization a and "
            "must never be disclosed to another tenant."
        ),
        scope=KnowledgeScope.ORGANIZATION,
        organization_id=org_a,
    )
    service.ingest_document(
        title="Org B only knowledge",
        source_uri=f"{SOURCE_PREFIX}/{suffix}-b",
        content=(
            "aws s3 bucket policy that belongs only to organization b and "
            "must never be disclosed to another tenant."
        ),
        scope=KnowledgeScope.ORGANIZATION,
        organization_id=org_b,
    )
    service.ingest_document(
        title="Global shared guidance",
        source_uri=f"{SOURCE_PREFIX}/{suffix}-global",
        content=(
            "aws s3 bucket public access block guidance shared with every "
            "tenant as global security knowledge."
        ),
        scope=KnowledgeScope.GLOBAL,
    )

    def titles_for(organization_id):
        retriever = SecurityKnowledgeRetriever(
            knowledge_base_path=None, db_session=db
        )
        result = retriever.retrieve_security_knowledge(
            "finding-1",
            "aws",
            "s3 bucket policy",
            None,
            db=db,
            organization_id=organization_id,
        )
        return {entry["title"] for entry in result["relevant_knowledge"]}

    titles_a = titles_for(org_a)
    titles_b = titles_for(org_b)
    titles_anonymous = titles_for(None)

    # Each tenant sees its own private knowledge...
    assert "Org A only knowledge" in titles_a
    assert "Org B only knowledge" in titles_b
    # ...and never the other tenant's.
    assert "Org A only knowledge" not in titles_b
    assert "Org B only knowledge" not in titles_a

    # GLOBAL knowledge stays intentionally visible to every caller.
    assert "Global shared guidance" in titles_a
    assert "Global shared guidance" in titles_b
    assert "Global shared guidance" in titles_anonymous

    # An unauthenticated/org-less caller sees only shared knowledge, never a
    # tenant's private documents.
    assert "Global shared guidance" in titles_anonymous
    assert "Org A only knowledge" not in titles_anonymous
    assert "Org B only knowledge" not in titles_anonymous

    # The isolation is enforced by SQL, not by filtering rows in Python.
    org_filtered = (
        SecurityKnowledgeRetriever(knowledge_base_path=None, db_session=db)
        .build_vector_query(
            db,
            SecurityKnowledgeRetriever(
                knowledge_base_path=None, db_session=db
            )._embed_query("aws s3 bucket policy"),
            org_b,
            10,
        )
        .all()
    )
    returned_titles = {document.title for _, document, _ in org_filtered}
    assert "Org A only knowledge" not in returned_titles


@pytest.fixture
def failing_chunk_writes():
    """Make chunk inserts fail at the database, not in application code.

    The trigger is created on its own connection so it survives the rollback
    that the service performs, and is always dropped afterwards.
    """
    engine = _engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE OR REPLACE FUNCTION aegivion_pytest_fail_chunk() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN RAISE EXCEPTION 'injected storage failure'; END; $$"
            )
        )
        conn.execute(
            text(
                "DROP TRIGGER IF EXISTS aegivion_pytest_fail_chunk_trg "
                "ON knowledge_chunks"
            )
        )
        conn.execute(
            text(
                "CREATE TRIGGER aegivion_pytest_fail_chunk_trg "
                "BEFORE INSERT ON knowledge_chunks FOR EACH ROW "
                "EXECUTE FUNCTION aegivion_pytest_fail_chunk()"
            )
        )
    try:
        yield
    finally:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "DROP TRIGGER IF EXISTS aegivion_pytest_fail_chunk_trg "
                    "ON knowledge_chunks"
                )
            )
            conn.execute(
                text("DROP FUNCTION IF EXISTS aegivion_pytest_fail_chunk()")
            )
        engine.dispose()


@requires_pgvector
def test_ingest_rolls_back_and_reports_storage_error_on_database_failure(
    failing_chunk_writes,
):
    """A real database error must roll back the whole document, not partially persist it."""
    engine = _engine()
    db = Session(bind=engine)
    source_uri = f"{SOURCE_PREFIX}/{uuid.uuid4()}"
    try:
        service = KnowledgeIngestionService(db, embedder=HashingEmbeddingService())
        result = service.ingest_document(
            title="Storage failure rollback check",
            source_uri=source_uri,
            content=(
                "aws s3 bucket guidance used to confirm the ingestion pipeline "
                "rolls back and reports storage failures instead of raising."
            ),
        )

        assert result.status == IngestionStatus.STORAGE_ERROR
        assert result.reason
        assert result.ok is False

        # The session must remain usable after the failed ingest.
        assert db.execute(text("SELECT 1")).scalar() == 1

        # And nothing may have been committed - not the document, not the chunks.
        with engine.connect() as conn:
            documents = conn.execute(
                text(
                    "SELECT count(*) FROM knowledge_documents "
                    "WHERE source_uri = :uri"
                ),
                {"uri": source_uri},
            ).scalar()
        assert documents == 0
    finally:
        _delete_rows(engine, source_uri)
        db.close()
        engine.dispose()


def test_vector_query_compiles_to_pgvector_cosine_sql():
    """Verify the pgvector wiring by compiling the query, without executing it.

    This holds even where the extension cannot load: it proves the generated SQL
    uses the cosine-distance operator, is ordered by similarity, restricts to
    vector-bearing active chunks of the same embedding model, and carries the
    tenant filter.
    """
    from sqlalchemy.dialects import postgresql

    engine = create_engine("postgresql+psycopg2://unused:unused@localhost:5432/unused")
    session = Session(bind=engine)
    try:
        retriever = SecurityKnowledgeRetriever(knowledge_base_path=None, db_session=session)
        retriever.embedding_model = "bge-small-en-v1.5"

        query = retriever.build_vector_query(
            session, [0.01] * EMBEDDING_DIMENSION, uuid.uuid4(), 5
        )
        sql = str(query.statement.compile(dialect=postgresql.dialect()))
        upper = sql.upper()

        assert "<=>" in sql, "cosine distance operator missing"
        assert "ORDER BY" in upper
        assert "KNOWLEDGE_CHUNKS.EMBEDDING IS NOT NULL" in upper
        assert "EMBEDDING_MODEL" in upper
        assert "STATUS" in upper
        # Tenant filter: shared scopes plus optionally the caller's own org.
        assert "SCOPE" in upper
        assert "ORGANIZATION_ID" in upper
    finally:
        session.close()
        engine.dispose()


def test_test_database_is_isolated_from_the_application_database():
    """Guard rail: the suite must never be pointed at the application database."""
    assert TEST_DATABASE_URL, "TEST_DATABASE_URL is required for the RAG storage tests"
    assert _database_name() == "aegivion_test", (
        "RAG integration tests must use the dedicated aegivion_test database, "
        f"got {_database_name()!r}"
    )


# ---------------------------------------------------------------------------
# Test G - the real neural BGE model drives pgvector semantic retrieval
# ---------------------------------------------------------------------------
@requires_pgvector
def test_real_bge_embeddings_drive_pgvector_semantic_retrieval(savepoint_session):
    """Prove retrieval is genuinely semantic, and never mixes embedding models.

    Unlike Test B (deterministic hashing embedder), this loads the real
    ``BAAI/bge-small-en-v1.5`` weights and ingests a document phrased differently
    from the query. Hashing vectors cannot match it; BGE must. An identical
    document embedded by the hashing backend is also ingested and must never be
    returned, because vectors from different models live in different spaces.
    """
    try:
        from app.services.embedding_service import LocalEmbeddingService

        bge = LocalEmbeddingService()
        bge.load_model()
    except Exception as exc:  # noqa: BLE001 - environment-dependent
        pytest.skip(f"real BGE model unavailable in this environment: {exc}")

    db, engine = savepoint_session
    suffix = uuid.uuid4()
    target_text = (
        "Block public access on object storage so that unauthenticated users "
        "on the internet cannot read or list stored files."
    )
    noise_text = (
        "Rotate IAM access keys every ninety days and enforce multi factor "
        "authentication for administrators."
    )

    service = KnowledgeIngestionService(db, embedder=bge)
    service.ingest_document(
        title="Neural BGE storage guidance",
        source_uri=f"{SOURCE_PREFIX}/{suffix}-bge-target",
        content=target_text,
        tags=["s3"],
    )
    service.ingest_document(
        title="Neural BGE identity guidance",
        source_uri=f"{SOURCE_PREFIX}/{suffix}-bge-noise",
        content=noise_text,
        tags=["iam"],
    )
    # Same wording, different vector space: must never surface for a BGE query.
    KnowledgeIngestionService(db, embedder=HashingEmbeddingService()).ingest_document(
        title="Hashing copy of the BGE document",
        source_uri=f"{SOURCE_PREFIX}/{suffix}-hashing-copy",
        content=target_text,
        tags=["s3"],
    )

    # The stored identifier is the project's canonical BGE model id and 384 dims.
    rows = db.execute(
        text(
            "SELECT c.embedding_model, vector_dims(c.embedding) "
            "FROM knowledge_chunks c "
            "JOIN knowledge_documents d ON d.id = c.document_id "
            "WHERE d.source_uri LIKE :uri"
        ),
        {"uri": f"{SOURCE_PREFIX}/{suffix}-%"},
    ).all()
    assert rows
    assert {model for model, _dims in rows} == {"bge-small-en-v1.5", "aegivion-hashing-v1"}
    assert {dims for _model, dims in rows} == {EMBEDDING_DIMENSION}
    bge_rows = [r for r in rows if r[0] == "bge-small-en-v1.5"]
    assert len(bge_rows) == 2, "the two neural documents must be stored as BGE vectors"

    # Kept independent of environment variables: bind the same model used for
    # ingestion to the query side so query/document spaces are identical.
    retriever = SecurityKnowledgeRetriever(knowledge_base_path=None, db_session=db)
    retriever._embedder = bge
    retriever._embedder_resolved = True
    retriever.embedding_model = "bge-small-en-v1.5"

    result = retriever.retrieve_security_knowledge(
        "finding-bge",
        "aws",
        "anonymous internet visitors can download files from a cloud bucket",
        None,
        db=db,
        tags=["s3", "iam"],
        top_k=5,
    )

    assert result["retrieval_source"] == "pgvector"
    titles = [entry["title"] for entry in result["relevant_knowledge"]]
    assert titles, "BGE retrieval returned no knowledge"
    assert titles[0] == "Neural BGE storage guidance", titles
    assert "Hashing copy of the BGE document" not in titles

    scores = {e["title"]: e["score"] for e in result["relevant_knowledge"]}
    assert scores["Neural BGE storage guidance"] > scores["Neural BGE identity guidance"]
