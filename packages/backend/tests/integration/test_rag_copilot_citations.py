"""Copilot integration test: retrieved knowledge must reach the prompt and the
response must cite real sources.

The chat endpoint consults ``OrgSettings`` (a legacy non-ORM model) before doing
anything else, so this test wraps a real SQLite session in a tiny proxy that
answers only that one lookup. All knowledge retrieval is genuinely executed
against the ingested data.
"""

import json
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_current_user
from app.database import get_db
from app.main import app
from app.models.postgres_base import PostgresBase
from app.services.embedding_service import HashingEmbeddingService
from app.services.knowledge_ingestion import KnowledgeIngestionService


class _EmptyQuery:
    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return None


class _SessionProxy:
    """Real session for knowledge lookups; neutral answer for org lookups.

    The AI-access gate and the legacy settings model are not what this test
    exercises (they are covered against real PostgreSQL elsewhere), so those
    lookups return "no row" and leave AI access enabled.
    """

    _NEUTRALIZED = {"OrgSettings", "Organization"}

    def __init__(self, real_session):
        self._real = real_session

    def query(self, *entities):
        if entities and getattr(entities[0], "__name__", "") in self._NEUTRALIZED:
            return _EmptyQuery()
        return self._real.query(*entities)

    def __getattr__(self, item):
        return getattr(self._real, item)


DOC_TITLE = "S3 Public Access Prevention"
DOC_URI = "https://docs.aws.amazon.com/s3/security.html"
DOC_CONTENT = (
    "aws s3 bucket public access block prevents accidental data exposure. "
    "Block Public Access must be enabled on every bucket unless static hosting "
    "is explicitly intended."
)


@pytest.fixture
def client_with_knowledge():
    # TestClient runs requests on a different thread, so the in-memory database
    # must be a single shared connection.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    PostgresBase.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    service = KnowledgeIngestionService(db, embedder=HashingEmbeddingService())
    service.ingest_document(
        title=DOC_TITLE,
        source_uri=DOC_URI,
        content=DOC_CONTENT,
        tags=["s3", "aws"],
    )

    proxy = _SessionProxy(db)

    # Disable the curated in-memory fallback so citations can only come from
    # the database, which is what this test is asserting.
    from ai.services.rag import rag_retriever

    saved_index = rag_retriever.index
    rag_retriever.index = []

    def override_get_db():
        yield proxy

    org_id = uuid.uuid4()
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: {
        "id": str(uuid.uuid4()),
        "organization_id": str(org_id),
    }

    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        rag_retriever.index = saved_index
        db.close()
        engine.dispose()


def _llm_json():
    return json.dumps(
        {
            "response": "Public S3 access should be blocked.",
            "observed": ["Bucket is public"],
            "inferred": ["Data exposure risk"],
            "unknown": ["Business owner"],
            "declined": False,
        }
    )


@patch("app.api.v1.chat.get_llm_provider")
def test_chat_returns_citations_from_retrieved_knowledge(mock_provider, client_with_knowledge):
    mock_provider.return_value.generate.return_value = _llm_json()

    response = client_with_knowledge.post(
        "/api/v1/ai/chat",
        json={"message": "Why does public S3 access matter?", "finding_id": "finding-1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["citations"], "retrieved knowledge should produce citations"
    assert payload["citations"][0]["source_uri"] == DOC_URI
    assert payload["citations"][0]["title"] == DOC_TITLE


@patch("app.api.v1.chat.get_llm_provider")
def test_chat_prompt_contains_retrieved_knowledge_as_untrusted_data(
    mock_provider, client_with_knowledge
):
    mock_provider.return_value.generate.return_value = _llm_json()

    response = client_with_knowledge.post(
        "/api/v1/ai/chat",
        json={"message": "Explain the S3 finding", "finding_id": "finding-1"},
    )
    assert response.status_code == 200

    prompt = mock_provider.return_value.generate.call_args[0][0]
    assert DOC_TITLE in prompt
    assert "public access block" in prompt
    assert "UNTRUSTED reference material" in prompt


@patch("app.api.v1.chat.get_llm_provider")
def test_chat_without_finding_id_returns_no_citations(mock_provider, client_with_knowledge):
    mock_provider.return_value.generate.return_value = _llm_json()

    response = client_with_knowledge.post(
        "/api/v1/ai/chat", json={"message": "What is our threat posture?"}
    )

    assert response.status_code == 200
    assert response.json()["citations"] == []
