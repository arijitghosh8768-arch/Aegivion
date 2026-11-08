import pytest
import uuid
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.postgres_base import PostgresBase
from app.models.knowledge import (
    KnowledgeDocument,
    KnowledgeChunk,
    KnowledgeScope,
    AuthorityLevel,
    ChunkStatus
)
from ai.services.rag import SecurityKnowledgeRetriever
from ai.services.executive_brief import ExecutiveBriefService, TopPriority, QuickWin

# In-memory SQLite for testing
@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    # We must mock Vector type for sqlite
    with patch("pgvector.sqlalchemy.Vector", MagicMock(return_value=None)):
        pass
    PostgresBase.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_live_db_rag_retrieval(db_session):
    """
    Test inserting KnowledgeChunk into PostgreSQL/DB and verifying
    SecurityKnowledgeRetriever queries and returns the chunk.
    """
    doc_id = uuid.uuid4()
    doc = KnowledgeDocument(
        id=doc_id,
        scope=KnowledgeScope.GLOBAL,
        authority=AuthorityLevel.VENDOR,
        title="AWS S3 Security Hardening Guide",
        source_uri="https://docs.aws.amazon.com/s3/security.html",
        version_hash="hash-12345",
        metadata_json={"vendor": "aws"}
    )
    db_session.add(doc)
    db_session.commit()

    chunk_id = uuid.uuid4()
    chunk = KnowledgeChunk(
        id=chunk_id,
        document_id=doc_id,
        scope=KnowledgeScope.GLOBAL,
        chunk_index=0,
        text_content="To remediate AWS-S3-001, configure S3 Block Public Access on bucket settings and review bucket ACLs.",
        content_hash="content-hash-5678",
        chunk_metadata={"tags": ["s3", "AWS-S3-001", "public_bucket"]},
        status=ChunkStatus.ACTIVE
    )
    db_session.add(chunk)
    db_session.commit()

    # Query using SecurityKnowledgeRetriever with DB session
    retriever = SecurityKnowledgeRetriever(db_session=db_session)
    result = retriever.retrieve_security_knowledge(
        finding_id="test-finding-1",
        provider="aws",
        finding_type="AWS-S3-001",
        finding_metadata={"mitre_technique": "T1530"}
    )

    assert result["finding_id"] == "test-finding-1"
    assert len(result["relevant_knowledge"]) > 0
    
    # Check that the DB chunk was retrieved
    db_hit = next((k for k in result["relevant_knowledge"] if k.get("source") == "postgres_db"), None)
    assert db_hit is not None
    assert "S3 Block Public Access" in db_hit["content"]
    assert db_hit["title"] == "AWS S3 Security Hardening Guide"

@pytest.mark.asyncio
async def test_executive_brief_llm_synthesis():
    """
    Test ExecutiveBriefService synthesizing structured AI narrative using LLM provider.
    """
    mock_llm = MagicMock()
    mock_llm_output = MagicMock()
    mock_llm_output.text = '{"summary": "Executive posture is critical due to public S3 data.", "technical_summary": "Unrestricted public read policies detected on core buckets.", "long_term_actions": ["Deploy IAM boundaries", "Enable S3 GuardDuty"]}'
    mock_llm.generate.return_value = mock_llm_output

    service = ExecutiveBriefService(llm_provider=mock_llm)

    findings = [
        {
            "finding_id": "F-001",
            "title": "Public S3 Bucket",
            "severity": "critical",
            "status": "open",
            "asset_id": "arn:aws:s3:::customer-vault"
        }
    ]
    risk_scores = {"F-001": 95}
    correlations = []
    scan_health = {"coverage_percentage": 100, "coverage_note": "Scan completed"}

    brief = await service.generate_brief(
        findings=findings,
        risk_scores=risk_scores,
        correlations=correlations,
        scan_health=scan_health
    )

    assert brief.posture in ["critical_risk", "high_risk", "moderate_risk", "low_risk"]
    assert "Executive posture is critical" in brief.executive_summary
    assert "Unrestricted public read policies" in brief.technical_summary
    assert len(brief.long_term_actions) >= 2
    assert len(brief.citations) > 0
    assert brief.citations[0]["value"] == "F-001"

