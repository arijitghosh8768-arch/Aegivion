"""Neural RAG / Copilot benchmark against an isolated benchmark database.

The benchmark corpus is synthetic and exists only in ``aegivion_bench``.  Real
BAAI/bge-small-en-v1.5 embeddings are used; hashing embeddings are never
substituted.  The LLM is mocked (paid providers remain out of scope).

Usage (from ``packages/backend``)::

    python tests/perf/bench_rag.py --queries 8 --samples 25 \
        --out reports/rag_benchmark.json
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

DEFAULT_DB = os.environ.get("AEGIVION_BENCH_DATABASE_URL", "")
# No credentials are committed: point this at a dedicated benchmark DB, e.g.
#   export AEGIVION_BENCH_DATABASE_URL=postgresql://aegivion@localhost:5433/aegivion_bench

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
PACKAGES_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
for path in (BACKEND_DIR, PACKAGES_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

os.environ.pop("TEST_DATABASE_URL", None)
os.environ["DATABASE_URL"] = DEFAULT_DB
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ["ENVIRONMENT"] = "test"
os.environ.pop("AEGIVION_EMBEDDING_BACKEND", None)

if not DEFAULT_DB:
    raise SystemExit(
        "AEGIVION_BENCH_DATABASE_URL is required (a dedicated benchmark database, "
        "never the application or test database)"
    )
if "aegivion_bench" not in os.environ["DATABASE_URL"]:
    raise SystemExit("Refusing to run the RAG benchmark against a non-benchmark database")

from sqlalchemy import text  # noqa: E402

from app.database import SessionLocal  # noqa: E402
from app.models.knowledge import (  # noqa: E402
    ChunkStatus,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeScope,
)
from app.models.organization import Organization  # noqa: E402
from app.services.embedding_service import (  # noqa: E402
    LocalEmbeddingService,
    get_embedding_service,
)
from app.services.knowledge_ingestion import KnowledgeIngestionService  # noqa: E402
from ai.services.rag import SecurityKnowledgeRetriever  # noqa: E402

DOCUMENTS = [
    ("Block public S3 bucket access", "global-s3-public", "GLOBAL",
     "A publicly accessible S3 bucket exposes objects to the internet. Remediate by enabling "
     "S3 Block Public Access at the account and bucket level, removing public bucket policies "
     "and ACL grants, and enabling access logging. Public READ or WRITE grants on a bucket "
     "allow anyone to download or overwrite objects."),
    ("Enforce MFA for IAM users", "global-iam-mfa", "GLOBAL",
     "Require multi-factor authentication for every IAM user, especially administrators. "
     "Without MFA a leaked password grants full console access. Enable MFA devices, require "
     "MFA in IAM policies, and audit users that have console access without MFA."),
    ("Restrict SSH port 22 from the internet", "global-ec2-ssh", "GLOBAL",
     "An EC2 security group that allows inbound TCP port 22 from 0.0.0.0/0 exposes SSH to the "
     "entire internet. Restrict SSH to trusted CIDR ranges, use a bastion host or SSM Session "
     "Manager, and remove public IP addresses from instances that do not need them."),
    ("Encrypt RDS storage at rest", "global-rds-encryption", "GLOBAL",
     "RDS database instances should have storage encryption enabled with KMS. Unencrypted "
     "database storage can be read if snapshots or disks are exposed. Enable encryption at "
     "instance creation or restore an encrypted snapshot."),
    ("Enable CloudTrail audit logging", "global-cloudtrail", "GLOBAL",
     "CloudTrail must log management events in all regions to support auditing and breach "
     "detection. A trail with logging disabled means API activity is not recorded. Enable "
     "logging, use a multi-region trail, and protect the log bucket."),
    ("Review security group egress rules", "global-sg-egress", "GLOBAL",
     "Security groups that allow all outbound traffic can enable data exfiltration. Restrict "
     "egress to required destinations and ports, and monitor unusual outbound connections."),
    ("Rotate KMS customer managed keys", "global-kms-rotation", "GLOBAL",
     "Enable automatic rotation for customer managed KMS keys and review key policies. "
     "Long-lived keys increase the impact of credential compromise."),
    ("S3 versioning protects against ransomware deletion", "global-s3-ransomware", "GLOBAL",
     "Enable S3 versioning and Object Lock to recover objects deleted or encrypted by "
     "ransomware. Combine versioning with MFA delete, replication, and least-privilege bucket "
     "policies so a compromised identity cannot destroy backups."),
    ("Detect threats with GuardDuty", "global-guardduty", "GLOBAL",
     "Amazon GuardDuty continuously monitors for malicious activity such as credential misuse "
     "and cryptocurrency mining. Enable GuardDuty in every region and route findings to "
     "incident response."),
    ("Rotate IAM access keys", "global-iam-keys", "GLOBAL",
     "Access keys older than 90 days should be rotated. Disable unused keys and prefer "
     "temporary credentials from IAM roles instead of long-lived access keys."),
    ("Aegivion S3 exfiltration response runbook", "org-a-exfil", "ORGANIZATION_A",
     "Aegivion internal runbook: on suspected S3 data exfiltration, revoke the compromised "
     "identity, snapshot bucket policies, enable GuardDuty, and preserve CloudTrail evidence. "
     "Escalate to the Aegivion security duty officer."),
    ("Aegivion IAM break-glass procedure", "org-a-breakglass", "ORGANIZATION_A",
     "Aegivion break-glass access requires two approvers, a time-bound role session, and a "
     "post-incident review recorded in the Aegivion ticketing system."),
    ("Aegivion network segmentation standard", "org-a-network", "ORGANIZATION_A",
     "Aegivion production VPCs are segmented by environment with no inbound access from the "
     "internet except the load balancer tier."),
    ("Globex data retention policy", "org-b-retention", "ORGANIZATION_B",
     "Globex retains customer records for seven years and encrypts archives with Globex "
     "managed keys."),
    ("Globex ransomware playbook", "org-b-ransomware", "ORGANIZATION_B",
     "Globex ransomware response isolates affected accounts, restores from immutable backups, "
     "and notifies the Globex incident commander."),
    ("Legacy S3 bucket policy guidance", "global-legacy-archived", "GLOBAL",
     "This legacy document describes an obsolete S3 bucket policy pattern and is archived."),
]

QUERIES = [
    ("How do I stop an S3 bucket from being publicly readable?", "Block public S3 bucket access"),
    ("Require multi-factor authentication for administrators", "Enforce MFA for IAM users"),
    ("SSH port 22 is open to the internet on an EC2 instance", "Restrict SSH port 22 from the internet"),
    ("Is RDS database storage encrypted at rest?", "Encrypt RDS storage at rest"),
    ("Enable CloudTrail audit logging in all regions", "Enable CloudTrail audit logging"),
    ("How do we protect S3 data from ransomware deletion?", "S3 versioning protects against ransomware deletion"),
    ("What is Aegivion's response to suspected data exfiltration?", "Aegivion S3 exfiltration response runbook"),
    # Tenant-B knowledge: retrievable only for tenant B, so it is excluded from
    # tenant A's recall metric and exercised by the isolation check below.
    ("What does the Globex ransomware playbook require?", None),
]


def _org(db, label: str) -> uuid.UUID:
    existing = db.query(Organization).filter(Organization.slug == label).first()
    if existing:
        return existing.id
    org = Organization(
        id=uuid.uuid4(),
        name=label,
        slug=label,
        subscription_plan="enterprise",
    )
    db.add(org)
    db.commit()
    return org.id


def _build_corpus(db, embedder) -> Dict[str, Any]:
    org_a = _org(db, "bench-rag-org-a")
    org_b = _org(db, "bench-rag-org-b")

    # Isolated benchmark corpus: start from an empty knowledge store.
    db.query(KnowledgeChunk).delete()
    db.query(KnowledgeDocument).delete()
    db.commit()

    service = KnowledgeIngestionService(db, embedder=embedder)
    created = 0
    for title, uri, scope_name, body in DOCUMENTS:
        if scope_name == "ORGANIZATION_A":
            scope, org_id = KnowledgeScope.ORGANIZATION, org_a
        elif scope_name == "ORGANIZATION_B":
            scope, org_id = KnowledgeScope.ORGANIZATION, org_b
        else:
            scope, org_id = KnowledgeScope.GLOBAL, None
        result = service.ingest_document(
            title=title,
            source_uri=f"bench://{uri}",
            content=body,
            scope=scope,
            organization_id=str(org_id) if org_id else None,
            tags=["benchmark"],
        )
        if not result.ok:
            raise RuntimeError(f"ingest failed for {uri}: {result.reason}")
        created += 1

    service.archive_document("bench://global-legacy-archived")

    return {
        "org_a": str(org_a),
        "org_b": str(org_b),
        "documents_ingested": created,
        "documents_in_db": db.query(KnowledgeDocument).count(),
        "active_chunks": db.query(KnowledgeChunk)
        .filter(KnowledgeChunk.status == ChunkStatus.ACTIVE)
        .count(),
        "archived_chunks": db.query(KnowledgeChunk)
        .filter(KnowledgeChunk.status == ChunkStatus.ARCHIVED)
        .count(),
        "embedding_model": db.query(KnowledgeChunk.embedding_model)
        .filter(KnowledgeChunk.embedding.isnot(None))
        .first()[0],
        "embedding_dim": db.execute(
            text("select vector_dims(embedding) from knowledge_chunks where embedding is not null limit 1")
        ).scalar(),
    }


def _percentile(values: List[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def _stats(values: List[float]) -> Dict[str, float]:
    return {
        "n": len(values),
        "median_ms": round(statistics.median(values) * 1000, 2),
        "min_ms": round(min(values) * 1000, 2),
        "max_ms": round(max(values) * 1000, 2),
        "p95_ms": round(_percentile(values, 0.95) * 1000, 2) if len(values) >= 20 else None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=25)
    parser.add_argument("--e2e-samples", type=int, default=12)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    cold_start = time.perf_counter()
    neural = LocalEmbeddingService()
    neural.load_model()
    neural.embed_chunks(["warm up"])
    cold_seconds = time.perf_counter() - cold_start
    assert neural.dimension == 384

    # Every retrieval in this benchmark uses the same neural instance that
    # produced the document vectors.
    import app.services.embedding_service as embedding_module

    embedding_module._active_embedding_service = neural

    db = SessionLocal()
    try:
        corpus = _build_corpus(db, neural)

        retriever = SecurityKnowledgeRetriever(
            knowledge_base_path=None, db_session=db, embedding_model="bge-small-en-v1.5"
        )
        retriever._embedder = neural
        retriever._embedder_resolved = True

        embed_times: List[float] = []
        query_times: List[float] = []
        full_times: List[float] = []
        context_times: List[float] = []
        hits = 0
        scored_queries = 0
        reciprocal_ranks: List[float] = []
        isolation_failures: List[str] = []
        archived_leaks: List[str] = []
        citation_failures: List[str] = []
        top_titles: Dict[str, List[str]] = {}

        from app.api.v1.chat import ChatMessage, ChatRequest, build_chat_prompt

        for question, expected in QUERIES:
            for _ in range(args.samples):
                started = time.perf_counter()
                vector = retriever._embed_query(question)
                embed_times.append(time.perf_counter() - started)

                started = time.perf_counter()
                rows = retriever.build_vector_query(
                    db, vector, corpus["org_a"], 5
                ).all()
                query_times.append(time.perf_counter() - started)

                started = time.perf_counter()
                rag = retriever.retrieve_security_knowledge(
                    finding_id="bench",
                    provider="aws",
                    finding_type="general",
                    finding_metadata={},
                    db=db,
                    organization_id=corpus["org_a"],
                    top_k=5,
                    include_synthetic_enrichment=False,
                    query_text=question,
                )
                full_times.append(time.perf_counter() - started)

                started = time.perf_counter()
                build_chat_prompt(
                    ChatRequest(message=question, finding_id="bench"),
                    {"retrieved": rag["relevant_knowledge"]},
                )
                context_times.append(time.perf_counter() - started)

            rag = retriever.retrieve_security_knowledge(
                finding_id="bench",
                provider="aws",
                finding_type="general",
                finding_metadata={},
                db=db,
                organization_id=corpus["org_a"],
                top_k=5,
                include_synthetic_enrichment=False,
                query_text=question,
            )
            titles = [entry["title"] for entry in rag["relevant_knowledge"]]
            top_titles[question] = titles
            if expected:
                scored_queries += 1
                if expected in titles:
                    hits += 1
                    reciprocal_ranks.append(1.0 / (titles.index(expected) + 1))
                else:
                    reciprocal_ranks.append(0.0)

            if rag["retrieval_source"] != "pgvector":
                isolation_failures.append(f"{question}: source={rag['retrieval_source']}")
            for entry in rag["relevant_knowledge"]:
                if entry.get("source_uri", "").startswith("bench://org-b-"):
                    isolation_failures.append(f"{question}: leaked {entry['source_uri']}")
                if entry.get("source_uri") == "bench://global-legacy-archived":
                    archived_leaks.append(question)
            for citation in rag["citations"]:
                if not citation.get("source_uri") or not citation.get("chunk_id"):
                    citation_failures.append(f"{question}: incomplete citation")

        # Tenant B visibility: its private playbook must be retrievable for B and
        # A's private runbook must not appear.
        rag_b = retriever.retrieve_security_knowledge(
            finding_id="bench-b",
            provider="aws",
            finding_type="Globex ransomware playbook",
            db=db,
            organization_id=corpus["org_b"],
            top_k=5,
            include_synthetic_enrichment=False,
            query_text="Globex ransomware playbook",
        )
        titles_b = [entry["title"] for entry in rag_b["relevant_knowledge"]]
        tenant_b_ok = (
            any("Globex" in title for title in titles_b)
            and not any("Aegivion" in title for title in titles_b)
        )

        # Idempotent re-ingestion.
        res = KnowledgeIngestionService(db, embedder=neural).ingest_document(
            title="Block public S3 bucket access",
            source_uri="bench://global-s3-public",
            content=DOCUMENTS[0][3],
            scope=KnowledgeScope.GLOBAL,
            tags=["benchmark"],
        )
        idempotent = res.status.value

        # Copilot E2E with a mocked LLM.
        from fastapi.testclient import TestClient
        from app.main import app
        from app.api.v1 import chat as chat_module

        class FakeProvider:
            def generate(self, prompt, system_prompt=None):
                assert "BLOCK PUBLIC" in prompt.upper() or "S3" in prompt.upper()
                return json.dumps(
                    {
                        "response": "Enable S3 Block Public Access and remove public grants.",
                        "observed": ["public bucket"],
                        "inferred": ["internet readable"],
                        "unknown": [],
                    }
                )

        chat_module.rag_retriever = retriever
        chat_module.get_llm_provider = lambda: FakeProvider()

        from app.database import get_db
        from app.api.deps import get_current_user

        def _override_db():
            yield db

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_current_user] = lambda: {
            "id": str(uuid.uuid4()),
            "organization_id": corpus["org_a"],
        }
        e2e_times: List[float] = []
        e2e_citations: List[int] = []
        e2e_status: List[int] = []
        try:
            with TestClient(app) as client:
                for _ in range(args.e2e_samples):
                    chat_module.limiter.reset()
                    started = time.perf_counter()
                    response = client.post(
                        "/api/v1/ai/chat",
                        json={
                            "message": QUERIES[0][0],
                            "finding_id": "bench-finding",
                        },
                    )
                    e2e_times.append(time.perf_counter() - started)
                    e2e_status.append(response.status_code)
                    if response.status_code == 200:
                        e2e_citations.append(len(response.json().get("citations", [])))
                    else:
                        e2e_citations.append(-1)
        finally:
            app.dependency_overrides.clear()

        output = {
            "environment": {
                "database": "postgresql://aegivion@localhost:5433/aegivion_bench",
                "embedding_backend": type(neural).__name__,
                "embedding_model": "BAAI/bge-small-en-v1.5",
                "llm": "mocked (paid providers out of scope)",
            },
            "corpus": corpus,
            "cold_start_s": round(cold_seconds, 3),
            "latency": {
                "query_embedding": _stats(embed_times),
                "pgvector_sql": _stats(query_times),
                "full_retrieval": _stats(full_times),
                "context_assembly": _stats(context_times),
                "copilot_e2e_mocked_llm": _stats(e2e_times),
            },
            "correctness": {
                "queries": scored_queries,
                "samples_per_query": args.samples,
                "recall_at_5": round(hits / scored_queries, 3),
                "mrr_at_5": round(sum(reciprocal_ranks) / len(reciprocal_ranks), 3),
                "tenant_isolation_failures": isolation_failures,
                "tenant_b_visibility_ok": tenant_b_ok,
                "archived_leaks": archived_leaks,
                "citation_failures": citation_failures,
                "idempotent_reingest_status": idempotent,
                "top_titles": top_titles,
            },
            "copilot_e2e": {
                "statuses": e2e_status,
                "citation_counts": e2e_citations,
                "samples": args.e2e_samples,
            },
        }

        text_out = json.dumps(output, indent=2)
        print(text_out)
        if args.out:
            os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(text_out)
    finally:
        db.close()


if __name__ == "__main__":
    main()
