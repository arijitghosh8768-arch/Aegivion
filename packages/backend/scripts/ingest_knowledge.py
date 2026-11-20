"""Deterministic knowledge ingestion CLI for the Aegivion RAG pipeline.

Three sub-commands:

``plan``     Build a manifest from approved in-repo knowledge sources. The
             manifest is deterministic (sorted, stable ids, content hashes) and
             is what a reviewer approves before any write happens.

``dry-run``  Validate, chunk and embed every manifest document **without
             touching any database**. This is the default.

``apply``    Persist the manifest. Requires an explicit ``--database-url`` and
             ``--confirm-apply``; there is no default target and no production
             database is contacted implicitly.

Approved sources
----------------
Only documents that already exist in the repository are used:
``packages/ai/knowledge_base/sample_entries.json`` (curated cloud-security
guidance). No external scraping, no unverified content.

Provenance preserved per document: stable ``source_uri``, ``version_hash``
(SHA-256 of the normalized content), authority, scope, tenant ownership and the
citation metadata (curated id, resource type, tags).

Usage::

    python scripts/ingest_knowledge.py plan --out knowledge_manifest.json
    python scripts/ingest_knowledge.py dry-run
    python scripts/ingest_knowledge.py apply --database-url postgresql://… --confirm-apply
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PACKAGES_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
for _path in (BACKEND_DIR, PACKAGES_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

CURATED_SOURCE = os.path.join(PACKAGES_DIR, "ai", "knowledge_base", "sample_entries.json")
SOURCE_URI_PREFIX = "kb://aegivion/sample_entries"

# The application database the API uses by default. ``apply`` refuses it unless
# the operator re-confirms, so a stray command cannot seed production.
DEFAULT_APP_DATABASE = os.getenv(
    "DATABASE_URL", "postgresql://aegivion@localhost:5432/aegivion"
)


def _normalize(text: str) -> str:
    from app.services.knowledge_ingestion import normalize_text

    return normalize_text(text)


def _fingerprint(text: str) -> str:
    return hashlib.sha256(_normalize(text).encode("utf-8")).hexdigest()


def build_manifest(source_path: str = CURATED_SOURCE) -> List[Dict[str, Any]]:
    """Build a deterministic manifest from the curated knowledge base."""
    with open(source_path, "r", encoding="utf-8") as handle:
        entries = json.load(handle)

    documents: List[Dict[str, Any]] = []
    for entry in sorted(entries, key=lambda item: str(item.get("id", ""))):
        curated_id = str(entry.get("id") or "").strip()
        if not curated_id:
            continue

        context = entry.get("context") or entry.get("content") or ""
        remediation = entry.get("remediation_terraform")
        content = context
        if remediation:
            content = f"{context}\n\nRemediation (Terraform):\n{remediation}"

        resource_type = entry.get("resource_type")
        tags = [resource_type] if resource_type else []

        documents.append(
            {
                "title": entry.get("topic") or entry.get("title") or curated_id,
                "source_uri": f"{SOURCE_URI_PREFIX}/{curated_id}",
                "content": content,
                "scope": "GLOBAL",
                "authority": "VENDOR",
                # GLOBAL knowledge is shared; ownership stays null by design.
                "organization_id": None,
                "tags": [tag for tag in tags if tag],
                "metadata": {
                    "curated_id": curated_id,
                    "resource_type": resource_type,
                    "source_dataset": os.path.relpath(source_path, PACKAGES_DIR),
                },
                "version_hash": _fingerprint(content),
            }
        )

    documents.sort(key=lambda doc: doc["source_uri"])
    return documents


def _resolution_document(documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Replace enum strings with the model enums expected by the service."""
    from app.models.knowledge import AuthorityLevel, KnowledgeScope

    resolved = []
    for document in documents:
        item = dict(document)
        item["scope"] = KnowledgeScope(document["scope"])
        item["authority"] = AuthorityLevel(document["authority"])
        resolved.append(item)
    return resolved


def cmd_plan(args: argparse.Namespace) -> int:
    documents = build_manifest()
    text = json.dumps(documents, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"Wrote manifest with {len(documents)} documents to {args.out}")
    else:
        print(text)
    return 0


def cmd_dry_run(args: argparse.Namespace) -> int:
    from app.services.embedding_service import (
        HashingEmbeddingService,
        LocalEmbeddingService,
    )
    from app.services.knowledge_ingestion import chunk_text, content_fingerprint

    documents = build_manifest()

    if args.embeddings == "hashing":
        os.environ["AEGIVION_EMBEDDING_BACKEND"] = "hashing"
        embedder = HashingEmbeddingService()
    elif args.embeddings == "none":
        embedder = None
    else:
        embedder = LocalEmbeddingService()

    rows = []
    total_chunks = 0
    total_deduped = 0
    embedded_ok = 0
    problems = 0

    for document in documents:
        content = document["content"]
        raw_chunks = chunk_text(content, args.chunk_size, args.overlap)

        seen = set()
        unique = []
        for chunk in raw_chunks:
            digest = content_fingerprint(chunk)
            if digest in seen:
                continue
            seen.add(digest)
            unique.append(chunk)

        total_chunks += len(raw_chunks)
        total_deduped += len(unique)

        dims: Optional[int] = None
        if embedder is not None and unique:
            try:
                vectors = embedder.embed_chunks(unique)
                dims = len(vectors[0]) if vectors and vectors[0] else None
                embedded_ok += sum(1 for vector in vectors if vector)
            except Exception as exc:  # noqa: BLE001
                problems += 1
                print(f"  ! embedding failed for {document['source_uri']}: {exc}")

        if len(content) < 20:
            problems += 1

        rows.append(
            {
                "source_uri": document["source_uri"],
                "title": document["title"],
                "chars": len(content),
                "raw_chunks": len(raw_chunks),
                "unique_chunks": len(unique),
                "embedding_dims": dims,
                "version_hash": document["version_hash"][:12],
                "authority": document["authority"],
                "scope": document["scope"],
            }
        )

    print("\n=== RAG ingestion dry run (no database writes) ===")
    print(f"{'source_uri':<44} {'chars':>6} {'chunks':>7} {'unique':>7} {'dims':>5}")
    print("-" * 76)
    for row in rows:
        print(
            f"{row['source_uri']:<44} {row['chars']:>6} {row['raw_chunks']:>7} "
            f"{row['unique_chunks']:>7} {str(row['embedding_dims'] or '-'):>5}"
        )
    print("-" * 76)
    print(f"documents          {len(rows)}")
    print(f"raw chunks         {total_chunks}")
    print(f"after dedupe       {total_deduped}")
    print(f"embeddings built   {embedded_ok}")
    print(f"validation issues  {problems}")
    print(f"embedder           {type(embedder).__name__ if embedder else 'disabled'}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"documents": rows}, indent=2))
        print(f"\nReport written to {args.json}")

    return 0 if problems == 0 else 1


def cmd_apply(args: argparse.Namespace) -> int:
    from app.services.embedding_service import get_embedding_service
    from app.services.knowledge_ingestion import KnowledgeIngestionService

    if not args.database_url:
        print("Refusing to apply without an explicit --database-url.")
        return 2
    if not args.confirm_apply:
        print("Refusing to apply without --confirm-apply.")
        return 2
    if args.database_url.rstrip("/") == DEFAULT_APP_DATABASE.rstrip("/") and not args.allow_production:
        print(
            "Refusing to write to the default application database. "
            "Pass --allow-production only with explicit approval."
        )
        return 2

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    url = args.database_url
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)

    engine = create_engine(url)
    session = sessionmaker(bind=engine)()
    try:
        service = KnowledgeIngestionService(
            session,
            embedder=None if args.embeddings == "none" else get_embedding_service(),
            chunk_size=args.chunk_size,
            overlap=args.overlap,
            generate_embeddings=args.embeddings != "none",
        )

        results = []
        for document in _resolution_document(build_manifest()):
            result = service.ingest_document(
                title=document["title"],
                source_uri=document["source_uri"],
                content=document["content"],
                scope=document["scope"],
                authority=document["authority"],
                organization_id=document["organization_id"],
                metadata=document["metadata"],
                tags=document["tags"],
            )
            results.append(result.to_dict())
            print(f"  {result.status.value:<14} {result.source_uri} ({result.chunk_count} chunks)")
    finally:
        session.close()
        engine.dispose()

    print(json.dumps(results, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan", "dry-run", "apply"], nargs="?", default="dry-run")
    parser.add_argument("--out", default="", help="write the plan manifest here")
    parser.add_argument("--json", default="", help="write the dry-run report here")
    parser.add_argument("--database-url", default="", help="explicit ingestion target (apply only)")
    parser.add_argument("--confirm-apply", action="store_true", help="required for apply")
    parser.add_argument("--allow-production", action="store_true", help="allow the default app database")
    parser.add_argument("--chunk-size", type=int, default=300)
    parser.add_argument("--overlap", type=int, default=45)
    parser.add_argument("--embeddings", choices=["auto", "hashing", "none"], default="hashing")
    args = parser.parse_args()

    if args.command == "plan":
        return cmd_plan(args)
    if args.command == "dry-run":
        return cmd_dry_run(args)
    return cmd_apply(args)


if __name__ == "__main__":
    raise SystemExit(main())
