"""Retrieval-quality evaluation for the Aegivion RAG knowledge base.

Runs a small hand-labelled question -> document set against the curated
knowledge base and reports Recall@K and MRR.

Important honesty note
----------------------
Each label has exactly one relevant document, so Recall@K is the fraction of
questions whose document appears in the top K. This measures the *lexical*
retrieval path (token overlap over the curated knowledge base). It is not a
measurement of neural-semantic quality: no embedding model is involved when the
in-memory fallback runs, and the pgvector path cannot execute on this machine.

Usage (from ``packages/backend``)::

    python tests/perf/eval_rag_quality.py
    python tests/perf/eval_rag_quality.py --json report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
PACKAGES_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
for path in (BACKEND_DIR, PACKAGES_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

# Keep the evaluation deterministic and offline.
os.environ.setdefault("AEGIVION_EMBEDDING_BACKEND", "hashing")

from ai.services.rag import SecurityKnowledgeRetriever  # noqa: E402

# (question, expected document title, provider)
LABELLED_SET = [
    ("How do I stop an S3 bucket from being publicly accessible?", "S3 Public Access Prevention", "aws"),
    ("Is SSH open to the internet on my security group?", "SSH Open to Internet", "aws"),
    ("A GCP compute instance is exposed to the public internet", "GCP Compute Instance Public Exposure", "gcp"),
    ("GCP firewall rule allows SSH from 0.0.0.0/0", "GCP Firewall SSH Publicly Accessible", "gcp"),
    ("Apply least privilege to a GCP service account", "GCP Service Account Least Privilege", "gcp"),
    ("Should I use user managed keys for service accounts?", "GCP User-Managed Keys for Service Accounts", "gcp"),
    ("Attack path from public compute to overprivileged service account", "GCP Multi-Cloud Attack Path: Public Compute to Overprivileged Service Account", "gcp"),
    ("Automatically disable a GCP user managed service account key", "Automated Response: Disable GCP User-Managed Service Account Key", "gcp"),
    ("Remove a public IP address from a compute instance automatically", "Automated Response: Remove Public IP from Compute Instance", "gcp"),
    ("CIS GCP foundation benchmark compliance controls", "CIS GCP Foundation Benchmark", "gcp"),
]

K_VALUES = (1, 3, 5)


def evaluate(top_k: int = 5) -> dict:
    retriever = SecurityKnowledgeRetriever()  # no DB session -> curated knowledge base
    if not retriever.index:
        raise SystemExit("Curated knowledge base is empty; cannot evaluate retrieval.")

    cases = []
    reciprocal_ranks = []
    hits = {k: 0 for k in K_VALUES}

    for index, (question, expected_title, provider) in enumerate(LABELLED_SET):
        result = retriever.retrieve_security_knowledge(
            f"eval-{index}", provider, question, None, top_k=top_k
        )
        titles = [entry.get("title") for entry in result["relevant_knowledge"]]

        rank = titles.index(expected_title) + 1 if expected_title in titles else None
        reciprocal_ranks.append(1.0 / rank if rank else 0.0)
        for k in K_VALUES:
            if rank is not None and rank <= k:
                hits[k] += 1

        cases.append(
            {
                "question": question,
                "expected": expected_title,
                "rank": rank,
                "returned": titles,
                "retrieval_source": result["retrieval_source"],
            }
        )

    total = len(LABELLED_SET)
    metrics = {f"recall_at_{k}": round(hits[k] / total, 4) for k in K_VALUES}
    metrics["mrr_at_%d" % top_k] = round(sum(reciprocal_ranks) / total, 4)
    metrics["num_queries"] = total
    metrics["corpus_chunks"] = len(retriever.index)

    return {
        "evaluation": "labelled question -> document, single relevant doc per query",
        "retrieval_path": "lexical token overlap over the curated knowledge base",
        "note": (
            "Lexical retrieval metrics only. Neural-semantic retrieval was not "
            "measured because the pgvector path cannot execute in this environment."
        ),
        "top_k": top_k,
        "metrics": metrics,
        "cases": cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    report = evaluate(top_k=args.top_k)

    print("\n=== RAG retrieval quality (lexical path) ===")
    print(f"{'question':<62} rank")
    print("-" * 72)
    for case in report["cases"]:
        rank = case["rank"] if case["rank"] is not None else "MISS"
        print(f"{case['question'][:60]:<62} {rank}")
    print("-" * 72)
    for key, value in report["metrics"].items():
        print(f"{key:<18} {value}")
    print()

    text = json.dumps(report, indent=2)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"Report written to {args.json}")


if __name__ == "__main__":
    main()
