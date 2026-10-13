# AI and RAG Specification

## Purpose
Generate evidence-grounded explanations and security intelligence from approved, authorized Aegivion context and curated knowledge.

## Allowed
Explain deterministic findings/paths; summarize technical/business impact with uncertainty; suggest approved remediation options; generate reports; answer questions using authorized tenant-scoped context.

## Not allowed
AI must not independently create findings, override deterministic risk/policy, grant access, or directly execute cloud mutations.

## RAG pipeline
1. Ingest approved documents with provenance and access metadata.
2. Validate source, file type, size, and ownership.
3. Extract text and preserve source references.
4. Chunk using a documented strategy.
5. Generate embeddings with a selected/versioned model.
6. Store chunks, embeddings, metadata, and versions.
7. Retrieve only authorized tenant-appropriate content.
8. Assemble bounded context with evidence labels and sources.
9. Generate versioned structured output.
10. Validate schema, claims, evidence references, and policy.
11. Return citations and uncertainty.
12. Record safe evaluation metadata without leaking sensitive content.

## Security
Treat documents, logs, event strings, and retrieved passages as untrusted. Defend against direct/indirect prompt injection. Enforce tenant/role filtering before context construction. Never send provider credentials to models. Retrieved text cannot change policy or authorize tools. AI output cannot execute unrestricted tools or mutate cloud resources.

## Evaluation
Measure retrieval relevance, citation correctness, unsupported claims, schema validity, access isolation, latency, cost, and regression quality.

## Decisions to record
Model/provider, embedding model, vector storage, ingestion sources, chunking, retention, budget, fallback behavior, and evaluation thresholds.
