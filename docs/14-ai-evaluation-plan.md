# AI Evaluation Plan

## Dimensions
Retrieval relevance; citation correctness; evidence support; unsupported-claim rate; observed/inferred/unknown separation; impact quality; recommendation safety; schema validity; tenant isolation; prompt-injection resistance; latency; cost; timeout/fallback behavior; regression quality.

## Dataset
Create a versioned, access-controlled test set with representative findings, incidents, attack paths, benign cases, contradictory/missing evidence, malicious resource names/documents, and cross-tenant retrieval attempts.

## Metrics
Define thresholds before production. Record dataset/model/prompt/embedding/index versions, denominators, failure examples, and limitations.

## Release gate
Plausible-looking examples are not enough. Evaluate fixed cases, inspect unsupported claims, validate citations, and test access controls.
