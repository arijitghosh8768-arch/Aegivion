# Testing and Acceptance Plan

## Layers
1. Unit tests for normalizers, algorithms, validators, and state machines.
2. Repository tests for tenant filters, transactions, constraints, and transitions.
3. Concurrency tests for claims, leases, fencing, retries, and idempotency.
4. Integration tests for cloud adapters, APIs, PostgreSQL, RAG, and frontend contracts.
5. Security tests for authorization, tenant isolation, sessions/OAuth, secrets, prompt injection, and response policy.
6. End-to-end onboarding → discovery → detection → explanation → approval → response → verification → audit.
7. Live validation against actual PostgreSQL and dedicated least-privilege test cloud resources.
8. Resilience tests for restarts, provider throttling, partial failures, database/model outages, and recovery.

## Status gates
- **Code complete:** required code/contracts exist.
- **Locally tested:** recorded commands actually pass in supported environment.
- **Integration tested:** connected modules exercised together.
- **Live validated:** actual required infrastructure/service used.
- **Production ready:** release, security, operations, recovery, and owner-approval gates pass.

Record commit, environment, command, actual test results, skips, artifacts, dependencies, known gaps, and reviewer. Never report skipped/blocked tests as passing.
