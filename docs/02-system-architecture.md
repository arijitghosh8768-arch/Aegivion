# System Architecture

## Logical pipeline
Cloud Providers → Collection → Asset Normalization → Security Digital Twin → Independent Detection → Correlation → Attack Activation → Attack-Path Analysis → What-If Simulation → Minimum-Impact Response Selection → AI Explanation → Policy/Human Approval → Allowlisted Execution → Verification → Audit Trail → Dashboard.

## Domains
- Cloud Management: authentication/org foundations, cloud accounts, adapters, collection, inventory, relationships, synchronization.
- Security Analytics: detection, findings, risk, incidents, correlation, attack paths, compliance, response policy.
- AI Security Intelligence: context assembly, RAG, explanations, recommendations, reporting, evaluation.
- Product/Integration: UI, API integration, dashboards, accessibility, product integration.
- Agent/Response: orchestration, runbooks, approvals, execution, verification, replay.

## Principles
- Deterministic detection, risk, and response policy remain authoritative.
- AI explains and assists; it does not authorize or directly execute cloud changes.
- Mutations require allowlist, policy, preconditions, approval when required, verification, and audit.
- Tenant scope comes from authenticated server-side membership.
- Provider-specific logic stays behind adapters.
- Event processing is idempotent and recoverable.
- Production must not silently fall back to in-memory persistence.

## Deployment topology to verify
Browser → frontend → backend/API → PostgreSQL; workers → cloud APIs; AI service → approved retrieval store/model provider; telemetry → logging/metrics/tracing.

Confirm the actual topology, network boundaries, secrets management, and scaling strategy from repository/deployment configuration.
