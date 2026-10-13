# Product Requirements Document

## Product goal
Provide security teams with unified multi-cloud asset visibility, evidence-backed findings, attack-path analysis, explainable intelligence, and controlled remediation.

## Users
Platform administrator; organization administrator; cloud/security administrator; security analyst; read-only viewer/auditor.

## Core journeys
1. User authenticates and can access only organizations with active membership.
2. Authorized administrator connects a cloud account through a secure flow.
3. Aegivion verifies account identity and discovers supported resources.
4. Resources are normalized and relationships updated.
5. Deterministic detectors create findings with evidence, severity, and risk.
6. Findings may be correlated into incidents and attack paths.
7. AI explains findings using authorized, traceable context; it never invents evidence.
8. Response candidates pass deterministic safety policy.
9. Required approvals occur before execution.
10. The system verifies the result and records an audit trail.

## Functional requirements
- Authentication, sessions, organizations, membership, RBAC
- Tenant-scoped APIs and persistence
- AWS/Azure/GCP onboarding and resource collection
- Canonical inventory, relationships, and history
- Event ingestion, deduplication, retries, and dead-letter handling
- Findings, risk, correlation, incidents, attack paths, compliance
- AI/RAG explanations, recommendations, reports, and evaluation
- Runbooks, approval, allowlisted response, verification, audit
- Dashboards, health checks, operational visibility

## Non-functional requirements
Tenant isolation; least privilege; secret hygiene; fail-closed production persistence; idempotency and recovery; observability; accessible responsive UI; reproducible builds/migrations; evidence provenance and AI validation.

## Acceptance
A feature is accepted only when its code, tests, contracts, failure behavior, and relevant tenant authorization are verified. Live infrastructure validation is recorded separately.

## Out of scope unless approved
Unrestricted cloud mutation, destructive actions without controls, unsupported resources presented as fully supported, and exact future-attack predictions without evaluation.
