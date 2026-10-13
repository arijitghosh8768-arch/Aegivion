# Aegivion Documentation Hub

Welcome to the comprehensive documentation library for **Aegivion — Autonomous Explainable Cloud Security Intelligence Platform**.

---

## 📑 Core Specification Pack (01–17)

| # | Document | Purpose & Scope |
|---|---|---|
| **01** | [Product Requirements](01-product-requirements.md) | Platform goals, user roles, core journeys, and acceptance criteria |
| **02** | [System Architecture](02-system-architecture.md) | Core planes, data ingestion, microservices, and component boundaries |
| **03** | [API Contracts](03-api-contracts.md) | REST API endpoints, schemas, headers, and error shapes |
| **04** | [Event & Data Contracts](04-event-and-data-contracts.md) | Event schema validation, normalization, and idempotency |
| **05** | [Data Model & Migrations](05-data-model-and-migrations.md) | Database schemas, indexing, relations, and migration policy |
| **06** | [Security Threat Model](06-security-threat-model.md) | Assets, trust boundaries, threat taxonomy, and mitigations |
| **07** | [AI & RAG Specification](07-ai-rag-specification.md) | Retrieval-augmented generation, prompt security, and ground truth |
| **08** | [Testing & Acceptance](08-testing-and-acceptance.md) | Unit, integration, E2E testing strategies, and acceptance gates |
| **09** | [Deployment & Operations](09-deployment-and-operations.md) | Docker, Kubernetes, CI/CD pipelines, and health checks |
| **10** | [Current Project Status](10-current-project-status.md) | Verified implementation status vs. deferred cloud validation |
| **11** | [Module Ownership](11-module-ownership.md) | Team responsibility boundaries and service boundaries |
| **12** | [Agent & Remediation Policy](12-agent-and-remediation-policy.md) | Autonomous agents, safety gate rules, and human-in-the-loop policies |
| **13** | [Cloud Provider Matrix](13-cloud-provider-matrix.md) | Supported resource collection and parity across AWS, Azure, GCP |
| **14** | [AI Evaluation Plan](14-ai-evaluation-plan.md) | Benchmarks, hallucination checks, and explainability accuracy |
| **15** | [Research & Benchmark Plan](15-research-and-benchmark-plan.md) | Academic baselines, comparative metrics, and research criteria |
| **16** | [Development & Release Workflow](16-development-and-release-workflow.md) | Git branching, semantic versioning, and release checklist |
| **17** | [User & Admin Guide](17-user-and-admin-guide.md) | Onboarding instructions, cloud connection steps, and operational workflows |

---

## 🛠️ Technical Deep-Dives & Operational Runbooks

- **Architecture & System:**
  - [System Architecture Overview](SYSTEM_ARCHITECTURE.md)
  - [Technical Decisions Log](technical_decisions.md)
  - [Threat Model (Detailed)](THREAT_MODEL.md)
  - [Security Review](SECURITY_REVIEW.md)
- **API & Data:**
  - [API Reference](API_REFERENCE.md)
  - [API Versioning Strategy](API_VERSIONING.md)
  - [Database Schema Guide](DATABASE_SCHEMA.md)
  - [API & Event Contracts](contracts/)
- **Frontend & Environment Setup:**
  - [Next.js Dashboard Blueprint](NEXTJS_BLUEPRINT.md)
  - [Node.js Setup Guide](NODE_SETUP.md)
- **Deployment & Recovery:**
  - [Deployment Runbook](DEPLOYMENT.md)
  - [Disaster Recovery Plan](DISASTER_RECOVERY.md)
  - [Credentials & Secret Policy](CREDENTIALS.md)
- **Demonstrations & Surveys:**
  - [Demo Overview](DEMO.md) & [Demo Script](DEMO_SCRIPT.md)
  - [Explainability Survey](EXPLAINABILITY_SURVEY.md)
  - [Part 2 Security Intelligence Modules](part2/)

---

## 🧭 Documentation Integrity Rules
1. Replace assumptions and TBD items with evidence verified directly in the codebase.
2. Keep code completion, local test results, integration tests, live validation, and production readiness as clearly distinct statuses.
3. Never store credentials, tokens, live customer data, or secrets in any documentation files.
