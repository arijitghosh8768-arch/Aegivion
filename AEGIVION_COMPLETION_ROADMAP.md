# AEGIVION — FASTEST COMPLETION ROADMAP

**Audit Date**: November 5, 2026  
**Auditor**: Senior Software Architect, Engineering Manager, QA Lead, DevSecOps Engineer  
**Objective**: Finish Aegivion as quickly as reasonably possible without sacrificing functionality, security, or reliability.

---

## 1. SEQUENTIAL COMPLETION PHASES OVERVIEW

```
┌────────────────────────────────────────────────────────────────────────┐
│                      AEGIVION COMPLETION TIMELINE                      │
├─────────┬──────────────────────────────────────────┬───────────────────┤
│ Phase   │ Description                              │ Estimated Time    │
├─────────┼──────────────────────────────────────────┼───────────────────┤
│ Phase 1 │ Core Backend Defect Fixes & Missing APIS │ 3 - 4 Days        │
│ Phase 2 │ Database Unification (PostgreSQL Shift)  │ 4 - 5 Days        │
│ Phase 3 │ Real AI & RAG Engine Implementation      │ 3 - 4 Days        │
│ Phase 4 │ Frontend Contract Alignment & Wiring     │ 4 - 5 Days        │
│ Phase 5 │ Cloud Response Adapters & Verification   │ 3 - 4 Days        │
│ Phase 6 │ Docker, Deployment & Observability       │ 2 Days            │
│ Phase 7 │ End-to-End System Testing & CI/CD        │ 3 Days            │
│ Phase 8 │ Security Audit & Production Hardening    │ 2 Days            │
├─────────┴──────────────────────────────────────────┴───────────────────┤
│ TOTAL ESTIMATED TIMELINE:                          │ 24 - 29 Days      │
│                                                    │ (~4.5 - 5 Weeks)  │
└────────────────────────────────────────────────────┴───────────────────┘
```

---

## 2. PHASE-BY-PHASE EXECUTION PLAN

### PHASE 1: CORE BACKEND DEFECT FIXES & MISSING ENDPOINTS
* **Primary Objective**: Eliminate all runtime 500 crashes and 404 missing routes required by the frontend and test suites.
* **Exact Tasks**:
  1. Fix `packages/backend/app/api/v1/assets.py`: Inject `current_user: Dict[str, Any] = Depends(get_current_user)` into `get_asset(asset_id, ...)` line 42.
  2. Fix `packages/backend/app/api/v1/chat.py`: Replace `current_user.org_id` with `user_org_id` line 102.
  3. Create `packages/backend/app/api/v1/correlations.py` implementing `GET /api/v1/correlations` using `DetectionCorrelationEngine`. Register in `api/v1/__init__.py`.
  4. Create `packages/backend/app/api/v1/memory.py` implementing `GET /api/v1/memory` returning historical incident patterns. Register in `api/v1/__init__.py`.
  5. Add `@router.patch("/{finding_id}")` alias in `packages/backend/app/api/v1/findings.py` routing to `update_finding_status`.
  6. Fix `test_agent_automation_e2e_pipeline.py` import by exporting `MemoryEventStore` from `security/engine/persistence/memory.py`.
  7. Fix `MockLLMProvider` signature in `packages/backend/tests/integration/test_rag_ai_pipeline.py`.
  8. Fix 85 normalizer failures in `algo/detection/cloud_destruction/normalizer.py` and batch ingestors.
* **Files Affected**:
  * `packages/backend/app/api/v1/assets.py`
  * `packages/backend/app/api/v1/chat.py`
  * `packages/backend/app/api/v1/findings.py`
  * `packages/backend/app/api/v1/correlations.py` (new)
  * `packages/backend/app/api/v1/memory.py` (new)
  * `packages/backend/app/api/__init__.py`
  * `packages/security/engine/persistence/memory.py`
  * `packages/backend/tests/integration/test_rag_ai_pipeline.py`
  * `packages/algo/detection/cloud_destruction/normalizer.py`
* **Dependencies**: None.
* **Estimated Effort**: 3 – 4 Days (24 – 32 Hours).
* **Acceptance Criteria**:
  * `GET /api/v1/assets/{id}` returns 200 with valid asset schema.
  * `GET /api/v1/correlations` returns 200 with valid threat chains.
  * `GET /api/v1/memory` returns 200 with valid pattern history.
  * `PATCH /v1/findings/{id}` updates status without 404.
  * All 550 tests in `algo/detection/cloud_destruction/` pass (100% pass rate).
* **Required Tests**: Pytest across `backend/tests`, `algo/tests`, `algo/detection/cloud_destruction/tests`.

---

### PHASE 2: DATABASE UNIFICATION & POSTGRESQL MIGRATION
* **Primary Objective**: Retire the MongoDB/Supabase custom shim layer (`MongoSQLSession`) and unify the persistence layer on real PostgreSQL.
* **Exact Tasks**:
  1. Refactor `packages/backend/app/database/__init__.py`: Connect `SessionLocal` and `get_db()` to real PostgreSQL engine via `asyncpg` / `psycopg2`.
  2. Migrate all models in `packages/backend/app/models/` (`user.py`, `cloud.py`, `incident.py`, `finding.py`, `runbook.py`, `automation.py`, `reports.py`) from `app.database.base.BaseModel` to inherit from `PostgresBase` (SQLAlchemy declarative base).
  3. Ensure all models define table names, foreign keys, and indexes matching PostgreSQL standards.
  4. Run `alembic revision --autogenerate` to produce a consolidated, clean schema migration.
  5. Apply migrations against PostgreSQL container and verify schema consistency.
  6. Enforce strict `organization_id` tenant filtering across all repository classes (`AssetRepository`, `FindingRepository`, `IncidentRepository`).
* **Files Affected**:
  * `packages/backend/app/database/__init__.py`
  * `packages/backend/app/database/postgres_foundation.py`
  * `packages/backend/app/models/*.py` (all 20 model files)
  * `packages/backend/app/repositories/*.py`
  * `packages/backend/alembic/versions/*.py`
* **Dependencies**: Phase 1 completed.
* **Estimated Effort**: 4 – 5 Days (32 – 40 Hours).
* **Acceptance Criteria**:
  * Backend boots up with PostgreSQL `DATABASE_URL` with zero MongoDB references.
  * `alembic upgrade head` runs cleanly without manual SQL execution.
  * Database operations support transactions, rollbacks, and foreign key cascades.
  * Un-scoped bulk queries in `incidents.py` and `findings.py` are eliminated.
* **Required Tests**: `test_postgres_persistence.py`, `test_postgres_concurrency.py`, `test_tenant_isolation.py`.

---

### PHASE 3: REAL AI & RAG ENGINE IMPLEMENTATION
* **Primary Objective**: Replace dummy mock strings with real LLM reasoning and real vector search.
* **Exact Tasks**:
  1. Implement real `OpenAIProvider` using official `openai` SDK with streaming support.
  2. Implement real `GeminiProvider` using official `google-genai` SDK.
  3. Wire API keys from environment variables (`OPENAI_API_KEY`, `GEMINI_API_KEY`).
  4. Replace `SecurityKnowledgeRetriever._simulate_vector_search()`: Connect to PostgreSQL `pgvector` extension (using the 384-dim embeddings from `LocalEmbeddingService`).
  5. Populate vector store with MITRE ATT&CK techniques, CIS AWS Benchmark rules, and remediation playbooks.
  6. Connect `IncidentReasonerService` and `ReportGeneratorService` to the active LLM provider.
  7. Implement JSON-repair fallback so LLM outputs always conform to the frontend schema.
* **Files Affected**:
  * `packages/ai/services/llm_provider.py`
  * `packages/ai/services/rag.py`
  * `packages/ai/engine/rag_skeleton.py`
  * `packages/backend/app/services/embedding_service.py`
  * `packages/backend/app/api/v1/chat.py`
  * `packages/ai/knowledge_base/sample_entries.json`
* **Dependencies**: Phase 2 completed.
* **Estimated Effort**: 3 – 4 Days (24 – 32 Hours).
* **Acceptance Criteria**:
  * `/api/v1/ai/chat` receives user prompt, performs vector search against `pgvector`, injects grounded evidence, and returns structured JSON with real LLM analysis.
  * Zero static dummy strings returned.
  * Strict groundedness checks prevent hallucination of non-existent cloud resources.
* **Required Tests**: `test_rag_ai_pipeline.py`, `test_embedding_service.py`, and new RAG accuracy evaluation scripts.

---

### PHASE 4: FRONTEND CONTRACT ALIGNMENT & WIRING
* **Primary Objective**: Eliminate all broken contracts, hardcoded mock values, and simulated `setTimeout` logic on the UI.
* **Exact Tasks**:
  1. Update `cloud-accounts/page.tsx`: Parse `data.accounts` and read `name` and `provider_account_id`.
  2. Update `prediction/page.tsx`: Reconcile trend data schema with `/v1/risk/intelligence` and wire "72h forecast" button.
  3. Update `detection-engine/page.tsx`: Change status patch URL to `/v1/findings/${id}/status`; wire "Auto-fix" button to trigger remediation generation.
  4. Update `threat-correlation/page.tsx`: Wire to newly implemented `/v1/correlations` endpoint.
  5. Update `security-memory/page.tsx`: Wire to newly implemented `/v1/memory` endpoint.
  6. Update `remediation/page.tsx`: Replace client-side `setTimeout` with `POST /v1/automation/approvals/{id}/approve`.
  7. Update `reports/page.tsx`: Wire template generation to `POST /v1/reports/generate`; implement real CSV export.
  8. Update `settings/page.tsx`: Replace hardcoded `"org-1"` with dynamic `user.organization_id`; fetch users and audit logs from backend APIs.
  9. Update `AskAegivionAI` in `right-panels.tsx`: Replace local `answer()` from `lib/data/ai.ts` with API call to `/v1/ai/chat`.
  10. Update `risk/page.tsx` & `heavy-attack-graph.tsx`: Fetch dynamic scores from `/v1/risk/intelligence` and render nodes from `/v1/attack-graph`.
* **Files Affected**:
  * `packages/frontend/app/(dashboard)/cloud-accounts/page.tsx`
  * `packages/frontend/app/(dashboard)/prediction/page.tsx`
  * `packages/frontend/app/(dashboard)/detection-engine/page.tsx`
  * `packages/frontend/app/(dashboard)/threat-correlation/page.tsx`
  * `packages/frontend/app/(dashboard)/security-memory/page.tsx`
  * `packages/frontend/app/(dashboard)/remediation/page.tsx`
  * `packages/frontend/app/(dashboard)/reports/page.tsx`
  * `packages/frontend/app/(dashboard)/settings/page.tsx`
  * `packages/frontend/components/dashboard/right-panels.tsx`
  * `packages/frontend/components/dashboard/metric-cards.tsx`
  * `packages/frontend/components/topology/heavy-attack-graph.tsx`
* **Dependencies**: Phases 1, 2, and 3 completed.
* **Estimated Effort**: 4 – 5 Days (32 – 40 Hours).
* **Acceptance Criteria**:
  * Zero 404 network errors in browser console during end-to-end navigation.
  * All dashboard screens display live data from PostgreSQL.
  * Approving an action on the Remediation page triggers a network mutation and updates status.
* **Required Tests**: Manual frontend smoke testing across all 18 routes.

---

### PHASE 5: CLOUD RESPONSE ADAPTERS & ACTION VERIFICATION
* **Primary Objective**: Expand automated remediation beyond identity role restriction to network ingress and storage protections.
* **Exact Tasks**:
  1. Extend `AWSResponseAdapter` in `packages/security/engine/aws_response_adapter.py`:
     * Support `REVOKE_SECURITY_GROUP_INGRESS` (revoke `0.0.0.0/0` SSH/RDP rules via Boto3 EC2 client).
     * Support `BLOCK_S3_PUBLIC_ACCESS` (apply `PutPublicAccessBlock` via Boto3 S3 client).
  2. Extend `AWSVerificationEngine` in `packages/security/engine/aws_verification_engine.py`:
     * Verify Security Group ingress rules are revoked.
     * Verify S3 bucket public access blocks are active.
  3. Connect `/api/v1/automation/approvals/{id}/approve` to real `ApprovalManager` execution.
  4. Ensure all mutations record immutable provenance audit entries in PostgreSQL.
* **Files Affected**:
  * `packages/security/engine/aws_response_adapter.py`
  * `packages/security/engine/aws_verification_engine.py`
  * `packages/security/engine/approval_manager.py`
  * `packages/backend/app/api/v1/automation.py`
* **Dependencies**: Phase 2 completed.
* **Estimated Effort**: 3 – 4 Days (24 – 32 Hours).
* **Acceptance Criteria**:
  * Executing an approved Security Group remediation successfully removes risky CIDR rules and receives `VERIFIED` status from `AWSVerificationEngine`.
  * Precondition checker halts execution if resource state has drifted.
* **Required Tests**: `test_aws_response_adapter.py`, `test_aws_verification_engine.py`, `test_approval_workflow.py`.

---

### PHASE 6: DOCKER, DEPLOYMENT & OBSERVABILITY
* **Primary Objective**: Enable single-command containerized local and staging deployment.
* **Exact Tasks**:
  1. Create standard `packages/frontend/Dockerfile` matching Next.js standalone output.
  2. Update `packages/frontend/next.config.js` with `output: 'standalone'` for minimal container size.
  3. Validate `docker compose up --build` across all 8 services:
     * `postgres`, `redis`, `qdrant`, `backend`, `security`, `ai`, `algo`, `frontend`.
  4. Test Nginx reverse proxy configuration (`nginx.conf`) routing `/api/` to backend and `/` to frontend.
  5. Verify Prometheus scraping on `backend:8000/metrics`.
  6. Sanitize repository `.env` by removing hardcoded credentials and moving to `.env.example`.
* **Files Affected**:
  * `packages/frontend/Dockerfile` (new)
  * `packages/frontend/next.config.js`
  * `docker-compose.yml`
  * `docker-compose.prod.yml`
  * `aegivion/.env`
  * `aegivion/.env.example`
* **Dependencies**: Phases 1 through 5 completed.
* **Estimated Effort**: 2 Days (16 Hours).
* **Acceptance Criteria**:
  * `docker compose up --build` succeeds with zero errors.
  * All services report healthy on `/health`.
  * No secret keys or plaintext passwords committed in git tree.
* **Required Tests**: Container smoke test and Prometheus scrape verification.

---

### PHASE 7: END-TO-END INTEGRATION TESTING & CI/CD
* **Primary Objective**: Establish continuous automated regression validation and high test coverage.
* **Exact Tasks**:
  1. Configure Vitest and `@testing-library/react` in `packages/frontend/package.json`.
  2. Implement unit and component tests for core dashboard screens (`threats`, `assets`, `compliance`).
  3. Update `.github/workflows/ci.yml`:
     * Add `packages/algo` to CI matrix.
     * Update frontend test step to run `npm test` and `npm run build`.
     * Spin up PostgreSQL service container for integration tests.
  4. Run full repository test suite across all packages.
* **Files Affected**:
  * `packages/frontend/package.json`
  * `packages/frontend/vitest.config.ts` (new)
  * `packages/frontend/__tests__/*.test.tsx`
  * `.github/workflows/ci.yml`
* **Dependencies**: Phase 6 completed.
* **Estimated Effort**: 3 Days (24 Hours).
* **Acceptance Criteria**:
  * GitHub Actions CI passes 100% on pull requests across all 4 services.
  * Zero skipped or ignored tests.
* **Required Tests**: Full pytest suite + Vitest frontend suite.

---

### PHASE 8: FINAL SECURITY & PRODUCTION-READINESS AUDIT
* **Primary Objective**: Final validation of tenant boundaries, rate limits, secret rotation, and operational runbooks.
* **Exact Tasks**:
  1. Run automated cross-tenant penetration tests (verifying Org A cannot read Org B assets or events).
  2. Validate rate limiting via SlowAPI on auth and scan endpoints.
  3. Validate secure headers (`HSTS`, `Content-Security-Policy`, `X-Frame-Options`).
  4. Produce production deployment checklist and operator runbook.
* **Files Affected**:
  * `packages/backend/app/middleware/security.py`
  * `packages/backend/app/core/rate_limit.py`
  * `docs/DEPLOYMENT.md`
* **Dependencies**: Phases 1 through 7 completed.
* **Estimated Effort**: 2 Days (16 Hours).
* **Acceptance Criteria**:
  * Zero high/critical vulnerabilities on static analysis.
  * Tenant isolation verified on 100% of API endpoints.
  * Production sign-off achieved.

