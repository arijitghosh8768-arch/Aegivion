# AEGIVION DATABASE DEPENDENCY MATRIX

**Date:** November 2026  
**Milestone:** M2 — Database Architecture Reconciliation  
**Scope:** Complete map of runtime endpoints, services, repositories, and persistence engines.

---

## 1. API Route Persistence Dependency Map

Every API route file in `packages/backend/app/api/v1/` and its persistence engine dependencies:

| API Route File | Primary Endpoints | Database Injected | Repositories Used | Database Operations Performed |
|---|---|---|---|---|
| `admin.py` | `/api/v1/admin/orgs`, `/users` | `get_db` (`MongoSQLSession`) | `OrganizationRepository` | `query(User)`, `query(OrgSettings)`, `query(Role)` |
| `assets.py` | `/api/v1/assets`, `/{id}` | `get_db` (`MongoSQLSession`) | `AssetRepository` | `asset_repo.list_assets()`, `asset_repo.get_by_id()` |
| `auth.py` | `/api/v1/auth/login`, `/register`, `/me` | `get_db` (`MongoSQLSession`) | `AuthRepository` | `auth_repo.get_user_by_email()`, `auth_repo.create_user()` |
| `automation.py` | `/api/v1/automation/rules`, `/executions`| `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(Runbook)`, `query(ResponseExecution)`, `query(PendingApproval)` |
| `brief.py` | `/api/v1/brief/executive` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(Finding).all()`, `query(CloudAsset).all()` |
| `chat.py` | `/api/v1/chat` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(OrgSettings).filter(...)` |
| `cloud_accounts.py` | `/api/v1/cloud-accounts` | `get_db` (`MongoSQLSession`) | `CloudAccountRepository`, `supabase` | `cloud_repo.list()`, `supabase.table("cloud_accounts").insert()` |
| `compliance.py` | `/api/v1/compliance/frameworks`, `/scan` | `get_db` (`MongoSQLSession`) | `ComplianceRepository` | `compliance_repo.get_summary()`, `compliance_repo.list_results()` |
| `context.py` | `/api/v1/context/{id}` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(CloudAsset)`, `query(Finding)`, `query(AssetRelationship)` |
| `correlations.py` | `/api/v1/correlations` | `get_db` (`MongoSQLSession`) | `FindingRepository` | `finding_repo.list_by_organization()` |
| `events.py` | `/api/v1/events/ingest`, `/recent` | `get_db` (`MongoSQLSession`) | `SecurityEventRepository` (via `supabase`) | `event_repo.create()`, `event_repo.get_recent_by_organization()` |
| `explain.py` | `/api/v1/explain/finding/{id}` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(Finding)`, `query(CloudAsset)`, `query(OrgSettings)` |
| `findings.py` | `/api/v1/findings`, `/{id}` | `get_db` (`MongoSQLSession`) | `FindingRepository`, `OrganizationRepository` | `finding_repo.list()`, `finding_repo.update()`, `query(CloudAsset)` |
| `google_auth.py` | `/api/v1/auth/google` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(User)`, `query(Organization)`, `query(Role)` |
| `graph.py` | `/api/v1/graph/topology` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(CloudAsset)`, `query(AssetRelationship)` |
| `history.py` | `/api/v1/history/snapshots`, `/suppressions`| `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(AssetSnapshot)`, `query(SecurityRiskSnapshot)`, `query(FindingSuppression)` |
| `incidents.py` | `/api/v1/incidents`, `/{id}` | `get_db` (`MongoSQLSession`) | `IncidentRepository` | `incident_repo.list()`, `incident_repo.get()`, `incident_repo.create()` |
| `integration.py` | `/api/v1/integration/stats` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(CloudAsset).count()`, `query(Finding).count()` |
| `invitations.py` | `/api/v1/invitations` | `get_db` (`MongoSQLSession`) | `InvitationRepository`, `OrganizationRepository` | `invitation_repo.create()`, `invitation_repo.get_by_token()` |
| `memory.py` | `/api/v1/memory` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(KnowledgeDocument)`, `query(KnowledgeChunk)` |
| `org_settings.py`| `/api/v1/settings/org` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(OrgSettings).filter(...)` |
| `relationships.py`| `/api/v1/relationships` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(AssetRelationship).all()` |
| `remediation.py` | `/api/v1/remediation/actions`, `/validate` | `get_db` (`MongoSQLSession`) | None (Direct Query) | `query(Finding)`, `query(RemediationValidation)` |
| `reports.py` | `/api/v1/reports`, `/posture` | `get_db` (`MongoSQLSession`) | `FindingRepository`, `IncidentRepository`, `AssetRepository` | Multi-repo aggregation, `query(GeneratedReport)` |
| `risk.py` | `/api/v1/risk/score` | `get_db` (`MongoSQLSession`) | `AssetRepository`, `FindingRepository`, `IncidentRepository` | Risk calculation over assets, findings, and incidents |
| `topology.py` | `/api/v1/topology/nodes` | `get_db` (`MongoSQLSession`) | `AssetRepository` | `asset_repo.list_assets()` |
| `twin.py` | `/api/v1/twin/stats`, `/sync` | `get_db` (`MongoSQLSession`) | `AssetRepository`, `SecurityEventRepository`, `supabase` | `asset_repo.count()`, `supabase.table("identities").select()` |

---

## 2. Background Workers & Synchronizers Dependency Map

| Component | File Path | Current Persistence Dependency | Operations Performed |
|---|---|---|---|
| `AutomationWorker` | `app/workers/automation_worker.py` | `MongoSQLSession(mongo_db)` | Evaluates automated runbook rules, updates `ResponseExecution` |
| `CloudtrailWorker` | `app/workers/cloudtrail_worker.py` | `supabase`, `db_session` | Ingests real-time events via `SecurityEventIngestionService` |
| `AWS Sync Engine` | `app/cloud/aws/sync.py` | `supabase`, `TwinPersistenceRepository` | Upserts discovered AWS assets into `cloud_assets` & `asset_versions` |
| `Azure Sync Engine`| `app/cloud/azure/sync.py` | `supabase`, `TwinPersistenceRepository` | Upserts discovered Azure resources into `cloud_assets` |
| `GCP Sync Engine` | `app/cloud/gcp/sync.py` | `supabase`, `TwinPersistenceRepository` | Upserts discovered GCP resources into `cloud_assets` |

---

## 3. Security Engine & Persistence Engine Map

| Component | File Path | Persistence Engine | Storage Strategy |
|---|---|---|---|
| `PostgresEventStore` | `packages/security/engine/persistence/postgres/` | PostgreSQL (Async) | Stores `PersistentEventModel`, leases, and dead-letter records |
| `PostgresAgentStateRepository` | `packages/security/engine/persistence/postgres/` | PostgreSQL (Async) | Tracks agent lifecycle state (`STARTING`, `RUNNING`, `STOPPED`) |
| `PostgresDetectionContextRepository` | `packages/security/engine/persistence/postgres/` | PostgreSQL (Async) | Caches active threat detection state and event context per tenant |
| `PostgresAttackStateRepository` | `packages/security/engine/persistence/postgres/` | PostgreSQL (Async) | Tracks multi-stage attack paths and lateral movement progression |

---

## 4. Test Suite Persistence Mocking Map

| Test Suite | File / Directory | Mocking Mechanism |
|---|---|---|
| Backend Base Tests | `packages/backend/tests/conftest.py` | `mongomock.MongoClient()["aegivion_test"]` into `MongoSQLSession` |
| Security Event Replay | `packages/backend/tests/part2/test_part2_v5_e2e_replay.py` | `unittest.mock.patch('supabase')` |
| Postgres Event Store | `packages/backend/tests/part2/test_postgres_event_store.py` | Requires live Postgres or skips if unavailable |
| Postgres Persistence Int | `packages/backend/tests/integration/test_postgres_persistence.py` | Requires live Postgres or skips if unavailable |
| Algo 1, 2, 3 Engines | `packages/algo/.../tests/` | In-memory models and event fixtures (no database required) |

