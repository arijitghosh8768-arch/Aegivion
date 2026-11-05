# AEGIVION DATABASE ARCHITECTURE AUDIT

**Audit Date:** November 2026  
**Milestone:** M2 — Database Architecture Reconciliation  
**Audit Scope:** `packages/backend/app/database/`, `app/models/`, `app/repositories/`, `alembic/`, `packages/security/engine/persistence/`  
**Git Baseline Commit:** `de15be7045cbad2d0228a7d19b04ca388980a92b`

---

## 1. Executive Summary

An exhaustive audit of the Aegivion persistence layer reveals that the repository is currently operating under a **quad-split architecture** with divergent persistence patterns:
1. **MongoDB Atlas / PyMongo** via an in-house SQL-to-Mongo emulator (`MongoSQLSession` and `MockQuery`).
2. **Supabase REST Client** (`supabase-py`) providing postgREST table operations (`.table().select().execute()`) mapped on top of or alongside MongoDB.
3. **PostgreSQL + SQLAlchemy (Async)** designed for the Security Engine Event Store (`PostgresEventStore`, `PersistentEventModel`, `agent_states`, etc.) and AI RAG knowledge chunks (`KnowledgeDocument`, `KnowledgeChunk`).
4. **Legacy SQLAlchemy Declarative Models & Alembic Migrations** originally created for PostgreSQL but partially orphaned during commit `a47edcdd` when models were converted into plain Python dictionaries to accommodate MongoDB.

This divergence introduces impedance mismatches, prevents relational transactional integrity, circumvents native foreign key constraints, and compromises multi-tenant isolation guarantees.

---

## 2. Inventory of Current Persistence Subsystems

### Subsystem 1: MongoSQLSession & MockQuery Emulation Layer
* **Location:** `packages/backend/app/database/__init__.py` (Lines 101–285), `app/database/base.py`
* **Mechanism:**
  - Instantiates `pymongo.MongoClient(MONGODB_URI)`.
  - Implements `BaseModelMeta` which intercepts attribute lookups and returns `MockField(key)` to allow pseudo-SQL expressions such as `User.email == req.email`.
  - Implements `MockQuery` supporting `.filter()`, `.filter_by()`, `.order_by()`, `.first()`, `.all()`, and `.count()`.
  - Implements `MongoSQLSession` with `.add()`, `.commit()`, `.rollback()`, `.delete()`, `.refresh()`, and `.flush()`.
* **Runtime Reality:**
  - Injected via FastAPI's `get_db` dependency in 23 out of 27 API routes in `packages/backend/app/api/v1/`.
  - In unit tests (`packages/backend/tests/conftest.py`), `get_db` is overridden with `mongomock.MongoClient()["aegivion_test"]`.
* **Severe Limitations:**
  - `commit()` does not offer ACID transaction guarantees across documents without explicit MongoDB replica set transactions.
  - `rollback()` simply clears in-memory lists `_new_objects` and `_queried_objects`; it cannot undo executed DB mutations.
  - Foreign keys, cascading deletes, joins, and database-enforced unique constraints are completely bypassed in memory.

### Subsystem 2: Supabase PostgREST Client
* **Location:** `packages/backend/app/database/supabase_client.py`, `app/repositories/twin_persistence_repository.py`, `app/repositories/security_event_repository.py`, `app/cloud/*/sync.py`
* **Mechanism:**
  - Connects using `SUPABASE_URL` and `SUPABASE_KEY` via `create_client`.
  - Performs direct table RPC/REST queries: `.table("cloud_assets").select("*").eq(...)`.
  - Intertwined with `MongoSQLSession`: `MongoSQLSession.commit()` checks `SUPABASE_MAPPING`; if a model matches (e.g., `CloudAsset`, `Finding`, `Incident`), it attempts to upsert directly to Supabase PostgREST tables.
* **Runtime Reality:**
  - Cloud collector synchronization pipelines (`aws/sync.py`, `azure/sync.py`, `gcp/sync.py`) store normalized assets directly into Supabase.
  - `TwinPersistenceRepository` operates exclusively against `supabase.table(...)` or an object implementing the same interface.
  - Fails closed when `SUPABASE_URL` or `SUPABASE_KEY` is not present unless patched/mocked.

### Subsystem 3: PostgreSQL Foundation & Security Persistence Engine
* **Location:** `packages/backend/app/database/postgres_foundation.py`, `packages/security/engine/persistence/postgres/`
* **Mechanism:**
  - Built on SQLAlchemy 2.0 async engine (`create_async_engine`) and `async_sessionmaker` with `postgresql+asyncpg`.
  - Defines strict declarative models in `packages/security/engine/persistence/postgres/models.py`:
    - `PersistentEventModel` (`persistent_events`)
    - `RequeueRecordModel` (`requeue_records`)
    - `PersistentAgentStateModel` (`agent_states`)
    - `PersistentWorkerStateModel` (`worker_states`)
    - `PersistentDetectionContextModel` (`detection_contexts`)
    - `PersistentAttackStateModel` (`attack_states`)
  - Backed by an ACID-compliant event store (`PostgresEventStore`) with atomic claims, lease timeouts, fencing tokens, and dead-letter queues (DLQ).
  - Production fail-closed rule in `packages/security/engine/config.py`:
    ```python
    if config.environment == "production" and config.backend != "postgres":
        raise ValueError("Production environment must explicitly select 'postgres' backend. Fail-closed.")
    ```

### Subsystem 4: Alembic Migrations & PostgreSQL Declarative Schema
* **Location:** `packages/backend/alembic/`
* **Current Versions:**
  - `810b4615d5cd_initial_migration.py`: Initial relational schema (`knowledge_base`, `organizations`, `roles`, `users`, `audit_logs`, `conversations`, `findings`, `cloud_accounts`).
  - `8f0ab4b64e3b_add_cloud_assets_tables.py`: Asset graph tables (`cloud_assets`, `ec2_instances`, `iam_users`, `s3_buckets`, `security_groups`).
  - `9f0bc4b64e3c_add_persistence_engine_tables.py`: Engine tables (`persistent_events`, `requeue_records`, `agent_states`, `worker_states`, `detection_contexts`, `attack_states`).
  - `a0001_add_knowledge_models.py`: RAG Knowledge tables (`knowledge_documents`, `knowledge_chunks` with pgvector support).
* **Disconnect:**
  - Alembic `env.py` points to `from app.models import Base; target_metadata = Base.metadata`.
  - Because `Base` in `app/database/base.py` was converted to a mock class (`class Base: metadata = None`) during commit `a47edcdd`, Alembic autogeneration against `Base.metadata` is currently disabled/broken.

---

## 3. Detailed Model-by-Model Persistence Audit

| Model Class | Python File | Inherits From | Target Table / Collection | Active Production Store | Active Test Store |
|---|---|---|---|---|---|
| `User` | `app/models/user.py` | `BaseModel` | `users` | MongoDB / Supabase | `mongomock` |
| `Organization` | `app/models/organization.py` | `BaseModel` | `organizations` | MongoDB / Supabase | `mongomock` |
| `Role` | `app/models/role.py` | `BaseModel` | `roles` | MongoDB / Supabase | `mongomock` |
| `OrganizationMember`| `app/models/organization_member.py` | `BaseModel` | `organization_members` | MongoDB / Supabase | `mongomock` |
| `AuthSession` / `Session` | `app/models/auth_session.py` | `BaseModel` | `sessions` | MongoDB / Supabase | `mongomock` |
| `Invitation` | `app/models/invitation.py` | `BaseModel` | `invitations` | MongoDB / Supabase | `mongomock` |
| `OrgSettings` | `app/models/org_settings.py` | `BaseModel` | `orgsettings` | MongoDB | `mongomock` |
| `CloudAccountV2` | `app/models/cloud_account.py` | `BaseModel` | `cloud_accounts_v2` | MongoDB / Supabase | `mongomock` |
| `CloudAsset` | `app/models/cloud.py` | `BaseModel` | `cloud_assets` | Supabase / MongoDB | `mongomock` |
| `SecurityGroupAsset`| `app/models/cloud.py` | `BaseModel` | `security_groups` | Supabase / MongoDB | `mongomock` |
| `IAMUserAsset` | `app/models/cloud.py` | `BaseModel` | `iam_users` | Supabase / MongoDB | `mongomock` |
| `S3BucketAsset` | `app/models/cloud.py` | `BaseModel` | `s3_buckets` | Supabase / MongoDB | `mongomock` |
| `EC2InstanceAsset` | `app/models/cloud.py` | `BaseModel` | `ec2_instances` | Supabase / MongoDB | `mongomock` |
| `ScanJob` | `app/models/cloud.py` | `BaseModel` | `scan_jobs` | Supabase / MongoDB | `mongomock` |
| `Relationship` | `app/models/cloud.py` | `BaseModel` | `asset_relationships` | Supabase / MongoDB | `mongomock` |
| `Finding` | `security/models/finding.py` | `BaseModel` | `findings` | Supabase / MongoDB | `mongomock` |
| `Incident` | `app/models/incident.py` | `BaseModel` | `incidents` | Supabase / MongoDB | `mongomock` |
| `ComplianceControlResult` | `app/models/compliance.py` | `BaseModel` | `compliancecontrolresults` | MongoDB | `mongomock` |
| `GeneratedReport` | `app/models/reports.py` | `BaseModel` | `generatedreports` | MongoDB | `mongomock` |
| `Runbook` | `app/models/runbook.py` | `BaseModel` | `runbooks` | Supabase / MongoDB | `mongomock` |
| `AgentHeartbeat` | `app/models/automation.py` | `BaseModel` | `agentheartbeats` | Supabase / MongoDB | `mongomock` |
| `ResponseExecution` | `app/models/automation.py` | `BaseModel` | `responseexecutions`| Supabase / MongoDB | `mongomock` |
| `PendingApproval` | `app/models/automation.py` | `BaseModel` | `pendingapprovals` | Supabase / MongoDB | `mongomock` |
| `SecurityEvent` | `app/models/security_event.py` | `BaseModel` | `security_events` | Supabase REST | Mock Supabase |
| `PersistentEventModel` | `security/.../postgres/models.py` | `PostgresBase` | `persistent_events` | PostgreSQL | Skipped if no PG |
| `KnowledgeDocument` | `app/models/knowledge.py` | `PostgresBase` | `knowledge_documents` | PostgreSQL | Skipped if no PG |
| `KnowledgeChunk` | `app/models/knowledge.py` | `PostgresBase` | `knowledge_chunks` | PostgreSQL | Skipped if no PG |

---

## 4. Repository Pattern Audit

The repository implementations exhibit three conflicting patterns:

1. **Standard `MongoSQLSession` Consumer Repositories:**
   - `AssetRepository`, `AuthRepository`, `CloudAccountRepository`, `ComplianceRepository`, `FindingRepository`, `IncidentRepository`, `InvitationRepository`, `OrganizationRepository`.
   - Constructor: `def __init__(self, db)` where `db` is expected to provide `.query(Model).filter(...).all()/.first()`.
   - Compatibility: Fully compatible with standard SQLAlchemy `Session` API when declarative models are used!

2. **Supabase PostgREST Direct Repositories:**
   - `SecurityEventRepository`: `def __init__(self, db_client)` calls `self.table = self.db_client.table("security_events")`.
   - `TwinPersistenceRepository`: `def __init__(self, db, organization_id: str)` invokes `.table("cloud_assets").select().eq()`.

3. **Pure SQLAlchemy Async Repositories:**
   - `PostgresEventStore`, `PostgresAgentStateRepository`, `PostgresDetectionContextRepository`, `PostgresAttackStateRepository`.
   - Constructor: Takes `async_sessionmaker` and issues native async SQL queries (`select(PersistentEventModel).where(...)`).

---

## 5. Architectural Flaws & Root Deficiencies

1. **Transaction Isolation Violation:**
   `MongoSQLSession` has no actual rollback mechanism for committed data and does not support transaction savepoints or isolation levels. If an error occurs midway through a multi-step operation (e.g. creating an organization, creating a user, assigning an admin role), partial mutations remain persisted.
2. **Double-Write Fragility:**
   `MongoSQLSession.commit()` attempts to dual-write to Supabase via REST calls during the commit loop. If Supabase is unreachable or times out, the MongoDB write succeeds while the Supabase write silently fails (caught by a generic `except Exception: pass`), causing severe data drift.
3. **Dual Base Class Fragmentation:**
   Two distinct base classes exist: `BaseModel` (mock class in `app/database/base.py`) and `PostgresBase` (SQLAlchemy `declarative_base()` in `app/models/postgres_base.py`). This prevents Alembic from managing schema state as a cohesive entity.
4. **Lack of Enforced Foreign Keys:**
   Relationships such as `User.organization_id -> Organization.id` and `Finding.resource_id -> CloudAsset.resource_id` are stored merely as loose string attributes without DB-level cascading or referential integrity.

---

## 6. Audit Verdict

The current architecture is unstable for enterprise production. However, because the primary application repositories (`AuthRepository`, `AssetRepository`, `FindingRepository`, etc.) were originally coded to the SQLAlchemy `.query(Model)` API, **re-unifying under standard PostgreSQL + SQLAlchemy will restore architectural integrity without breaking API layer contracts.**

