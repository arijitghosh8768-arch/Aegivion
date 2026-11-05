# AEGIVION DATABASE MIGRATION PLAN

**Target Milestone:** M2 Execution & Verification  
**Objective:** Unify all persistence on PostgreSQL 15+ using SQLAlchemy 2.0 and Alembic.  
**Strategy:** Phased, Non-Destructive, Dual-Session Transition.

---

## 1. Target Architecture Overview

```
                                  +------------------------------------+
                                  |         FastAPI Endpoints          |
                                  |     (packages/backend/app/api)     |
                                  +-----------------+------------------+
                                                    |
                                          get_db / get_db_session
                                                    |
                                                    v
                      +-----------------------------+-----------------------------+
                      |                                                           |
                      v                                                           v
       +-------------------------------+                         +----------------------------------+
       |   Synchronous Repositories    |                         |  Asynchronous Processing Engines |
       |  (Auth, Assets, Findings,     |                         |  (Security Engine, Event Store,  |
       |   Incidents, Compliance)      |                         |   Agent Orchestrator, AI RAG)    |
       +---------------+---------------+                         +----------------+-----------------+
                       |                                                          |
                       v                                                          v
       +-------------------------------+                         +----------------------------------+
       |   SQLAlchemy 2.0 Sync Session |                         |  SQLAlchemy 2.0 Async Session    |
       |   (psycopg2 / scoped_session) |                         |  (asyncpg / async_sessionmaker)  |
       +---------------+---------------+                         +----------------+-----------------+
                       |                                                          |
                       +-----------------------------+----------------------------+
                                                     |
                                                     v
                                       +----------------------------+
                                       |     PostgreSQL 15+ DB      |
                                       |  (Single Source of Truth)  |
                                       +----------------------------+
```

---

## 2. Model Migration & Normalization Plan

All models currently subclassing `app.database.base.BaseModel` will be migrated to inherit from a unified SQLAlchemy declarative base (`app.database.base.Base`).

### 2.1 Base Class Definition (`app/database/base.py`)
```python
from datetime import datetime, timezone
import uuid
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID

Base = declarative_base()

class BaseModel(Base):
    __abstract__ = True

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(UUID(as_uuid=True), nullable=True)
    updated_by = Column(UUID(as_uuid=True), nullable=True)

    def dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
```

### 2.2 Models to Restore to SQLAlchemy Declarative:
1. **Core Identity & RBAC:**
   - `User` (`app/models/user.py`)
   - `Organization` (`app/models/organization.py`)
   - `Role` (`app/models/role.py`)
   - `OrganizationMember` (`app/models/organization_member.py`)
   - `AuthSession` (`app/models/auth_session.py`)
   - `Invitation` (`app/models/invitation.py`)
2. **Cloud Infrastructure & Digital Twin:**
   - `CloudAccount` / `CloudAccountV2` (`app/models/cloud_account.py`)
   - `CloudAsset`, `SecurityGroupAsset`, `IAMUserAsset`, `S3BucketAsset`, `EC2InstanceAsset` (`app/models/cloud.py`)
   - `Relationship`, `AssetRelationship` (`app/models/cloud.py`)
   - `ScanJob` (`app/models/cloud.py`)
3. **Security Findings & Incidents:**
   - `Finding` (`security/models/finding.py`)
   - `Incident` (`app/models/incident.py`)
   - `SecurityEvent` (`app/models/security_event.py`)
   - `Vulnerability` (`app/models/vulnerability.py`)
4. **Governance, Compliance & Automation:**
   - `ComplianceControlResult` (`app/models/compliance.py`)
   - `GeneratedReport`, `SecurityPostureSnapshot` (`app/models/reports.py`)
   - `Runbook` (`app/models/runbook.py`)
   - `AgentHeartbeat`, `ResponseExecution`, `PendingApproval` (`app/models/automation.py`)
   - `OrgSettings` (`app/models/org_settings.py`)

---

## 3. Session & Connection Management

To support both legacy synchronous repositories and modern async processing workers:
1. **Sync Engine & Session (`app/database/session.py`):**
   - Configured via `DATABASE_URL` (using `psycopg2` or `psycopg`).
   - Standard `sessionmaker(bind=engine, autocommit=False, autoflush=False)`.
   - `get_db()` FastAPI dependency provides a standard `Session` with automatic context manager commit/rollback on exception.
2. **Async Engine & Session (`app/database/postgres_foundation.py`):**
   - Configured via `create_async_engine(DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"))`.
   - Injected via `get_db_session()` for async workers, event processors, and RAG pipelines.

---

## 4. Alembic Migration Strategy

### Step 1: Re-bind Alembic `target_metadata`
Update `packages/backend/alembic/env.py`:
```python
from app.database.base import Base
target_metadata = Base.metadata
```

### Step 2: Harmonize Existing Migrations
The repository already contains foundational migrations:
- `810b4615d5cd`: `users`, `organizations`, `roles`, `findings`, `knowledge_base`
- `8f0ab4b64e3b`: `cloud_assets`, `security_groups`, `iam_users`, `s3_buckets`, `ec2_instances`
- `9f0bc4b64e3c`: `persistent_events`, `requeue_records`, `agent_states`, `worker_states`, `detection_contexts`, `attack_states`
- `a0001_add_knowledge_models`: `knowledge_documents`, `knowledge_chunks`

### Step 3: Generate Consolidation Revision
Generate a new migration `b0001_reconcile_all_models.py` to fill missing tables and indexes:
- `incidents`
- `organization_members`
- `sessions` / `auth_sessions`
- `invitations`
- `org_settings`
- `compliance_control_results`
- `generated_reports`
- `runbooks`
- `response_executions`
- `pending_approvals`
- `security_events`

---

## 5. Multi-Tenant Isolation Enforcement

Tenant isolation must be enforced at both the ORM level and database level:
1. **Mandatory `organization_id` Column:**
   Every tenant-owned table must include an indexed `organization_id` foreign key referencing `organizations.id` with `ON DELETE CASCADE`.
2. **Composite Indexes:**
   Add composite indexes `ix_<table_name>_org_<key>` for high-throughput queries (e.g., `(organization_id, status)`, `(organization_id, resource_id)`).
3. **Repository Guard Rails:**
   All repository methods will require explicit `organization_id` parameter filtering.
4. **PostgreSQL Row Level Security (RLS) Phase 2 Readiness:**
   Enable `ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY;` with tenant policies for direct PostgREST/Supabase or multi-tenant database connection pooling.

---

## 6. Data Migration, Backup & Rollback Plan

### Pre-Migration Backup:
1. **MongoDB Dump:** Execute `mongodump --uri="$MONGODB_URI" --out="./backup_mongo_$(date +%Y%m%d)"`.
2. **Supabase Export:** Export all tables as JSON/CSV using pg_dump or REST script.

### Data Migration Script (`scripts/migrate_mongo_to_postgres.py`):
1. Connects to source MongoDB database and target PostgreSQL database.
2. Migrates in topological foreign-key order:
   1. `organizations`
   2. `roles`
   3. `users`
   4. `organization_members`
   5. `cloud_accounts`
   6. `cloud_assets` & relationships
   7. `findings` & `incidents`
   8. `audit_logs`
3. Generates UUIDs for documents lacking standard UUID formats.
4. Validates row counts and field integrity post-copy.

### Rollback Strategy:
- The migration is designed as a **dual-read/write capable or non-destructive switch**.
- The existing `app/database/__init__.py` code can remain available behind a feature flag (`USE_LEGACY_MONGO=true`) during initial testing.
- If PostgreSQL encounter unrecoverable failures during rollout, setting `USE_LEGACY_MONGO=true` immediately reverts routing back to `MongoSQLSession`.

---

## 7. Execution Checklist for Phase 3 (Pending Approval)

- [ ] Restore SQLAlchemy declarative inheritance in `packages/backend/app/database/base.py`.
- [ ] Restore SQLAlchemy declarative models across `packages/backend/app/models/*.py`.
- [ ] Implement robust sync `SessionLocal` and `get_db` in `packages/backend/app/database/session.py`.
- [ ] Update `TwinPersistenceRepository` and `SecurityEventRepository` to support SQLAlchemy `Session` alongside Supabase client.
- [ ] Generate and test Alembic migration revision.
- [ ] Run full backend API and regression test suites.

