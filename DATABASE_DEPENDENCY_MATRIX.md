# AEGIVION DATABASE RISK REGISTER

**Audit Date:** November 2026  
**Milestone:** M2 — Database Architecture Reconciliation  
**Risk Assessment Standard:** ISO 31000 / OWASP Top 10 Database & Cloud Security

---

## 1. Risk Matrix Overview

| Risk ID | Category | Description | Likelihood | Impact | Severity | Mitigation Strategy |
|---|---|---|---|---|---|---|
| **R-01** | Data Integrity | `MongoSQLSession.commit()` lacks ACID cross-collection transaction guarantees. | High | High | **CRITICAL** | Reconcile to PostgreSQL standard transactions with atomic commits and explicit rollbacks. |
| **R-02** | Data Drift | Dual-writing to MongoDB and Supabase causes unsynchronized state on network failure. | High | High | **CRITICAL** | Eliminate dual-write layer; designate PostgreSQL as the single authoritative source of truth. |
| **R-03** | Schema Drift | Alembic migration autogeneration broken due to mock `Base.metadata`. | High | Medium | **HIGH** | Restore unified SQLAlchemy declarative `Base.metadata` in `app/database/base.py`. |
| **R-04** | Security | Foreign key constraints and cascading deletes not enforced in database engine. | Medium | High | **HIGH** | Re-establish explicit PostgreSQL Foreign Keys with `ON DELETE CASCADE` / `RESTRICT`. |
| **R-05** | Multi-Tenancy | Data leakage across tenant boundaries if queries fail to apply `organization_id`. | Medium | Critical | **CRITICAL** | Implement tenant-scoped base repository classes and prepare PostgreSQL RLS policies. |
| **R-06** | Operational | Dual-dependency on external MongoDB Atlas and Supabase credentials. | High | Medium | **HIGH** | Reduce third-party dependencies by consolidating on standard self-hosted or cloud PostgreSQL. |
| **R-07** | Performance | `MockQuery` filtering executes full collection scan or naive Python filtering. | Medium | High | **HIGH** | Leverage PostgreSQL B-Tree indexes and composite tenant indexes for fast queries. |
| **R-08** | Migration Downtime| Switching persistence could disrupt active API routes or cause regressions. | Medium | Medium | **MEDIUM** | Dual-session feature flag (`USE_LEGACY_MONGO`) with seamless fallback during migration verification. |

---

## 2. Detailed Risk Deep Dives

### R-01: Lack of ACID Transaction Guarantees in `MongoSQLSession`
* **Root Cause:** In `packages/backend/app/database/__init__.py`, `MongoSQLSession.commit()` iterates over `self._new_objects` and `self._queried_objects`, executing individual PyMongo `replace_one` statements without starting a replica set session transaction (`client.start_session()`).
* **Exploitation / Failure Scenario:** If creating an invitation or executing automated remediation fails at step 2 of 3, step 1 is never rolled back, leaving orphaned or corrupted state in the database.
* **Remediation:** Transitioning to PostgreSQL provides native multi-statement ACID transactions wrapped in SQLAlchemy session contexts (`with session.begin(): ...`).

### R-02: Double-Write Failures (MongoDB vs. Supabase)
* **Root Cause:** Lines 225–230 of `packages/backend/app/database/__init__.py` attempt to upsert records into Supabase PostgREST tables within a generic `try...except Exception: pass` block.
* **Consequence:** If the Supabase REST endpoint returns a 500 or rate limits, the MongoDB document is updated but the Supabase table is not. The system enters an undetectable split-brain condition.
* **Remediation:** Remove the Supabase REST upsert hook from `commit()` and establish PostgreSQL as the sole system of record.

### R-03: Broken Alembic Schema Versioning
* **Root Cause:** When `BaseModel` was decoupled from SQLAlchemy in commit `a47edcdd`, `Base.metadata` was replaced with `None`. Alembic's `target_metadata` can no longer detect schema diffs across application models.
* **Consequence:** Any schema changes made in code must be manually handcrafted in Alembic without migration safety checks or type verification.
* **Remediation:** Harmonize all models under a single declarative base inheriting from `sqlalchemy.orm.declarative_base()`.

### R-05: Multi-Tenant Data Leakage Risk
* **Root Cause:** Because collections have no database-level isolation policies, a developer writing `db.query(CloudAsset).all()` without an explicit `.filter(CloudAsset.organization_id == user_org_id)` leaks cross-tenant assets.
* **Remediation:**
  1. Enforce mandatory tenant assertions in repository layer methods (as implemented in `TwinPersistenceRepository._assert_tenant`).
  2. Implement database-level PostgreSQL Row-Level Security (RLS) policies scoped to `current_setting('app.current_org_id')`.

---

## 3. Contingency & Fallback Strategy

To ensure zero risk of blocking sprint progress or college submission readiness:
1. **No Code Destructive Action:** The legacy `MongoSQLSession`, `MockQuery`, and `app/database/__init__.py` implementations will NOT be deleted or mutated during Phase 2.
2. **Feature Flag Isolation:** The reconciled PostgreSQL persistence engine can be toggled via `DATABASE_BACKEND=postgres|mongo` (defaulting safely to existing behavior until approved).
3. **Automated Regression Safety Net:** The existing 1,576 passing tests (Algo 1, 2, 3, backend, and security) must pass identically under both test configurations before final sign-off.

