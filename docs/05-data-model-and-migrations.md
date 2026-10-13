# Data Model and Migrations

## Domains to inventory
Users, identities, organizations, memberships, invitations, sessions, cloud accounts, assets, relationships, asset history, events, event-processing state, findings, incidents, attack paths, agent/worker state, leases, retries, DLQ records, runbooks, approvals, executions, verification, audit, and AI knowledge/evaluation metadata where applicable.

## PostgreSQL requirements
- Versioned, reviewable migrations tested against PostgreSQL.
- Indexes for tenant-scoped lookups, queue claiming, status/time queries, and common relationships.
- Foreign keys, uniqueness constraints, nullability, and retention/deletion policies.
- Explicit transaction boundaries.
- `FOR UPDATE SKIP LOCKED` for appropriate concurrent queue claims.
- Lease expiry and fencing/ownership checks for stale workers.
- Persistent and audited retries/requeues.
- Tenant filtering enforced at persistence boundaries.
- Production fails closed if PostgreSQL is required but unavailable or misconfigured.

## Validation
The current project report says PostgreSQL code is complete while live validation is deferred. Verify current code and test migrations, concurrency, restart/recovery, and connection pooling against a real PostgreSQL instance before claiming live validation.
