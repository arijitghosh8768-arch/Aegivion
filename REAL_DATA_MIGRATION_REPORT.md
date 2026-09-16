# Aegivion Real-Data Migration Audit Report
**Phase:** Milestone 0 (Complete Demo Data Audit)
**Date:** September 2026

## 1. CURRENT STATE
The Aegivion platform currently operates using a custom MongoDB ORM wrapper (`app/database/base.py`) that stores *all* platform data (Authentication, Organizations, Runbooks, Assets, and Findings) in a single MongoDB cluster. There is currently no active Supabase/PostgreSQL integration. Some parts of the UI still rely on gracefully degrading to mock/demo data if the backend is disconnected, and multi-cloud collectors are partially written but not fully wired to store real data continuously.

## 2. DEMO DATA INVENTORY
- **Frontend Fallbacks:** Discovered mock states in `invite/accept/page.tsx` (`demo@company.com`) and `chat-panel.tsx` (mock LLM responses if backend is missing).
- **Backend Tests & Mocks:** Test files (`test_day10.py`, `test_day11.py`, `test_day13.py`) use extensive `MockEC2Client`, `MockS3Client`, and hardcoded `mock_finding` / `mock_asset` objects.
- **Topology & Dashboard Data:** Previously stripped out most static JSON, but the backend `v1/assets` and `v1/topology` APIs currently pull from the MongoDB ORM which may contain seed/fixture data generated during development rather than real-time live syncs.
- **Mock Telemetry Directory:** Referenced in documentation (`data/` directory), but it appears to have been largely cleaned up in earlier phases.

## 3. MONGODB STATUS
- **Active & Online:** Connected via `MONGODB_URI` in `.env`.
- **Current Usage:** Stores *everything* (`Users`, `OrgSettings`, `Invitations`, `CloudAsset`, `Finding`, `Runbook`, `AgentHeartbeat`, etc.).
- **Required Action:** We must strictly restrict MongoDB usage to Auth and Identity models (`Users`, `Organizations`, `Roles`, `Sessions`, `Invitations`). All other ORM models must be migrated away.

## 4. SUPABASE STATUS
- **Status:** NON-EXISTENT.
- **Database Gap:** There is no Supabase URL in `.env`, no `supabase` pip package in the backend, and no PostgreSQL SQLAlchemy models configured.
- **Required Action:** Introduce `supabase-py` (or async `postgrest`) and SQLAlchemy/Psycopg2. Map all Cloud Security data models (`CloudAsset`, `Finding`, `Incident`, `ResponseExecution`, etc.) to this new connection.

## 5. AWS STATUS
- **Collectors Built:** `EC2Collector`, `S3Collector`, `SecurityGroupCollector` exist under `packages/backend/app/cloud/aws/`.
- **Status:** They utilize `boto3`, but they are currently only triggered via test scripts or isolated API calls, rather than a continuous 24/7 background worker that syncs to Supabase.
- **Required Action:** Wire these collectors into a Background Sync Worker that writes normalized data into the new Supabase Postgres database.

## 6. AZURE STATUS
- **Status:** NOT STARTED. There is no `app/cloud/azure` directory.
- **Required Action:** Will be implemented after the AWS vertical slice is completed and verified.

## 7. GCP STATUS
- **Status:** Shell exists (`app/cloud/gcp`), but needs complete validation and implementation of actual GCP Python API clients (`google-cloud-compute`, `google-cloud-resourcemanager`).

## 8. MIGRATION MAP

| Data Type | Current Source | Current API | Current Frontend Consumer | New Data Source |
| :--- | :--- | :--- | :--- | :--- |
| Users & Auth | MongoDB | `/v1/auth`, `/v1/admin` | Login, Invite, Team | **MongoDB** (Keep) |
| Organizations | MongoDB | `/v1/admin/orgs` | Settings, Admin | **MongoDB** (Keep) |
| Cloud Accounts | MongoDB | `/v1/cloud-accounts` | `/cloud-accounts` | **Supabase (PostgreSQL)** |
| Assets & Config | MongoDB | `/v1/assets` | `/assets`, `/cloud-topology` | **Supabase (PostgreSQL)** |
| Findings/Events | MongoDB | `/v1/findings` | `/risk`, `/threats` | **Supabase (PostgreSQL)** |
| Automation Execs | MongoDB | `/v1/automation/*` | `/automation` | **Supabase (PostgreSQL)** |

## 9. SECURITY RISKS
- **Secret Management:** Currently, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are hardcoded in the `.env` file directly. When we build the Cloud Accounts UI, we must encrypt these or use secure credential vaults before storing them in Supabase, preventing plaintext storage.
- **Tenant Isolation:** Because we are splitting databases (Auth in Mongo, Data in Supabase), we must ensure that the `organization_id` derived from the Mongo session token is securely and flawlessly passed into every single Supabase Postgres query. Cross-database joins are impossible, so app-level enforcement is critical.

## 10. IMPLEMENTATION ORDER
As requested, I will strictly follow the provided sequence:
1. **Milestone 0:** Audit Complete (This Report).
2. **Milestone 1:** Supabase Integration (Set up Postgres connection, migrate Asset/Finding/CloudAccount schemas).
3. **Milestone 2 (First Vertical Slice):** AWS Test Account → AWS Connection → AWS IAM/EC2/VPC Collector → Normalizer → Supabase → Assets API → Frontend Assets Page.
4. **Milestone 3:** Azure Implementation.
5. **Milestone 4:** GCP Implementation.
6. **Milestone 5:** Asset History & Real Event Ingestion.

---
**Ready to begin Milestone 1 (Supabase Setup & Schema Finalization).**
