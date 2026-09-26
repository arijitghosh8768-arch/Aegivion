## Step 16 — Repository Boundary Audit

### 🟢 Repository-safe
- `auth.py`
- `cloud_accounts.py` (reads migrated)
- `assets.py` (reads migrated)
- `findings.py` (reads migrated, exceptions for scan write paths)
- `incidents.py` (reads migrated, exceptions for AI correlation bulk queries)
- `events.py` (reads migrated)
- `invitations.py` (reads migrated)

### 🟡 Read migrations required
- `org_settings.py` (reads `OrgSettings` via `db.query`)
- `automation.py` (reads `Runbook` via `db.query`)
- `relationships.py` (reads `AssetRelationship` via `db.query`)
- `explain.py` / `chat.py` (reads `OrgSettings`)

### 🔴 Tenant-sensitive (High Risk)
- **`reports.py`**: Executes `db.query(Finding).all()` and `db.query(CloudAsset).all()` and attempts to filter by `.organization_id`, which does not exist on `Finding` or `CloudAsset`. This breaks tenant boundaries and is a critical leak/failure point.
- **`risk.py`**: Direct `supabase.table("cloud_assets")` and `supabase.table("findings")` calls.
- **`topology.py`**: Direct `supabase.table("cloud_assets")` calls.
- **`compliance.py`**: Reads `ComplianceControlResult` directly via `db.query`.

### 🔵 Write-path only
- `google_auth.py`
- `cloud_accounts.py` (insertions)
- `events.py` (ingest_event)

### ⚙️ System/internal
- `admin.py` (system admin route)
- `integration.py` (scanner webhooks, bulk metrics)

### 🟣 Special/raw database access
- `graph.py`
- `history.py` (snapshots, sync quality, evaluations)
- `remediation.py` (validation checks, validation queries)

### 🎯 Next migration target
**`reports.py`** 
It aggregates data from multiple models (`Finding`, `Incident`, `CloudAsset`) but bypasses the newly created `FindingRepository` and `AssetRepository`. It manually attempts to filter by `getattr(f, 'organization_id')`, which we know from Step 13 does not exist natively on `Finding` or `CloudAsset` objects, leading to cross-tenant data leaks or entirely broken aggregations. Migrating `reports.py` to use our established repositories is the highest priority.
