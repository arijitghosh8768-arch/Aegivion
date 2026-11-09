# Aegivion Incident Response Runbook

This document provides actionable procedures for operational readiness, disaster recovery, emergency remediation, and credential management for the **Aegivion Autonomous Cloud Security Copilot** production infrastructure.

---

## 1. What to Do If the Render Backend Goes Down

### Symptoms
- Frontend displays `NetworkError` or `Failed to fetch`.
- Uptime monitoring alerts trigger (`/health` returning 502/503/timeout).
- Sentry / Datadog alerts report backend unavailability.

### Diagnostic & Recovery Steps
1. **Check Live Status & Deployment Logs**:
   - Access the Render Dashboard: [dashboard.render.com](https://dashboard.render.com).
   - Navigate to the `aegivion-backend` web service.
   - Inspect the **Logs** tab for fatal errors (e.g., OOM killer, PostgreSQL connection exhaustion, unhandled exceptions during worker initialization).

2. **Verify Database Connectivity**:
   - Run a direct database check from local CLI or Render Shell:
     ```bash
     psql "$DATABASE_URL" -c "SELECT 1;"
     ```
   - If PostgreSQL rejects connections (`too many connections`), verify connection pool settings in `app/database/session.py` (`pool_size=10, max_overflow=20`).

3. **Restart the Web Service**:
   - On the Render dashboard, click **Manual Deploy** > **Clear build cache & deploy** or **Restart Service**.
   - If triggered via Render CLI / API:
     ```bash
     curl -X POST https://api.render.com/v1/services/{service_id}/restart \
       -H "Authorization: Bearer $RENDER_API_KEY"
     ```

4. **Verify Service Health**:
   - Verify liveness endpoint:
     ```bash
     curl -i https://aegivion.onrender.com/health
     # Expected: HTTP 200 {"status": "ok", "success": true}
     ```
   - Verify readiness endpoint:
     ```bash
     curl -i https://aegivion.onrender.com/health/ready
     ```

---

## 2. How to Rotate RSA & JWT Keys

Aegivion utilizes RSA keypairs (`RS256`) for asymmetric JWT token signing, ensuring backend microservices and workers can verify identity without holding the private signing key.

### Rotation Procedure
1. **Generate a New RSA Keypair**:
   ```bash
   # Generate 2048-bit private RSA key
   openssl genrsa -out jwt_private_new.pem 2048

   # Extract public key in PEM format
   openssl rsa -in jwt_private_new.pem -pubout -out jwt_public_new.pem
   ```

2. **Stage in Key Management / Environment Secrets**:
   - Format key contents with single-line escaped newlines or base64:
     ```bash
     export JWT_PRIVATE_KEY="$(cat jwt_private_new.pem)"
     export JWT_PUBLIC_KEY="$(cat jwt_public_new.pem)"
     ```
   - Update `JWT_SECRET_KEY` / `JWT_PRIVATE_KEY` in:
     - Render Web Service Environment Variables
     - Vercel Environment Variables (`NEXT_PUBLIC_JWT_PUBLIC_KEY` if client-side validation is active)

3. **Graceful Dual-Key Validation Window**:
   - The auth middleware accepts both the new key and the previous public key for 24 hours to prevent sudden logout of active sessions.
   - Expire sessions gradually as refresh tokens are exchanged.

4. **Revoke Old Keys**:
   - Delete previous PEM files from secret managers.

---

## 3. How to Restore the Supabase / PostgreSQL Database

### Automated Backup Architecture
- Supabase / Managed PostgreSQL executes automated daily snapshots with Point-in-Time Recovery (PITR) up to 7 days.
- In addition, scheduled schema and table data dumps are stored in an encrypted offsite GCS/S3 cold bucket.

### Disaster Recovery Drill
1. **Assess Incident Scope**:
   - Determine target recovery timestamp before data corruption or accidental drop.

2. **Supabase PITR Restore (Fastest)**:
   - Log into Supabase Dashboard: `Project Settings` > `Database` > `Backups`.
   - Select **Point in Time Recovery**.
   - Select the timestamp (UTC) immediately preceding the incident.
   - Click **Restore to point in time**.

3. **Manual SQL Dump Restore Procedure**:
   ```bash
   # 1. Download latest verified cold backup
   aws s3 cp s3://aegivion-db-backups/daily/aegivion_backup_latest.sql.gz ./
   gunzip aegivion_backup_latest.sql.gz

   # 2. Restore into target database
   psql "$RESTORE_DATABASE_URL" < aegivion_backup_latest.sql

   # 3. Apply any incremental Alembic migrations
   alembic upgrade head
   ```

4. **Verify Schema & Vector Extension**:
   ```sql
   SELECT extname, extversion FROM pg_extension WHERE extname = 'vector';
   SELECT count(*) FROM cloud_assets;
   SELECT count(*) FROM security_findings;
   ```

---

## 4. How to Pause a Runaway or Misconfigured Scan

If a scan job causes rate-limiting on customer AWS APIs (`RequestLimitExceeded`), encounters infinite recursion, or loops unexpectedly:

### Emergency Scan Pause Procedure
1. **Via Aegivion UI**:
   - Navigate to **Cloud Accounts** (`/cloud-accounts`).
   - Click **Actions** on the target account > **Pause Discovery**.

2. **Via REST API (Admin Override)**:
   ```bash
   curl -X POST https://aegivion.onrender.com/api/v1/cloud-accounts/{account_id}/pause \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json"
   ```

3. **Direct Database Circuit Breaker (Emergency Fallback)**:
   If the API itself is unresponsive, kill active scan jobs directly in PostgreSQL:
   ```sql
   -- 1. Mark all active scanning jobs as CANCELLED
   UPDATE scan_jobs 
   SET status = 'CANCELLED', completed_at = NOW() 
   WHERE status = 'RUNNING';

   -- 2. Mark cloud account status as IDLE to halt worker pickup
   UPDATE cloud_accounts 
   SET status = 'IDLE' 
   WHERE status = 'SYNCING';
   ```

4. **Restart Automation Worker**:
   - The worker dynamically detects the `CANCELLED` status and terminates active collector threads immediately.
