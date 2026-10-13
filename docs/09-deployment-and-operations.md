# Deployment and Operations Runbook

## Environments
Separate local, CI/test, staging, and production configuration, secrets, data, and cloud permissions.

## Deployment checklist
- Pin/review runtime and dependencies.
- Build reproducible frontend/backend/worker artifacts.
- Validate required configuration without printing values.
- Run migrations as a controlled step.
- Verify health/readiness and dependency connectivity.
- Apply least-privilege network and cloud permissions.
- Configure TLS, secure cookies, CORS, trusted hosts, and rate limits.
- Configure structured logs, metrics, traces, alerts, and correlation IDs.
- Verify backups and conduct a restore test.
- Define rollout/rollback and schema compatibility.
- Keep response actions safely gated until approved for the environment.

## Runbooks
Database outage/pool exhaustion; worker crash/lease recovery; queue backlog/DLQ growth; cloud throttling/expired credentials; model outage; partial response failure; suspected tenant exposure; secret compromise; restore/disaster recovery.

Record live-validation environment, non-sensitive identifiers, tests, results, limitations, and approver. Never include access keys/tokens.
