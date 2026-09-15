# REAL_AUTOMATION_IMPLEMENTATION_AUDIT

## 1. Existing Automation Page
- Located at `packages/frontend/app/(dashboard)/automation/page.tsx`.
- Recently modified to connect to the backend (via `/v1/automation/rules`) using `@tanstack/react-query`.
- Replaced the static/mocked UI with a real database-driven list of runbooks (showing `id`, `name`, `desc`, `trigger`, `action`, `runs`, `lastRun`, `enabled`).
- Added Role-Based Access Control (RBAC): UI conditionally hides the Create Rule button and replaces toggle switches with read-only badges if the user lacks the `organization_admin` or `Super Admin` role.
- Still missing deeper integration for true "executions", "pending approvals", "agent status", "timeline", and a detailed 6-step runbook creation flow (currently a simple 4-field modal).

## 2. Existing Backend Capabilities & APIs
- **Automation API**: `packages/backend/app/api/v1/automation.py` contains CRUD endpoints:
  - `GET /v1/automation/rules`
  - `POST /v1/automation/rules`
  - `PATCH /v1/automation/rules/{id}/toggle`
- **RBAC**: Implemented in `packages/backend/app/core/rbac.py` using Casbin, enforcing the `manage_automation` permission on mutating endpoints.
- **Remediation API**: `packages/backend/app/api/v1/remediation.py` exists but is heavily mocked. It provides mock fallback data to ensure the UI looks rich. It needs to be scrubbed of mocks to act on real finding data.
- **Security Engine**: `packages/security/engine` exists with files like `risk_engine.py`, `rule_engine.py`, `attack_paths.py`, `executor.py`, `detection_pipeline.py`. This proves the backend has an architectural foundation for evaluating triggers and risk, but needs to be hooked up to the automation response flow.
- **Audit Logs**: Exist in `packages/backend/app/models/audit_log.py`.

## 3. Existing Database Tables
- **MongoDB**: Used for Auth, Users, Organizations, and now `AutomationRule` instances via the custom `OrmBaseModel`.
- **Findings/Incidents**: Present in `packages/security/schema/finding.py`, `packages/backend/app/models/incident.py`.
- Missing tables for: `verifications`, `agent_runs`, `response_decisions`, `response_executions`.

## 4. Existing Cloud Response Adapters
- Adapters exist in `packages/backend/app/cloud/` for `aws`, and placeholders for others. Need to verify that the "allowlisted actions" can be mapped cleanly to these adapters.

## 5. Agent Functionality
- There is no `agent` directory in `packages/backend/app`, but there is a `scanner.py` service and a `security/engine` framework. A continuous "Agent Worker" model is not yet structurally isolated as independent workers (Discovery, Detection, Investigation, Response, Verification).

## 6. Implementation Plan
**PHASE 0: Audit** (Complete - this document)
**PHASE 1:** Expand the `AutomationPage` Overview (Agent Status, Executions, KPIs) fetching from real endpoints. Remove all remaining frontend mocks.
**PHASE 2:** Runbook Database Expansion (add Modes, Provider, Safety Policy, Severity to the `AutomationRule` model).
**PHASE 3:** Agent Status Integration (create `GET /v1/automation/agent/status` representing the security engine scanner state).
**PHASE 4:** Response Candidates & Approvals Workflow (add endpoints and UI for pending approvals).
**PHASE 5:** Safe Allowlisted Cloud Execution.
**PHASE 6:** Verification system.
**PHASE 7:** Minimum-impact response integration.
**PHASE 8:** Simulation UI.
**PHASE 9:** AI Explanation layer (using `ai.services`).
**PHASE 10:** Realtime data (SSE/WebSockets).
**PHASE 11:** Super Admin vs Org Admin scope enforcement.
**PHASE 12:** Hardening & Test Verification.
