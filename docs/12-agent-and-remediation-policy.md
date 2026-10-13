# Agent and Remediation Policy

## Control flow
Detection → Recommendation → Safety Validation → Approval Decision → Preconditions → Allowlisted Action → Cloud Adapter → Verification → Audit → Twin Reconciliation.

## Rules
- Unsupported actions fail closed.
- Missing/contradictory evidence is not permission to act.
- Approval does not bypass policy, preconditions, or allowlists.
- Production/critical assets require stricter policy and approval.
- Prefer reversible, minimum-impact actions.
- Never execute arbitrary shell commands or model-generated cloud API calls.
- Record actor, tenant, reason, target, policy result, approval, execution result, verification, and timestamps.

## Runbook schema
Trigger, conditions, target scope, allowlisted action, evidence/confidence requirements, blast-radius limits, approval policy, preconditions, timeout, retry behavior, verification, rollback/compensation if available, and audit fields.

A successful API response is not sufficient. Verify actual state and rerun relevant detection/path analysis before declaring success.
