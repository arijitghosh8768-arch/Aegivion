# Step 5C: Execution Safety / Precondition Check

The Precondition Check (Step 5C) is the final read-only guardrail before Aegivion commits an AWS IAM mutation. It strictly verifies the current real-world state of the cloud environment to prevent Time-Of-Check to Time-Of-Use (TOCTOU) vulnerabilities.

## The TOCTOU Problem

Between the time Aegivion analyzes a threat, predicts an attack path, evaluates policy, and orchestrates the execution, the underlying cloud environment may have drifted. For instance, a human administrator could have already removed the dangerous policy from the compromised role.

If Aegivion blindly executes a mutation without checking the current state, it might operate on inaccurate assumptions, risking unintended consequences or failing silently.

## Precondition Checker Architecture

The `AWSPreconditionChecker` acts as a read-only state verification engine. 

It receives the exact `ExecutionRequest` approved by the policy engine and checks it against live AWS state.

### Core Principles

1.  **Read-Only Integrity**: The Precondition Checker strictly uses non-mutating `Get`, `List`, and `Describe` API calls (e.g., `list_attached_role_policies`). It NEVER executes state-altering operations.
2.  **Structural Validation**: It verifies the target configuration (account ID, ARN formats, attachment types) before communicating with AWS.
3.  **Action Consistency**: It only processes known, safe execution actions (`RESTRICT_IDENTITY_PRIVILEGE`).
4.  **Expected vs. Actual Comparison**: It explicitly queries the real-time presence of the exact `PrivilegeTarget` specified and matches it against the `PrivilegeExpectedState`.

### Evaluation Outcomes

The checker yields a `PreconditionResult` with one of the following statuses:

*   `PASS`: The runtime state exactly matches the expected state. Execution may proceed safely to Step 5B.
*   `FAIL_DRIFT`: The runtime state differs from expected (e.g., policy already detached, role deleted). Execution is safely ABORTED.
*   `FAIL_VALIDATION`: The contract contains malformed or unverified information. Execution is ABORTED.
*   `FAIL_PROVIDER_ERROR`: An unexpected AWS API error occurred (e.g., `AccessDenied`). Execution is safely ABORTED (fail-closed).

## Interaction with Execution Orchestrator

This module fits neatly between Step 5A (Orchestrator) and Step 5B (AWS Response Adapter).
Only when `PreconditionResult.status == PASS` does the orchestrator hand off the execution to the AWS Adapter.
