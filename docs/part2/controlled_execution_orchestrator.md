# Step 5A - Controlled Execution Orchestrator

## 1. Purpose
Step 5A bridges the gap between Step 4D (Safety Policy) and Step 5B (Cloud Response Adapters). It establishes an immutable Execution Contract, validates execution metadata, handles state transition safety, prevents idempotency conflict, and controls the execution lifecycle.

## 2. Security Boundary
This component forms the ultimate pre-mutation security boundary:
- Only explicitly whitelisted actions can proceed (`RESTRICT_IDENTITY_PRIVILEGE`).
- AI, LLM, or Chatbots are absolutely prohibited from initiating action executions.
- Step 4D policy outputs MUST map explicitly to execution inputs, preventing silent translation of DENY -> ALLOW.
- **NO REAL CLOUD MUTATION is implemented in Step 5A.** A `MockIdentityPrivilegeAdapter` serves as the test adapter.

## 3. Execution Contract
The `ExecutionRequest` contract mandates specific typed properties, notably `execution_id`, `organization_id`, `requested_by`, `source`, `finding_id`, `action`, `target`, `policy_decision`, `idempotency_key`, and `correlation_id`. A corresponding `ExecutionResult` is generated for transparency and tracing.

## 4. State Machine
Executions transition through a strict state machine: `CREATED -> VALIDATING -> ELIGIBILITY_PENDING -> APPROVAL_PENDING / READY -> EXECUTING -> EXECUTION_SUCCEEDED / EXECUTION_FAILED`. Illegal state jumping is structurally blocked.

## 5. Policy Binding
Each request binds rigorously to its Step 4D policy. Expired policies, missing policies, and `DENY` policies immediately halt execution logic.

## 6. Approval Handling
If a policy requires approval (`REQUIRE_APPROVAL`), the execution demands an explicit `APPROVAL` status and `approval_id`. If left `PENDING`, the execution sits in `APPROVAL_PENDING`. Rejections transition the execution to `REJECTED`.

## 7. Idempotency
An in-memory idempotency store blocks repeated executions sharing the same `idempotency_key` but divergent target metadata. Duplicate identical keys correctly replay the initial execution's result.

## 8. Tenant Isolation
Every operation verifies tenant-matching between the supplied `organization_id` context and the actual execution request context. Failure results in a rapid `TENANT_MISMATCH` fail-closed event.

## 9. Adapter Abstraction
A `CloudResponseAdapter` interface represents future integrations. It forces methods `supports()`, `validate_target()`, and `execute()`.

## 10. Mock Adapter
The `MockIdentityPrivilegeAdapter` validates target shape strictly against `target_type=identity` and simulates execution without interacting with real cloud identities or APIs. 

## 11. Dry Run
A `dry_run` flag passes execution validation but intercepts before the actual adapter fires, yielding a mocked success with `simulated=True` response metadata.

## 12. Timeout Behavior
Should an adapter raise a Timeout exception, the Orchestrator will record it as `EXECUTION_FAILED` with `EXECUTION_TIMEOUT`.

## 13. Cancellation
Requests can be cancelled while validating or pending approval. Once the adapter takes control (`EXECUTING`), cancellation assumes the adapter proceeds.

## 14. Failure Handling
Strict `ExecutionErrorCode` classifications define failures, e.g., `POLICY_EXPIRED`, `TENANT_MISMATCH`, or `APPROVAL_REJECTED`.

## 15. Logging
Structured logging is present across state transitions and failure reasons. Importantly, secrets, credentials, and API responses are omitted from output.

## 16. Correlation IDs
The inclusion of a `correlation_id` creates an unbroken lineage mapping the resulting action back to the finding, policy decision, and eventually the audit replay.

## 17. Why Automatic Retries are Disabled
Automatic retries are omitted because an underlying provider operation might have succeeded despite a timeout. Duplicating mutation could create unintended environmental degradation. Actual verification falls to Step 5D.

## 18. TOCTOU Considerations
Step 5A does not guarantee that the real cloud target remains unchanged between policy evaluation and execution. Final target-state validation is the responsibility of Step 5C.

## 19. What Step 5A intentionally does NOT implement
- Step 5A deliberately does not mutate AWS/Azure/GCP.
- Step 5A does not perform target-state precondition verification (reserved for 5C).
- Step 5A does not perform Digital Twin reconciliation (reserved for 5E).
- Step 5A does not accept free-form execution commands from an LLM.

## 20. Integration plan for 5B–5F
5B: Build AWS IAM-specific Cloud Response Adapters (for restriction).
5C: Introduce the `ExecutionPreconditionChecker` to query target state instantly before the adapter fires.
5D: Re-fetch AWS IAM state post-mutation.
5E: Map AWS states back into Digital Twin.
5F: Stream final execution metadata to an immutable replay store.
