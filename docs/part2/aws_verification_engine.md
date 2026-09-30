# Step 5D: Verification Engine

The AWS Verification Engine is Aegivion's final, authoritative arbiter of remediation success.

A primary principle of autonomous security execution is that **submitting an API call is not remediation; observing the resulting secure state is remediation.** Therefore, the successful completion of Step 5B (`AWSResponseAdapter`) merely prompts this distinct layer to prove the work.

## Core Directives

*   **Read-Only Operations:** Like the Precondition Check (5C), the Verification Engine relies purely on `get`, `list`, and `describe` operations.
*   **Decoupled Proof:** It explicitly re-queries AWS state rather than trusting the adapter's return status.
*   **Intent Verification:** It maps Aegivion's execution contract (`expected_privilege_state`) to the post-action expectation. If the action was `RESTRICT_IDENTITY_PRIVILEGE`, the expected post-state is that the policy is *absent*.

## Result Taxonomy

The engine enforces five highly specific outcomes (`VerificationStatus`):

| Status | Meaning |
| :--- | :--- |
| **`VERIFIED`** | Live cloud state strictly matches the expected post-action secure state (e.g., policy is missing). |
| **`FAILED`** | The API operation succeeded, but the environment did not change as expected (e.g., policy is still attached). Indicates a provider propagation delay or logic error. |
| **`DRIFT_DETECTED`** | The environment structurally changed (e.g., the target IAM Role was deleted entirely), making it impossible to verify the action's specific intent. |
| **`PROVIDER_ERROR`** | AWS returned a transient/authorization error preventing Aegivion from checking state (e.g., `AccessDenied`, `Throttling`). |
| **`INSUFFICIENT_EVIDENCE`** | The execution contract lacked the necessary scope to know what to look for, or the action is not supported for verification. |

## Contract Flow

```text
       5A - Orchestrator
              │
       5B - Mutating AWS Adapter
              │
           (Delay)
              │
       5D - AWS Verification Engine
              │
    ┌─────────┼─────────┐
    │         │         │
VERIFIED    FAILED    DRIFT
    │
    ▼
5E - Digital Twin Update
```
