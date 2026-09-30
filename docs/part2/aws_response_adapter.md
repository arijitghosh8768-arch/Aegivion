# Step 5B: AWS Response Adapter

The AWS Response Adapter implements Step 5B of the Aegivion controlled execution pipeline. It provides a highly restricted, precise translation from Aegivion's normalized `RESTRICT_IDENTITY_PRIVILEGE` execution contract to actual AWS IAM boto3 calls.

## Architectural Boundaries

* **No Intelligence**: The adapter makes no decisions. It merely maps pre-authorized, pre-validated contracts into provider-specific SDK calls.
* **Narrow Allowlist**: The adapter ONLY supports `RESTRICT_IDENTITY_PRIVILEGE` on AWS IAM Roles.
* **Deterministic Execution**:
    * `PrivilegeTarget(attachment_type="managed")` exactly maps to `iam:DetachRolePolicy`.
    * `PrivilegeTarget(attachment_type="inline")` exactly maps to `iam:DeleteRolePolicy`.
* **Tenant Isolation**: The adapter uses a session factory injected with the target `cloud_account_id` and the originating `organization_id` to obtain securely scoped AWS credentials.
* **No Arbitrary Commands**: The adapter blocks any arbitrary `boto3` parameters, script execution, or shell execution. 
* **Dry-Run Separation**: Dry run is guaranteed to return `simulated=True` and avoid all boto3 mutation calls, preserving testing safety.

## Validation Pipeline

1. Action is `RESTRICT_IDENTITY_PRIVILEGE`
2. Target provider is `aws`
3. Target identity type is `role`
4. Target ID is a valid AWS ARN (e.g. `arn:aws:iam::123456789012:role/RoleName`)
5. Extracted account ID matches `cloud_account_id` of target.
6. Privilege target contains valid structural combinations of `attachment_type` and `policy_arn`/`policy_name`.

If any of the above fails, the execution aborts safely with `ExecutionErrorCode.INVALID_TARGET`.

## Error Normalization

AWS raw exceptions are swallowed and converted into Aegivion structured `ExecutionErrorCode`:
* `AccessDenied` -> `PROVIDER_ERROR`
* `NoSuchEntity` -> `INVALID_TARGET`
* `Throttling` -> `PROVIDER_ERROR`
* `InvalidParameter` -> `INVALID_REQUEST`
* `ReadTimeoutError` -> `EXECUTION_TIMEOUT`

Raw credentials and raw boto3 traces are never logged.
