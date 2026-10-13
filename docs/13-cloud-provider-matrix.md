# Cloud Provider Capability Matrix

Use this as an evidence-backed inventory; adapter existence alone does not prove full provider coverage.

| Capability | AWS | Azure | GCP | Evidence/gaps |
|---|---|---|---|---|
| Identity verification | Reported implemented | Reported implemented | Reported implemented | Recheck code/tests |
| Compute collection | Reported implemented | Reported implemented | Reported implemented | List exact resource types |
| Network/security collection | Reported implemented | Reported implemented | Reported implemented | Verify routes, subnets, firewalls, NSGs/SGs |
| IAM relationships | Scope to verify | Scope to verify | Scope to verify | Document supported policy forms |
| Storage configuration | Reported implemented | Reported implemented | Reported implemented | List checks/unsupported cases |
| Pagination/throttling | Verify | Verify | Verify | Add bounded retries/rate-limit tests |
| Least-privilege read-only access | Intended | Intended | Intended | Validate with dedicated identities |
| Response mutations | Narrow allowlist reported | Do not assume supported | Do not assume supported | Fail closed unless explicitly tested |
| Live validation | Deferred | Deferred | Deferred | Record actual run evidence |

For each resource type record collector, permissions, mapping, relationships, pagination, errors, unit/integration tests, and live validation.
