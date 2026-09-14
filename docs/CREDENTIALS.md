# Aegivion Credential Storage Policy

## Customer Secrets
Aegivion strictly **does not store any customer secret access keys**. 

To connect to customer cloud environments, we exclusively utilize:
- Role ARNs (Amazon Resource Names) for AWS integrations.
- Workload Identities and OIDC identity federation for cross-cloud access.
- Temporary, short-lived session tokens generated dynamically during operations.

## Internal Secrets
All internal application secrets and keys used by Aegivion (e.g., database passwords, encryption keys, and internal API tokens) are strictly managed via **Environment Variables** (`.env`). These are injected at runtime by the container orchestration system or deployment environment and are never hardcoded in the source code or persisted directly in application databases.
