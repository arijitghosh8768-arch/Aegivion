# Aegivion Security Review

This document outlines the security posture of the Aegivion platform, completed during the Week 14 Production Security & Deployment phase.

## 1. Cloud Credential Handling
Aegivion adheres to a strict "No Stored Customer Secrets" policy.
- **AWS**: We utilize AWS IAM Cross-Account Roles. The platform only stores the Role ARN. Temporary STS tokens are assumed at runtime and are never cached beyond their expiration.
- **GCP**: Workload Identity Federation is used. No long-lived service account JSON keys are stored.
- **Azure**: Managed Identities or App Registrations with certificate-based auth are required; client secrets are heavily discouraged and never stored in plain text.

## 2. Encryption and Data Protection
- **In Transit**: TLS 1.2+ is strictly enforced for all API traffic, inter-service communication, and external cloud provider API calls. HSTS is enforced on the frontend.
- **At Rest**: PostgreSQL databases are configured with at-rest encryption (AES-256) at the storage volume level. Redis caches are ephemeral and do not store PII or sensitive findings persistently.

## 3. Application Security Controls
- **Tenant Isolation**: Multi-tenancy is enforced at the API layer. Every query validating assets, findings, or incidents is bound to the `current_user.org_id`.
- **RBAC**: A robust Role-Based Access Control system restricts mutating endpoints. Elevated privileges are required for actions such as Exception Approvals and Remediation Execution.
- **Injection Defense**: 
  - *SQL Injection*: Prevented via ORM (SQLAlchemy) parameterized queries.
  - *Prompt Injection*: LLM prompts include explicit system directives instructing the model to ignore adversarial instructions embedded within asset metadata or user chat.
- **Rate Limiting**: `slowapi` enforces request limits on expensive endpoints (e.g., `/ai/*` and `/scan`) and login routes to mitigate brute force and cost-exhaustion attacks.
- **XSS & CSRF**: The frontend leverages React's native escaping, prohibiting `dangerouslySetInnerHTML`. API calls use Bearer Tokens, mitigating traditional CSRF vectors. Strict CORS and CSP headers are enforced.

## 4. Remediation Workflow Safety
- AI-generated remediation actions are subject to strict server-side validation against a predefined allowlist.
- Actions require a secondary human-in-the-loop approval step if defined by the organization's Security Policy, preventing autonomous destructive actions.
