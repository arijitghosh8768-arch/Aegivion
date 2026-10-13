# Security Threat Model

## Assets
Identity/session tokens, tenant data, cloud credentials, cloud configuration, findings/events, AI knowledge, approvals, execution privileges, and audit records.

## Threats
Cross-tenant access; broken authentication/session/OAuth; leaked or overprivileged cloud credentials; malicious events or poisoned knowledge; prompt injection; AI hallucinations treated as facts; unauthorized remediation; replay/race conditions/stale worker leases; secrets in Git/logs/artifacts; denial of service.

## Controls
- Server-side membership/permission checks on every protected operation.
- Tenant scope enforced in repositories, caches, retrieval, and background jobs.
- Secure session/cookie settings, OAuth state validation, CSRF protection where applicable, rate limits, and audit.
- Least-privilege provider access and safe secret storage.
- Input validation and bounded payloads.
- RAG access filtering before context reaches a model.
- Treat retrieved content and resource strings as untrusted data, never instructions.
- Structured output validation and evidence references.
- Allowlisted actions, deterministic policy, approval, preconditions, verification, and audit.
- Fail closed for unsupported actions or uncertain evidence.
- Dependency, secret, static, and dynamic security tests.

For each risk record ID, asset, threat, preconditions, impact, likelihood, severity, mitigation, owner, evidence, and residual risk. This is a baseline, not proof that controls are verified.
