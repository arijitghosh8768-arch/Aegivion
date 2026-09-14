# Aegivion Threat Model

## Detection Scope
Aegivion's detection engine focuses on the following primary attack surfaces and entry points:

### 1. Network Exposure (External)
- Publicly accessible resources (EC2, S3, RDS).
- Misconfigured security groups allowing ingress from `0.0.0.0/0`.
- Weakened Public Access Blocks on cloud storage.

### 2. IAM Misconfiguration & Privilege Escalation
- Over-privileged identities (e.g. `AdministratorAccess` where unnecessary).
- Lack of MFA on privileged accounts.
- Privilege escalation paths (e.g. users capable of modifying their own policies, or assuming administrative roles).

### 3. Lateral Movement (Internal)
- Broad outbound access from internal subnets.
- Permissive egress rules that facilitate pivoting inside the network once an initial foothold is established.

## Out of Scope
The following are explicitly **out of scope** for Aegivion's current detection capabilities:
- **Application-Layer Vulnerabilities**: We do not perform dynamic application security testing (DAST) or static analysis (SAST) of customer application code (e.g. SQL Injection, XSS in custom web apps).
- **Supply Chain Attacks**: We do not scan third-party dependencies (npm, PyPI) or CI/CD pipeline integrity.
- **Insider Threat Detection**: We detect misconfigurations, but do not profile user behavior anomalies (UEBA) indicative of a malicious insider acting within their granted privileges.
