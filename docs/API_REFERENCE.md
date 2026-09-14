# Aegivion API Reference

This document outlines the core endpoints available in the Aegivion platform under `/api/v1/`.

## Authentication (`/auth`)
- `POST /api/v1/auth/login`: Authenticate a user and receive JWT access/refresh tokens.
- `POST /api/v1/auth/refresh`: Refresh an expired access token.
- `POST /api/v1/auth/logout`: Invalidate the current session.

## Findings (`/findings`)
- `GET /api/v1/findings`: Retrieve a paginated list of security findings. Supports filtering by severity, status, and cloud account.
- `GET /api/v1/findings/{id}`: Get detailed information about a specific finding, including affected assets and related incidents.
- `PATCH /api/v1/findings/{id}/status`: Update the status of a finding (e.g., `OPEN`, `RESOLVED`, `IGNORED`).

## Assets & Cloud Resources (`/assets`)
- `GET /api/v1/assets`: Retrieve a list of all discovered cloud assets (EC2, S3, IAM roles, etc.).
- `GET /api/v1/assets/{id}`: View detailed configuration and associated security risks for a specific asset.

## AI Chat (`/chat`)
- `POST /api/v1/chat/message`: Send a prompt to the Aegivion AI Assistant. Maintains conversation context to query architecture or risk posture.
- `GET /api/v1/chat/history`: Retrieve the current user's AI chat history.

## Explanations & Remediation (`/explain`)
- `GET /api/v1/explain/{finding_id}`: Auto-generate a plain-English explanation of the attack path and risk for a specific finding.
- `POST /api/v1/remediation/generate`: Generate IaC (Terraform/CloudFormation) or CLI scripts to remediate a finding.

## Settings & Organizations (`/cloud_accounts`, `/organization`)
- `GET /api/v1/cloud_accounts`: List all connected cloud accounts (AWS, GCP, Azure) for the current organization.
- `POST /api/v1/cloud_accounts`: Onboard a new cloud account via cross-account IAM roles or service principals.
- `GET /api/v1/organization/settings`: Retrieve organization-wide security policies and alert configurations.
