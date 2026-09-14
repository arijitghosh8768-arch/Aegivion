# Database Schema (ER Model)

This document maps out the Entity-Relationship (ER) schema for the Aegivion platform, referencing the models in `packages/backend/app/models/` and `packages/security/models/`.

## Core Entities

### `Organization`
Represents a tenant in the system.
- `id` (UUID, Primary Key)
- `name` (String)
- `created_at` (Timestamp)

### `User`
Users belonging to an Organization.
- `id` (UUID, Primary Key)
- `organization_id` (UUID, Foreign Key -> Organization.id)
- `email` (String, Unique)
- `password_hash` (String)
- `role_id` (UUID, Foreign Key -> Role.id)

### `Role`
RBAC roles defining user permissions.
- `id` (UUID, Primary Key)
- `name` (String) - e.g., 'Admin', 'Viewer'
- `permissions` (JSONB)

### `CloudAccount`
Connected cloud environments (AWS, Azure, GCP).
- `id` (UUID, Primary Key)
- `organization_id` (UUID, Foreign Key -> Organization.id)
- `provider` (String) - e.g., 'AWS'
- `account_id` (String)
- `status` (String)

## Security & Graph Entities

### `Asset` (Cloud Resource)
Discovered infrastructure components.
- `id` (UUID, Primary Key)
- `cloud_account_id` (UUID, Foreign Key -> CloudAccount.id)
- `resource_type` (String) - e.g., 'aws_s3_bucket', 'aws_iam_role'
- `arn` / `resource_id` (String)
- `metadata` (JSONB)

### `Finding` / `Vulnerability`
Security issues detected on assets.
- `id` (UUID, Primary Key)
- `asset_id` (UUID, Foreign Key -> Asset.id)
- `title` (String)
- `severity` (Enum: CRITICAL, HIGH, MEDIUM, LOW)
- `status` (Enum: OPEN, RESOLVED, SUPPRESSED)
- `description` (Text)

### `Incident`
A correlated group of findings representing an active threat or attack path.
- `id` (UUID, Primary Key)
- `title` (String)
- `status` (String)
- `severity` (String)

### `AuditLog`
Tracking user actions for compliance.
- `id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key -> User.id)
- `action` (String)
- `resource_type` (String)
- `timestamp` (Timestamp)

## Relationships
- **One-to-Many**: `Organization` -> `User`, `Organization` -> `CloudAccount`
- **One-to-Many**: `CloudAccount` -> `Asset`
- **One-to-Many**: `Asset` -> `Finding`
- **Many-to-Many**: `Finding` <-> `Incident` (via association table)
