# TEAM MANAGEMENT IMPLEMENTATION AUDIT

## 1. What already exists
- Frontend Team Management page exists at `packages/frontend/app/(dashboard)/team/page.tsx`
- The UI contains Add Employee form, Employee Email input, Target Organization dropdown (for Super Admins), Role dropdown, Add to Allowlist button, and Employee Allowlist table.
- API service layer already has `/v1/invitations` containing `GET /orgs/{org_id}/invitations`, `POST /orgs/{org_id}/invitations`, and `DELETE /invitations/{id}`.
- Authentication and session handling via Google OAuth is handled using `get_current_user`.
- MongoDB connection provides the `Invitation`, `Organization`, and `User` identity records.
- Roles are already standardized across the app (`superadmin`, `admin`, `viewer`).

## 2. Existing database tables
- `organizations`
- `users`
- `invitations`
- `roles`

## 3. Existing APIs
- `GET /v1/orgs/{org_id}/invitations` - Lists invites.
- `POST /v1/orgs/{org_id}/invitations` - Creates invites.
- `DELETE /v1/invitations/{id}` - Revokes invites.
- `GET /v1/admin/orgs` - Loads organizations for Super Admins.

## 4. Existing authentication and RBAC
- Super Admins can list and manage invites for any organization.
- Org Admins can manage invites only for their `organization_id`.
- RBAC is enforced on both frontend UI (rendering selectors) and backend (raising HTTP 403).

## 5. Existing invitation flow
- Invites are created with `PENDING` status.
- Once accepted via Google OAuth, the user gets added to the tenant.

## 6. Missing functionality
- Prevent duplicate entries (a pending/active user can be invited multiple times).
- Email normalization (emails are not lowercased/trimmed).
- Role normalization (roles sent from frontend lack strict validation).
- Better action lifecycle mapping (REVOKED status).

## 7. Files that need modification
- `packages/backend/app/api/v1/invitations.py`

## 8. Implementation sequence
1. Read existing implementations.
2. Update backend `POST /orgs/{org_id}/invitations` to enforce duplicates and roles.
3. Validate RBAC.
4. Document the Implementation Report.
