"""
TwinPersistenceRepository
=========================
The single authoritative persistence layer for Digital Twin state.

Ownership contract (Phase 5A):
  - This is the ONLY class that directly reads/writes CloudAsset,
    CloudIdentity, AssetRelationship, and SecurityChange rows.
  - SecurityDigitalTwin calls this for event-driven Pathway 1 writes.
  - SecurityDigitalTwinAdapter (used by TwinReconciliationEngine) calls
    this for verified-response Pathway 2 writes.
  - No worker, AgentController, or detector may import this class.

Tenant isolation:
  - Every public method requires organization_id as its first argument.
  - Cross-tenant writes raise TenantBoundaryError.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class TenantBoundaryError(Exception):
    """Raised when a caller attempts a cross-tenant write."""
    pass


class TwinPersistenceRepository:
    """
    Single persistence owner for Digital Twin state.

    Parameters
    ----------
    db :
        A DB session/client (Supabase client, SQLAlchemy Session, or any
        object that exposes .table().select()/.insert()/.update() as used
        by the existing codebase).
    organization_id : str
        The tenant this repository instance is bound to. All writes are
        implicitly scoped to this org; cross-tenant writes are rejected.
    """

    def __init__(self, db, organization_id: str) -> None:
        self._db = db
        self._organization_id = str(organization_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_tenant(self, organization_id: str) -> None:
        """Raise if the caller is attempting a cross-tenant operation."""
        if str(organization_id) != self._organization_id:
            raise TenantBoundaryError(
                f"TwinPersistenceRepository bound to org {self._organization_id!r} "
                f"cannot write for org {organization_id!r}."
            )

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # READ operations (Pathway 1 + 2)
    # ------------------------------------------------------------------

    def get_asset(self, organization_id: str, resource_id: str) -> Optional[Dict[str, Any]]:
        """Return a CloudAsset dict scoped to the tenant, or None."""
        self._assert_tenant(organization_id)
        try:
            result = (
                self._db.table("cloud_assets")
                .select("*")
                .eq("resource_id", resource_id)
                .eq("organization_id", organization_id)
                .execute()
            )
            rows = result.data or []
            return rows[0] if rows else None
        except Exception:
            return None

    def get_identity(self, organization_id: str, native_id: str) -> Optional[Dict[str, Any]]:
        """Return a CloudIdentity dict scoped to the tenant, or None."""
        self._assert_tenant(organization_id)
        try:
            result = (
                self._db.table("cloud_identities")
                .select("*")
                .eq("native_id", native_id)
                .eq("organization_id", organization_id)
                .execute()
            )
            rows = result.data or []
            return rows[0] if rows else None
        except Exception:
            return None

    def get_relationships(self, organization_id: str, resource_id: str) -> List[Dict[str, Any]]:
        """Return AssetRelationship dicts for a given resource, scoped to tenant."""
        self._assert_tenant(organization_id)
        try:
            result = (
                self._db.table("asset_relationships")
                .select("*")
                .eq("organization_id", organization_id)
                .eq("source_asset_id", resource_id)
                .execute()
            )
            return result.data or []
        except Exception:
            return []

    # ------------------------------------------------------------------
    # PATHWAY 1 writes — event-driven (called by SecurityDigitalTwin)
    # ------------------------------------------------------------------

    def upsert_asset(self, organization_id: str, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create or update a CloudAsset row.
        Domain semantics (what to write) are decided by SecurityDigitalTwin;
        this method handles only how it is persisted.
        """
        self._assert_tenant(organization_id)
        now = self._now()
        resource_id = asset_data.get("resource_id")
        if not resource_id:
            raise ValueError("asset_data must contain 'resource_id'")

        existing = self.get_asset(organization_id, resource_id)
        if existing:
            updated = {**existing, **asset_data, "updated_at": now}
            try:
                self._db.table("cloud_assets").update(updated).eq(
                    "resource_id", resource_id
                ).eq("organization_id", organization_id).execute()
            except Exception:
                pass
            return updated
        else:
            new_row = {
                "id": str(uuid.uuid4()),
                "organization_id": organization_id,
                "created_at": now,
                "updated_at": now,
                **asset_data,
            }
            try:
                self._db.table("cloud_assets").insert(new_row).execute()
            except Exception:
                pass
            return new_row

    def upsert_identity(self, organization_id: str, identity_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create or update a CloudIdentity row.
        Domain semantics decided by SecurityDigitalTwin; persistence here.
        """
        self._assert_tenant(organization_id)
        now = self._now()
        native_id = identity_data.get("native_id")
        if not native_id:
            raise ValueError("identity_data must contain 'native_id'")

        existing = self.get_identity(organization_id, native_id)
        if existing:
            updated = {**existing, **identity_data, "last_seen": now, "updated_at": now}
            try:
                self._db.table("cloud_identities").update(updated).eq(
                    "native_id", native_id
                ).eq("organization_id", organization_id).execute()
            except Exception:
                pass
            return updated
        else:
            new_row = {
                "id": str(uuid.uuid4()),
                "organization_id": organization_id,
                "first_seen": now,
                "last_seen": now,
                "created_at": now,
                "updated_at": now,
                **identity_data,
            }
            try:
                self._db.table("cloud_identities").insert(new_row).execute()
            except Exception:
                pass
            return new_row

    def create_asset_snapshot(
        self,
        organization_id: str,
        asset_id: str,
        snapshot_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Record an AssetSnapshot for RESOURCE_MODIFIED events."""
        self._assert_tenant(organization_id)
        now = self._now()
        row = {
            "id": str(uuid.uuid4()),
            "organization_id": organization_id,
            "asset_id": asset_id,
            "snapshot_at": now,
            "created_at": now,
            **snapshot_data,
        }
        try:
            self._db.table("asset_snapshots").insert(row).execute()
        except Exception:
            pass
        return row

    # ------------------------------------------------------------------
    # PATHWAY 2 writes — reconciliation (called by SecurityDigitalTwinAdapter)
    # ------------------------------------------------------------------

    def update_identity_privileges(
        self,
        organization_id: str,
        native_id: str,
        privileges: List[Any],
    ) -> None:
        """
        Update the privilege list for a CloudIdentity after a verified
        response action. Called only by SecurityDigitalTwinAdapter
        (used by TwinReconciliationEngine).
        """
        self._assert_tenant(organization_id)
        now = self._now()
        try:
            self._db.table("cloud_identities").update(
                {"privileges": privileges, "last_seen": now, "updated_at": now}
            ).eq("native_id", native_id).eq(
                "organization_id", organization_id
            ).execute()
        except Exception:
            pass

    def record_security_change(
        self, organization_id: str, change: Dict[str, Any]
    ) -> None:
        """
        Write an immutable SecurityChange audit record.
        Called only by SecurityDigitalTwinAdapter (Pathway 2).
        """
        self._assert_tenant(organization_id)
        now = self._now()
        row = {
            "id": str(uuid.uuid4()),
            "organization_id": organization_id,
            "created_at": now,
            **change,
        }
        try:
            self._db.table("security_changes").insert(row).execute()
        except Exception:
            pass
