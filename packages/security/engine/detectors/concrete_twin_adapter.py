"""
ConcreteTwinAdapter
===================
Concrete implementation of SecurityDigitalTwinAdapter (Phase 5A).

Ownership contract:
  - Bridges TwinReconciliationEngine (reconciliation semantics authority)
    to TwinPersistenceRepository (persistence authority).
  - TwinReconciliationEngine calls this; this calls TwinPersistenceRepository.
  - Does NOT call SecurityDigitalTwin — the two write pathways are independent.
  - Does NOT import SQLAlchemy directly.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from app.repositories.twin_persistence_repository import TwinPersistenceRepository
from security.engine.twin_reconciliation_engine import (
    SecurityChangeRecord,
    SecurityDigitalTwinAdapter,
)


class ConcreteTwinAdapter(SecurityDigitalTwinAdapter):
    """
    Concrete bridge between TwinReconciliationEngine and
    TwinPersistenceRepository.

    Parameters
    ----------
    persistence : TwinPersistenceRepository
        Must be pre-scoped to the same organization as the reconciliation
        request being processed.
    """

    def __init__(self, persistence: TwinPersistenceRepository) -> None:
        self._persistence = persistence

    # ------------------------------------------------------------------
    # SecurityDigitalTwinAdapter interface implementation
    # ------------------------------------------------------------------

    def get_identity(
        self, target_id: str, organization_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve a CloudIdentity by native_id, scoped to the tenant.
        Returns None if not found.
        """
        return self._persistence.get_identity(organization_id, native_id=target_id)

    def update_identity(
        self, target_id: str, organization_id: str, updates: Dict[str, Any]
    ) -> None:
        """
        Apply verified privilege-list changes to a CloudIdentity.
        Semantics (what to update) decided by TwinReconciliationEngine;
        persistence (how) handled by TwinPersistenceRepository.
        """
        privileges = updates.get("privileges")
        if privileges is not None:
            self._persistence.update_identity_privileges(
                organization_id, native_id=target_id, privileges=privileges
            )
        # If other fields are passed (e.g. last_seen_at) we upsert them
        non_privilege = {k: v for k, v in updates.items() if k != "privileges"}
        if non_privilege:
            self._persistence.upsert_identity(
                organization_id, {"native_id": target_id, **non_privilege}
            )

    def record_change(self, change: SecurityChangeRecord) -> None:
        """
        Persist an immutable SecurityChangeRecord as an audit entry.
        Called only after TwinReconciliationEngine produces a reconciled result.
        """
        self._persistence.record_security_change(
            organization_id=change.organization_id,
            change={
                "target_id": change.target_id,
                "change_type": change.change_type,
                "field": change.field,
                "old_value": change.old_value,
                "new_value": change.new_value,
                "verified_at": change.verified_at.isoformat()
                if hasattr(change.verified_at, "isoformat")
                else str(change.verified_at),
                "execution_id": change.execution_id,
            },
        )
