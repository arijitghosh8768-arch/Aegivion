"""
SecurityDigitalTwin
===================
Domain/state authority for the Digital Twin.

Ownership contract (Phase 5A):
  - Owns the domain semantics of event-driven Twin updates (Pathway 1):
      decides WHAT the event means and WHAT state must change.
  - Delegates HOW that state is persisted to TwinPersistenceRepository.
  - Provides read-only context to workers (get_asset_context,
    query_blast_radius, evaluate_event_impact).
  - Does NOT import SQLAlchemy or write to the DB directly.
  - Does NOT call TwinReconciliationEngine.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.repositories.twin_persistence_repository import TwinPersistenceRepository


# Event types that trigger Pathway 1 writes
_WRITE_EVENT_TYPES = frozenset([
    "RESOURCE_CREATED",
    "RESOURCE_MODIFIED",
    "PERMISSION_CHANGED",
    "IDENTITY_ACTIVITY",
])


class SecurityDigitalTwin:
    """
    Orchestration layer bridging normalized security events to the
    Digital Twin's asset/identity graph.

    NOT a database model — it is a domain/context layer.
    All persistence goes through TwinPersistenceRepository.

    Parameters
    ----------
    persistence : TwinPersistenceRepository
        The repository this twin is bound to. Must be pre-scoped to the
        same organization_id as this instance.
    organization_id : str
        Tenant scope. Every read and write is bounded to this org.
    """

    def __init__(self, persistence: TwinPersistenceRepository, organization_id: str) -> None:
        self._persistence = persistence
        self._organization_id = str(organization_id)

    # ------------------------------------------------------------------
    # READ operations (context for workers — Pathway 0)
    # ------------------------------------------------------------------

    def get_asset_context(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Return the full security context for a specific asset,
        bounded to this tenant. Returns None if the asset is not known.
        """
        asset = self._persistence.get_asset(self._organization_id, resource_id)
        if not asset:
            return None

        relationships = self._persistence.get_relationships(
            self._organization_id, resource_id
        )
        return {
            "asset_id": asset.get("id"),
            "resource_id": asset.get("resource_id"),
            "provider": asset.get("provider"),
            "resource_type": asset.get("type"),
            "environment": asset.get("environment"),
            "business_criticality": asset.get("business_criticality"),
            "internet_exposed": asset.get("internet_exposed", False),
            "importance_score": asset.get("importance_score", 0.0),
            "relationships": relationships,
        }

    def query_blast_radius(self, resource_id: str, depth: int = 2) -> List[Dict[str, Any]]:
        """
        Graph traversal — returns all assets reachable from a compromised
        resource within `depth` relationship hops, scoped to this tenant.
        """
        visited: set[str] = set()
        frontier = [resource_id]
        result: List[Dict[str, Any]] = []

        for _ in range(depth):
            next_frontier: List[str] = []
            for rid in frontier:
                if rid in visited:
                    continue
                visited.add(rid)
                rels = self._persistence.get_relationships(self._organization_id, rid)
                for rel in rels:
                    target = rel.get("target_asset_id")
                    if target and target not in visited:
                        ctx = self.get_asset_context(target)
                        if ctx:
                            result.append(ctx)
                        next_frontier.append(target)
            frontier = next_frontier

        return result

    def evaluate_event_impact(self, canonical_event: Any) -> Dict[str, Any]:
        """
        Given a normalized event, determine business/security impact by
        querying the affected assets in the twin.
        """
        target_id = getattr(canonical_event, "target", None) or getattr(
            canonical_event, "target_resource_id", None
        )
        context = self.get_asset_context(target_id) if target_id else None

        importance = (context or {}).get("importance_score", 0.0)
        internet_exposed = (context or {}).get("internet_exposed", False)
        criticality = (context or {}).get("business_criticality", "UNKNOWN")

        impact_score = importance * (1.5 if internet_exposed else 1.0)
        attack_path_active = internet_exposed and criticality not in ("LOW", "UNKNOWN")

        return {
            "event_id": getattr(canonical_event, "event_id", None),
            "target_context": context,
            "attack_path_active": attack_path_active,
            "impact_score": impact_score,
        }

    # ------------------------------------------------------------------
    # PATHWAY 1 write — event-driven (called by AgentController before workers)
    # ------------------------------------------------------------------

    def update_from_event(self, canonical_event: Any) -> None:
        """
        Apply event-driven Digital Twin state changes.

        Domain semantics (this method):
          - Decides WHAT the event means and WHAT must change.

        Persistence (TwinPersistenceRepository):
          - Decides HOW those changes are persisted.

        Permitted writes per event type:
          RESOURCE_CREATED    → upsert_asset
          RESOURCE_MODIFIED   → upsert_asset + create_asset_snapshot
          PERMISSION_CHANGED  → upsert_identity (privilege-related metadata)
          IDENTITY_ACTIVITY   → upsert_identity (last_seen_at only)
          All others          → read-only; no write performed
        """
        event_type = getattr(canonical_event, "event_type", None) or ""
        if event_type not in _WRITE_EVENT_TYPES:
            return  # read-only for all other event types

        org = self._organization_id
        actor = getattr(canonical_event, "actor", None) or {}
        target = getattr(canonical_event, "target", None) or {}

        # Normalize actor/target — they may be dicts or plain strings
        actor_id = actor.get("native_id") if isinstance(actor, dict) else str(actor or "")
        target_id = target.get("native_id") if isinstance(target, dict) else str(target or "")

        # ── IDENTITY_ACTIVITY ─────────────────────────────────────────
        if event_type == "IDENTITY_ACTIVITY" and actor_id and actor_id != "unknown":
            self._persistence.upsert_identity(org, {
                "native_id": actor_id,
                "account_id": str(getattr(canonical_event, "cloud_account_id", "") or ""),
                "provider": getattr(canonical_event, "provider", "aws"),
                "status": "ACTIVE",
            })

        # ── PERMISSION_CHANGED ────────────────────────────────────────
        elif event_type == "PERMISSION_CHANGED" and actor_id and actor_id != "unknown":
            self._persistence.upsert_identity(org, {
                "native_id": actor_id,
                "account_id": str(getattr(canonical_event, "cloud_account_id", "") or ""),
                "provider": getattr(canonical_event, "provider", "aws"),
                "identity_type": "IAM_USER",
                # Note: privilege-list reconciliation after a VERIFIED response
                # is owned by TwinReconciliationEngine, not this method.
                # This only records the identity's presence.
            })

        # ── RESOURCE_CREATED / RESOURCE_MODIFIED ──────────────────────
        elif event_type in ("RESOURCE_CREATED", "RESOURCE_MODIFIED") and target_id:
            metadata = getattr(canonical_event, "metadata", {}) or {}
            asset_data = {
                "resource_id": target_id,
                "account_id": str(getattr(canonical_event, "cloud_account_id", "") or ""),
                "provider": getattr(canonical_event, "provider", "aws"),
                "type": metadata.get("resource_type", "UNKNOWN"),
                "region": metadata.get("region"),
                "metadata_json": metadata,
            }
            upserted = self._persistence.upsert_asset(org, asset_data)

            if event_type == "RESOURCE_MODIFIED":
                self._persistence.create_asset_snapshot(
                    org,
                    asset_id=upserted.get("id", target_id),
                    snapshot_data={"metadata_json": metadata, "event_id": str(
                        getattr(canonical_event, "event_id", "") or ""
                    )},
                )
