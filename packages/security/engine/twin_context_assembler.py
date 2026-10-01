"""
TwinContextAssembler
====================
Phase 5C — Pre-detection context wiring.

Ownership contract:
  - Assembles a flat, detector-ready context dict from SecurityDigitalTwin.
  - Called by DetectionCorrelationWorker BEFORE running detectors.
  - Detectors receive a prepared dict; they never touch TwinPersistenceRepository.
  - TwinContextAssembler reads from SecurityDigitalTwin (read path only).
  - No writes. No SQLAlchemy. No direct DB access.

Tenant isolation:
  - SecurityDigitalTwin is pre-scoped to an organization_id.
  - TwinContextAssembler receives an already-scoped twin instance; it never
    performs cross-tenant reads.

Context freshness:
  - Every returned dict includes 'twin_context_fresh' (bool) and
    'twin_context_assembled_at' (ISO timestamp).
  - When SecurityDigitalTwin is unavailable, twin_context_fresh=False and
    all optional fields are absent. Detectors must degrade gracefully.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


class TwinContextAssembler:
    """
    Assembles per-event detection context from the Digital Twin.

    The assembled context dict is the only interface between the Twin and
    detectors. Detectors are consumers of this dict; they must not query
    the Twin or the database themselves.

    Context keys provided:
    ─────────────────────────────────────────────────────────────────────
    Common (all detectors):
      twin_context_fresh        bool — True if Twin was available
      twin_context_assembled_at ISO str — when context was assembled

    Identity-related (credential compromise detector):
      identity_type             str | None
      identity_status           str | None
      identity_criticality      str | None
      known_ips                 list — empty when unknown
      recent_failed_logins      int  — 0 when unknown

    Asset-related (data exfiltration detector):
      asset_resource_id         str | None
      asset_environment         str | None
      asset_business_criticality str | None
      asset_internet_exposed    bool
      asset_importance_score    float

    Relationships (all detectors — blast radius context):
      blast_radius_assets       list[dict] — reachable asset contexts
      relationship_count        int

    Ransomware/history-related (ransomware detector):
      actor_baseline_deletions  int  — 0 when unknown
      actor_baseline_modifications int
      actor_historical_targets  list[str]
    ─────────────────────────────────────────────────────────────────────
    """

    def assemble(
        self,
        organization_id: str,
        actor_id: Optional[str],
        target_id: Optional[str],
        digital_twin: Any,  # SecurityDigitalTwin | None
    ) -> Dict[str, Any]:
        """
        Assemble a flat detection context dict.

        Parameters
        ----------
        organization_id : str
            Tenant scope. Used only for safety assertions here; the twin
            is already pre-scoped to this org.
        actor_id : str | None
            Native identity ID of the event actor.
        target_id : str | None
            Native resource/asset ID of the event target.
        digital_twin : SecurityDigitalTwin | None
            The pre-scoped twin. If None, returns a degraded context with
            twin_context_fresh=False and safe default values.

        Returns
        -------
        dict
            Flat context dict consumed by detectors.
        """
        now = datetime.now(timezone.utc).isoformat()
        base = {
            "twin_context_fresh": False,
            "twin_context_assembled_at": now,
            # Identity defaults
            "identity_type": None,
            "identity_status": None,
            "identity_criticality": None,
            "known_ips": [],
            "recent_failed_logins": 0,
            # Asset defaults
            "asset_resource_id": target_id,
            "asset_environment": None,
            "asset_business_criticality": None,
            "asset_internet_exposed": False,
            "asset_importance_score": 0.0,
            # Relationship defaults
            "blast_radius_assets": [],
            "relationship_count": 0,
            # Ransomware/history defaults
            "actor_baseline_deletions": 0,
            "actor_baseline_modifications": 0,
            "actor_historical_targets": [],
        }

        if digital_twin is None:
            return base

        try:
            ctx = self._enrich(base, actor_id, target_id, digital_twin)
            ctx["twin_context_fresh"] = True
            return ctx
        except Exception:
            # Twin read failure → degrade, never propagate to detectors
            return base

    # ------------------------------------------------------------------
    # Private enrichment helpers
    # ------------------------------------------------------------------

    def _enrich(
        self,
        ctx: Dict[str, Any],
        actor_id: Optional[str],
        target_id: Optional[str],
        twin: Any,
    ) -> Dict[str, Any]:
        ctx = dict(ctx)

        # ── Identity context (credential compromise detector) ──────────
        if actor_id and actor_id not in ("unknown", "unknown_user", ""):
            identity = twin._persistence.get_identity(
                twin._organization_id, actor_id
            )
            if identity:
                ctx["identity_type"] = identity.get("identity_type")
                ctx["identity_status"] = identity.get("status")
                ctx["identity_criticality"] = identity.get("criticality")
                meta = identity.get("metadata") or {}
                ctx["known_ips"] = meta.get("known_ips", [])
                ctx["recent_failed_logins"] = meta.get("recent_failed_logins", 0)
                ctx["actor_baseline_deletions"] = meta.get("baseline_deletions", 0)
                ctx["actor_baseline_modifications"] = meta.get("baseline_modifications", 0)
                ctx["actor_historical_targets"] = meta.get("historical_targets", [])

        # ── Asset context (data exfiltration + ransomware detectors) ──
        if target_id:
            asset_ctx = twin.get_asset_context(target_id)
            if asset_ctx:
                ctx["asset_resource_id"] = asset_ctx.get("resource_id")
                ctx["asset_environment"] = asset_ctx.get("environment")
                ctx["asset_business_criticality"] = asset_ctx.get("business_criticality")
                ctx["asset_internet_exposed"] = asset_ctx.get("internet_exposed", False)
                ctx["asset_importance_score"] = asset_ctx.get("importance_score", 0.0)

                relationships = asset_ctx.get("relationships", [])
                ctx["relationship_count"] = len(relationships)

        # ── Blast radius (all detectors) ──────────────────────────────
        if target_id:
            blast = twin.query_blast_radius(target_id, depth=1)
            ctx["blast_radius_assets"] = blast

        return ctx
