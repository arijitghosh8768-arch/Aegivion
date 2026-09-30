"""Actor-resource relationship intelligence.

Learns who normally accesses what (actor->resource, workload->resource)
and evaluates novelty of the current pairing, plus cross-business-unit
access when asset ownership is supplied.

A novel pairing is evidence for review — an analyst's occasional access
to a colleague's dataset is normal; it is not automatically malicious.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.schemas import DataActivityEvent, DataAccessSession


@dataclass
class ActorResourceHistory:
    """Observed actor/workload -> resource relationships."""

    actor_resources: dict[str, set[str]] = field(default_factory=dict)
    workload_resources: dict[str, set[str]] = field(default_factory=dict)
    resource_owners: dict[str, str] = field(default_factory=dict)
    """resource_id -> business unit / owning team (from asset inventory)."""


def build_actor_resource_history(events: Sequence[DataActivityEvent]) -> ActorResourceHistory:
    """Accumulate relationships from historical events."""
    history = ActorResourceHistory()
    for event in events:
        if event.resource_id is None:
            continue
        if event.actor_id:
            history.actor_resources.setdefault(event.actor_id, set()).add(event.resource_id)
        if event.workload_id:
            history.workload_resources.setdefault(event.workload_id, set()).add(event.resource_id)
    return history


def actor_resource_signals(
    session: DataAccessSession,
    history: ActorResourceHistory | None = None,
    *,
    resource_business_units: dict[str, str] | None = None,
    actor_business_unit: str | None = None,
) -> dict[str, Any]:
    """Novelty of the actor/workload -> resource pairings."""
    history = history or ActorResourceHistory()

    known_resources: set[str] = set()
    for resource in session.resources_accessed:
        if session.actor_id and resource in history.actor_resources.get(session.actor_id, set()):
            known_resources.add(resource)
        if session.session_features.get("workload_id") and resource in history.workload_resources.get(
            session.session_features["workload_id"], set()
        ):
            known_resources.add(resource)

    novel = [r for r in session.resources_accessed if r not in known_resources]
    history_available = bool(history.actor_resources or history.workload_resources)
    if not history_available:
        # no relationship history at all: novelty is unknowable, not 100%
        actor_resource_novelty = None
    elif session.resources_accessed:
        actor_resource_novelty = round(len(novel) / len(session.resources_accessed), 4)
    else:
        actor_resource_novelty = None
    workload_resource_novelty = None
    workload_id = session.session_features.get("workload_id")
    if workload_id and session.resources_accessed:
        wl_known = [
            r for r in session.resources_accessed
            if r in history.workload_resources.get(workload_id, set())
        ]
        workload_resource_novelty = round(1.0 - len(wl_known) / len(session.resources_accessed), 4)

    cross_bu: list[dict[str, Any]] = []
    if resource_business_units:
        for resource in session.resources_accessed:
            bu = resource_business_units.get(resource)
            if bu and actor_business_unit and bu != actor_business_unit:
                cross_bu.append({"resource": resource, "business_unit": bu})

    return {
        "actor_resource_novelty": actor_resource_novelty,
        "workload_resource_novelty": workload_resource_novelty,
        "cross_business_unit_access": cross_bu,
        "novel_resources": novel,
        "known_pairings": sorted(known_resources),
        "history_available": history_available,
    }
