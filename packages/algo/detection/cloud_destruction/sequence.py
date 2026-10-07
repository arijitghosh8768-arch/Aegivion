"""Destructive API sequence analysis — **Part 2**.

Detects *ordering* structure in a session's destructive activity — without
hard-coded attack signatures and without any ML:

- protection changes **preceding** deletion-family activity
  (disable protection, then destroy);
- READ → REWRITE → DELETE-ORIGINAL transform chains;
- **rapid action transitions**: distinct canonical categories following
  each other within ``rapid_transition_max_gap_seconds``.

Output is one deterministic ``sequence_anomaly`` in ``[0, 1]`` plus the raw
transitions, so Part 3 can explain every point.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from algo.detection.cloud_destruction.baseline import BehaviorBaseline
from algo.detection.cloud_destruction.config import BehavioralConfig
from algo.detection.cloud_destruction.deviation import clamp01
from algo.detection.cloud_destruction.evidence import DELETION_FAMILY, SessionEvidence, collect_evidence
from algo.detection.cloud_destruction.provenance import MeasuredValue
from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    DestructiveActivitySession,
    ResourceActivityEvent,
)

__all__ = ["SequenceAnalysis", "analyze_sequences"]


@dataclass
class SequenceAnalysis:
    """Deterministic sequence/ordering features for one session."""

    sequence_anomaly: Optional[MeasuredValue] = None
    protection_before_destruction: bool = False
    transform_chain_present: bool = False
    rapid_transitions: int = 0


def analyze_sequences(
    session: DestructiveActivitySession,
    baseline: Optional[BehaviorBaseline],
    *,
    events: Optional[list[ResourceActivityEvent]] = None,
    config: Optional[BehavioralConfig] = None,
    evidence: Optional[SessionEvidence] = None,
) -> SequenceAnalysis:
    """Analyze destructive API ordering for one session."""
    cfg = config or BehavioralConfig()
    ev = evidence or collect_evidence(session, events)
    result = SequenceAnalysis()

    if not ev.has_event_detail or not ev.events:
        result.sequence_anomaly = MeasuredValue.unavailable(
            "event_detail_missing", contributors=("sequence",)
        )
        return result

    ordered = sorted(ev.events, key=lambda e: (e.timestamp, e.event_id))

    # 1) protection change preceding deletion-family activity
    protection_before_destruction = False
    seen_protection_change = False
    for event in ordered:
        if event.action_category in (
            ActionCategory.PROTECTION_CHANGE,
            ActionCategory.POLICY_CHANGE,
            ActionCategory.SHARE_CHANGE,
        ):
            seen_protection_change = True
        elif seen_protection_change and event.action_category in DELETION_FAMILY:
            protection_before_destruction = True
            break
    result.protection_before_destruction = protection_before_destruction

    # 2) READ → REWRITE → DELETE-ORIGINAL chain on a shared key
    transform_chain_present = len(ev.rewritten_then_deleted_keys) > 0
    result.transform_chain_present = transform_chain_present

    # 3) rapid distinct-category transitions
    rapid_gap = cfg.rapid_transition_max_gap_seconds
    rapid_transitions = 0
    for prev, nxt in zip(ordered, ordered[1:]):
        gap = (nxt.timestamp - prev.timestamp).total_seconds()
        if gap <= rapid_gap and prev.action_category is not nxt.action_category:
            if {prev.action_category, nxt.action_category} & (DELETION_FAMILY | {ActionCategory.REWRITE}):
                rapid_transitions += 1
    result.rapid_transitions = rapid_transitions

    score = clamp01(
        (0.4 if protection_before_destruction else 0.0)
        + (0.25 if transform_chain_present else 0.0)
        + 0.05 * rapid_transitions
    )
    result.sequence_anomaly = MeasuredValue.measured(
        score,
        method="ordering_structure",
        contributors=("sequence",),
        raw={
            "protection_change_before_deletions": protection_before_destruction,
            "transform_chain": transform_chain_present,
            "rapid_transitions": rapid_transitions,
            "rapid_transition_max_gap_seconds": rapid_gap,
        },
    )
    return result
