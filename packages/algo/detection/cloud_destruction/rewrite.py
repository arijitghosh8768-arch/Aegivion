"""Mass rewrite/replace analysis — **Part 2**.

Detects repeated READ → REWRITE → REPLACE → DELETE-ORIGINAL patterns across
many resources (``CopyObject`` storms, same-key overwrite bursts) that can
accompany ransomware-style data replacement.

Naming discipline (Part 2 spec): the feature is
``rewrite_transform_score`` — a deterministic evidence strength in ``[0,1]``
for *rewrite/transform behavior*. It must **not** be read as "data was
encrypted": rewriting objects is content-neutral evidence. Any claim of
actual encryption requires content-level proof that this detector does not
have; Part 3 must not map this feature onto an encryption verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from algo.detection.cloud_destruction.baseline import BehaviorBaseline
from algo.detection.cloud_destruction.config import BehavioralConfig
from algo.detection.cloud_destruction.deviation import clamp01, hour_span, ratio_to_factor
from algo.detection.cloud_destruction.evidence import SessionEvidence, collect_evidence
from algo.detection.cloud_destruction.provenance import MeasuredValue
from algo.detection.cloud_destruction.schemas import DestructiveActivitySession, ResourceActivityEvent

__all__ = ["RewriteAnalysis", "analyze_rewrite"]


@dataclass
class RewriteAnalysis:
    """Deterministic rewrite/transform features for one session."""

    rewrite_transform_score: Optional[MeasuredValue] = None
    transform_chains: tuple[str, ...] = field(default_factory=tuple)


def analyze_rewrite(
    session: DestructiveActivitySession,
    baseline: Optional[BehaviorBaseline],
    *,
    events: Optional[list[ResourceActivityEvent]] = None,
    config: Optional[BehavioralConfig] = None,
    evidence: Optional[SessionEvidence] = None,
) -> RewriteAnalysis:
    """Analyze rewrite volume and transform chains for one session."""
    cfg = config or BehavioralConfig()
    ev = evidence or collect_evidence(session, events)
    result = RewriteAnalysis()

    hours = hour_span(ev.event_count, ev.duration_seconds, cfg.min_session_seconds)
    contributors = ("rewrite",) + (("baseline",) if baseline is not None else ())

    rewrites = ev.rewrite_events if ev.rewrite_events is not None else 0
    if rewrites == 0:
        result.rewrite_transform_score = MeasuredValue.measured(
            0.0,
            method="no_rewrite_events",
            contributors=("rewrite",),
            raw={"rewrite_events": 0},
        )
        return result

    # chain evidence (event mode only; absent detail these stay 0 and the
    # raw block records that honestly)
    read_rewrite = len(ev.read_then_rewritten_keys)
    rewrite_delete = len(ev.rewritten_then_deleted_keys)
    chains: list[str] = []
    if read_rewrite:
        chains.append("read_then_rewrite")
    if rewrite_delete:
        chains.append("rewrite_then_delete_original")
    if read_rewrite and rewrite_delete:
        chains.append("read_rewrite_replace_delete_original")

    chain_strength = clamp01(rewrite_delete / max(1, cfg.rewrite_chain_cap))
    volume_strength = clamp01(rewrites / max(1, cfg.rewrite_chain_cap * 5))

    if baseline is not None and baseline.rewrite_rate.mean is not None:
        deviation = ratio_to_factor(
            rewrites / hours, baseline.rewrite_rate.mean, cfg.max_rate_deviation_factor
        )
        baseline_component = deviation if deviation is not None else volume_strength
        raw: dict[str, object] = {"normal_rewrite_per_hour": baseline.rewrite_rate.mean}
    else:
        baseline_component = volume_strength
        raw = {"observed_per_hour": rewrites / hours}

    score = clamp01(
        0.5 * baseline_component + 0.3 * chain_strength + 0.2 * volume_strength
    )
    raw.update(
        {
            "rewrite_events": rewrites,
            "read_then_rewrite_keys": read_rewrite,
            "rewrite_then_delete_original_keys": rewrite_delete,
            "chain_strength": chain_strength,
            "unique_rewritten_keys": len(ev.rewritten_keys),
            "duration_hours": hours,
            "note": "content-neutral transform evidence; not an encryption verdict",
        }
    )
    result.rewrite_transform_score = MeasuredValue.measured(
        score,
        method="rewrite_volume_and_transform_chains",
        contributors=contributors,
        raw=raw,
    )
    result.transform_chains = tuple(chains)
    return result
