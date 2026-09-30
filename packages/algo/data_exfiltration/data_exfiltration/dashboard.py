"""Dashboard view model: one flat, render-ready shape for analysts.

Turns a finding (plus the session, feature set, and events behind it) into
the ~15 fields an analyst-facing UI needs — including the access timeline,
the normal-vs-observed comparison, ranked top signals, and both sides of
the evidence. It is a *view*: pure derivation, no new judgments.

Honesty rules mirror the output contract: unavailable comparisons say so
rather than showing a fabricated baseline, and the contradicting-evidence
panel is always present so the UI cannot show only the accusation.
"""

from __future__ import annotations

from typing import Any, Iterable

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import BehavioralFeatureSet
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoredSession
from algo.data_exfiltration.data_exfiltration.output_contract import (
    build_output_contract,
    output_contract_of,
)
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession, SecurityFinding

DASHBOARD_VIEW_VERSION = "dashboard-view-1.0.0"

_FEATURE_LABELS = {
    "volume_score": "Data volume",
    "object_count_score": "Object count",
    "request_rate_score": "Request rate",
    "destination_score": "Destination novelty",
    "access_pattern_score": "Access-pattern novelty",
    "sensitivity_score": "Sensitivity",
    "time_score": "Time-of-day anomaly",
    "actor_resource_score": "Actor–resource novelty",
    "egress_score": "Network egress",
}


def _timeline(session: DataAccessSession, events: Iterable[Any] | None) -> list[dict[str, Any]]:
    """Chronological per-event rows for the session (observed values only)."""
    rows: list[dict[str, Any]] = []
    if not events:
        return rows
    wanted = set(session.event_ids or [])
    for event in events:
        if wanted and getattr(event, "event_id", None) not in wanted:
            continue
        bytes_value = None
        if getattr(event, "bytes_accessed", None) is not None:
            bytes_value = event.bytes_accessed.value
        rows.append({
            "event_id": getattr(event, "event_id", None),
            "timestamp_epoch_ms": getattr(event, "event_time_epoch_ms", None),
            "data_action": getattr(getattr(event, "data_action", None), "value", None),
            "resource": getattr(event, "resource_id", None),
            "object_key": getattr(event, "object_key", None),
            "bytes_accessed": bytes_value,
            "destination": getattr(event, "destination_ip", None) or getattr(event, "destination_domain", None),
            "error_code": getattr(event, "error_code", None),
        })
    rows.sort(key=lambda r: r["timestamp_epoch_ms"] or 0.0)
    return rows


def _normal_vs_observed(fset: BehavioralFeatureSet | None) -> dict[str, Any]:
    if fset is None:
        return {
            "available": False,
            "reason": "no behavioral feature set attached",
            "baseline_quality": None,
            "baseline_scope_used": None,
            "dimensions": [],
        }
    dimensions: list[dict[str, Any]] = []
    for name, label in _FEATURE_LABELS.items():
        feature = getattr(fset, name, None)
        value = feature.value if feature is not None else None
        availability = feature.availability.value if feature is not None else "unavailable"
        dimensions.append({
            "dimension": name,
            "label": label,
            "observed_score": value,
            "availability": availability,
            "provenance": feature.provenance if feature is not None else None,
            "comparison": (
                f"{label} scored {value:.2f} against a {fset.baseline_scope_used} baseline"
                if value is not None
                else f"{label} not measurable from available history"
            ),
        })
    return {
        "available": True,
        "baseline_quality": round(float(fset.baseline_quality), 6),
        "baseline_scope_used": fset.baseline_scope_used,
        "cold_start": fset.cold_start,
        "dimensions": dimensions,
    }


def _top_signals(contract: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    signals = contract.get("signals", {})
    contributions = signals.get("contributions") or {}
    ranked = sorted(contributions.items(), key=lambda kv: -float(kv[1]))
    out = [
        {"component": name, "contribution": round(float(value), 6)}
        for name, value in ranked[:limit]
    ]
    for rule in signals.get("fired_rules", []):
        out.append({"component": rule, "contribution": None, "kind": "rule"})
    return out


def build_dashboard_view(
    finding: SecurityFinding,
    *,
    session: DataAccessSession,
    scored: ScoredSession | None = None,
    fset: BehavioralFeatureSet | None = None,
    events: Iterable[Any] | None = None,
    arde: Any | None = None,
) -> dict[str, Any]:
    """Assemble the render-ready dashboard view for one finding."""
    contract = output_contract_of(finding) or build_output_contract(
        finding, session=session, scored=scored, fset=fset, arde=arde
    )
    return {
        "view_version": DASHBOARD_VIEW_VERSION,
        # headline
        "finding_id": finding.finding_id,
        "finding_type": contract["finding_type"],
        "severity": contract["severity"],
        "risk_score": contract["risk_score"],
        "confidence": contract["confidence"],
        "robustness_score": contract["robustness_score"],
        "robustness_level": contract["robustness_level"],
        "validation_status": contract["validation_status"],
        # who / what
        "actor": contract["actor"],
        "resource": contract["resource"],
        "session": contract["session"],
        "temporal_context": contract["temporal_context"],
        "data_volume": contract["data_volume"],
        "sensitivity": contract["sensitivity"],
        "destination": contract["destination"],
        # analytic panels
        "access_timeline": _timeline(session, events),
        "normal_vs_observed": _normal_vs_observed(fset),
        "top_signals": _top_signals(contract),
        "supporting_evidence": contract["supporting_evidence"],
        "contradicting_evidence": contract["contradicting_evidence"],
        "baseline_quality": contract["baseline_quality"],
        "feature_availability": contract["feature_availability"],
        "recommended_next_steps": contract["recommended_next_steps"],
        "versions": contract["versions"],
    }


def dashboard_view_of(finding: SecurityFinding, *, session: DataAccessSession, **kwargs: Any) -> dict[str, Any] | None:
    """Convenience wrapper that never raises on a missing session."""
    if session is None:
        return None
    return build_dashboard_view(finding, session=session, **kwargs)


__all__ = ["DASHBOARD_VIEW_VERSION", "build_dashboard_view", "dashboard_view_of"]
