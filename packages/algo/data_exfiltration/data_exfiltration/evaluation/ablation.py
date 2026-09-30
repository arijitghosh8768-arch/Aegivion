"""Ablation study: remove one component at a time, measure the change.

Components under test (the contract's list): volume, destination,
sensitivity, access pattern, time, network egress, ML, ARDE.

Method: each ablation produces a feature set copy in which the removed
component's features are marked UNAVAILABLE (the fusion renormalizes —
exactly what production would experience if that signal source were
dark). ML ablation removes the anomaly model from the stack. ARDE
ablation disables the validator for variant E. Deltas are measured on
the SAME test period against the full variant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    AvailableFeature,
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack

ABLATABLE_COMPONENTS = (
    "volume",
    "destination",
    "sensitivity",
    "access_pattern",
    "time",
    "network_egress",
    "ml",
    "arde",
)

_FEATURE_GROUP = {
    "volume": ("volume_score", "object_count_score", "request_rate_score"),
    "destination": ("destination_score",),
    "sensitivity": ("sensitivity_score",),
    "access_pattern": ("access_pattern_score",),
    "time": ("time_score",),
    "network_egress": ("egress_score",),
}


@dataclass
class AblationResult:
    component: str
    metrics: dict[str, Any] = field(default_factory=dict)
    delta_f1: float | None = None
    delta_recall: float | None = None
    delta_precision: float | None = None
    delta_fpr: float | None = None
    delta_pr_auc: float | None = None


def ablate_features(
    fset: BehavioralFeatureSet,
    component: str,
) -> BehavioralFeatureSet:
    """Return a copy with the component's features marked unavailable."""
    if component not in _FEATURE_GROUP:
        return fset
    copy = fset.model_copy(deep=True)
    for name in _FEATURE_GROUP[component]:
        feature: AvailableFeature = getattr(copy, name)
        feature.value = None
        feature.availability = FeatureAvailability.UNAVAILABLE
        feature.provenance = f"ablated:{component}"
    return copy.finalize()


def ablate_stack(stack: ScoringStack, component: str) -> ScoringStack:
    """Return a stack copy without the ML component when ablated."""
    if component != "ml":
        return stack
    import dataclasses

    return dataclasses.replace(stack, anomaly_model=None, supervised_model=None)


def run_ablation(
    records: Sequence[Any],
    full_stack: ScoringStack,
    *,
    score_fn: Any,
    baseline_metrics: dict[str, Any],
    components: Sequence[str] = ABLATABLE_COMPONENTS,
) -> list[AblationResult]:
    """Run leave-one-out ablations with a caller-supplied scoring function.

    ``score_fn(component, stack, records_iter)`` must yield
    (scores, labels, extras) for the given ablated stack; this keeps the
    ablation composable with both the pure-fusion and ARDE-gated paths.
    """
    results: list[AblationResult] = []
    for component in components:
        if component in ("arde",):
            # ARDE ablation is handled by the caller (needs validator)
            continue
        def records_iter(c=component):
            for record in records:
                yield record, ablate_features(
                    record.session.session_features["_behavioral_feature_set"], c
                )
        scores, labels, _extras = score_fn(component, ablate_stack(full_stack, component), records_iter())
        from .metrics import full_metrics

        m = full_metrics(scores, labels)
        results.append(
            AblationResult(
                component=component,
                metrics=m,
                delta_f1=_delta(m.get("f1"), baseline_metrics.get("f1")),
                delta_recall=_delta(m.get("recall"), baseline_metrics.get("recall")),
                delta_precision=_delta(m.get("precision"), baseline_metrics.get("precision")),
                delta_fpr=_delta(m.get("false_positive_rate"), baseline_metrics.get("false_positive_rate")),
                delta_pr_auc=_delta(m.get("pr_auc"), baseline_metrics.get("pr_auc")),
            )
        )
    return results


def _delta(ablated: float | None, baseline: float | None) -> float | None:
    if ablated is None or baseline is None:
        return None
    from algo.data_exfiltration.data_exfiltration.ml.evaluation import _r

    return _r(ablated - baseline)
