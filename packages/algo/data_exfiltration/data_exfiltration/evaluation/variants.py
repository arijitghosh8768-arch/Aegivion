"""Variants A-E for the comparative evaluation.

Extends the Part 3 A/B/C/D ladder with:

- E: the FULL detector — behavior + volume + destination + sensitivity +
  access pattern + temporal + network evidence + ML anomaly + risk
  fusion + **ARDE validation**.

E's decision differs from D in one way: ARDE. A session is alerted when
the fused risk clears the threshold AND ARDE does not REJECT it.
PASSED_WITH_WARNINGS still alerts (warnings travel, they do not veto).
REVIEW_REQUIRED alerts at reduced confidence in the report but still
counts as an alert for measurement. This is the false-positive control
layer doing its job: suspicious-looking but internally inconsistent or
exception-explained activity gets challenged before it becomes a page.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.arde.models import ValidationStatus
from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import BehavioralFeatureSet
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack, ScoredSession
from algo.data_exfiltration.data_exfiltration.ml.replay import replay_sessions

from .dataset import LabeledRecord
from .scenarios import ScenarioBundle

ARDE_ALERT_BLOCKING = {ValidationStatus.REJECTED}
"""ARDE outcomes that veto an E-variant alert."""


@dataclass
class _ScoredWithArde:
    """ScoredSession + the ARDE verdict that reviewed it."""

    scored: ScoredSession
    validation_status: str | None = None
    robustness_score: float | None = None
    alert: bool = False
    alert_latency_ms: float | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.scored, name)


def score_with_arde(
    fset: BehavioralFeatureSet,
    stack: ScoringStack,
    *,
    validator: Any | None = None,
    threshold: float = 0.5,
    session: Any | None = None,
    finding_stub: Any | None = None,
) -> _ScoredWithArde:
    """Score one feature set; when a validator is supplied, apply ARDE."""
    scored = stack.score(fset)
    result = _ScoredWithArde(scored=scored, alert=scored.risk_score >= threshold)
    if validator is None or not result.alert or session is None:
        return result

    from algo.data_exfiltration.data_exfiltration.schemas import SecurityFinding

    stub = finding_stub or SecurityFinding(
        finding_id=f"eval-{fset.session_id}",
        detector_name="aegivion.data_exfiltration",
        title="evaluation finding",
        description="synthetic evaluation replay",
        observed_at_epoch_ms=fset.computed_at_epoch_ms,
        session_id=fset.session_id,
    )
    outcome = validator.validate(
        stub,
        session=session,
        scored=scored,
        fset=fset,
        observed_at_epoch_ms=fset.computed_at_epoch_ms,
    )
    result.validation_status = outcome.validation_status.value
    result.robustness_score = outcome.robustness_score
    if outcome.validation_status in {s.value for s in ARDE_ALERT_BLOCKING}:
        result.alert = False
    return result


def run_variants(
    records: list[LabeledRecord],
    stacks: dict[str, ScoringStack],
    *,
    validator: Any | None = None,
    sessions_by_id: dict[str, Any] | None = None,
    threshold: float = 0.5,
) -> dict[str, list[_ScoredWithArde]]:
    """Score every record under each variant (chronological replay order).

    Variant E additionally applies ARDE to alerted sessions.
    """
    ordered = sorted(records, key=lambda r: r.session.start_time_epoch_ms or 0.0)
    out: dict[str, list[_ScoredWithArde]] = {}
    for name, stack in sorted(stacks.items()):
        use_arde = name == "E" and validator is not None
        scored_list: list[_ScoredWithArde] = []
        for record in ordered:
            fset = record.session.session_features.get("_behavioral_feature_set")
            if fset is None:
                # feature sets are attached by the caller; skip honestly
                continue
            result = score_with_arde(
                fset,
                stack,
                validator=validator if use_arde else None,
                threshold=threshold,
                session=(sessions_by_id or {}).get(record.session_id),
            )
            scored_list.append(result)
        out[name] = scored_list
    return out
