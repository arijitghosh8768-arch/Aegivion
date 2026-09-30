"""Machine-readable explainability.

Every validated finding carries a structured explanation answering:

- WHAT happened?
- WHY is it unusual?
- What is the normal baseline?
- What changed?
- What data was involved?
- How sensitive was it?
- Where did the data appear to move?
- Which signals contributed most?
- Which signals contradicted the finding?
- What telemetry was unavailable?

The future LLM explanation layer may render this structure into prose.
**The LLM must never create evidence that is absent from this
structure** — that constraint is why the structure exists.

Field naming follows the contract example: ``top_contributors``,
``supporting_evidence``, ``contradicting_evidence``, ``baseline_quality``,
``feature_availability``, ``model_agreement``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoredSession
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession

from .models import CheckStatus, ValidationOutcome


class FindingExplanation(BaseModel):
    """The complete, self-contained explanation of one finding."""

    finding_id: str
    session_id: str | None = None
    what_happened: str
    why_unusual: list[str] = Field(default_factory=list)
    normal_baseline: dict[str, Any] = Field(default_factory=dict)
    what_changed: list[str] = Field(default_factory=list)
    data_involved: dict[str, Any] = Field(default_factory=dict)
    sensitivity: dict[str, Any] = Field(default_factory=dict)
    data_movement: dict[str, Any] = Field(default_factory=dict)

    top_contributors: list[str] = Field(default_factory=list)
    supporting_evidence: list[dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: list[dict[str, Any]] = Field(default_factory=list)

    baseline_quality: str = "UNKNOWN"
    """GOOD | FAIR | POOR | NONE | UNKNOWN."""
    feature_availability: str = "UNKNOWN"
    """HIGH | MEDIUM | LOW | UNKNOWN."""
    model_agreement: str = "UNKNOWN"
    """STRONG | PARTIAL | WEAK | UNKNOWN."""

    unavailable_telemetry: list[str] = Field(default_factory=list)
    validation: dict[str, Any] = Field(default_factory=dict)
    """Validation status, robustness, exceptions — explanation of trust."""
    generated_at_epoch_ms: float | None = None


class ExplainabilityBuilder:
    """Builds FindingExplanation from everything the pipeline knows."""

    def __init__(self, *, top_n_contributors: int = 4) -> None:
        self._top_n = top_n_contributors

    def build(
        self,
        finding: Any,
        *,
        session: DataAccessSession,
        scored: ScoredSession | None = None,
        fset: BehavioralFeatureSet | None = None,
        outcome: ValidationOutcome | None = None,
    ) -> FindingExplanation:
        now_ms = datetime.now(timezone.utc).timestamp() * 1000.0
        actor = session.actor_id or "an unknown actor"
        resources = session.resources_accessed or []

        # --- WHAT happened --------------------------------------------------
        what = (
            f"Session {session.session_id}: {actor} performed "
            f"{session.event_count} data event(s) over "
            f"{len(resources)} resource(s) "
            f"({session.read_event_count} read, {session.write_event_count} write, "
            f"{session.enumerate_list_count} list/enumerate)."
        )

        # --- data involved ----------------------------------------------------
        bytes_total = (
            session.bytes_accessed.value
            if session.bytes_accessed is not None and session.bytes_accessed.measurements
            else None
        )
        data_involved: dict[str, Any] = {
            "resources": resources,
            "objects_accessed": session.objects_accessed,
            "bytes_total": bytes_total,
            "bytes_presence": (
                session.bytes_accessed.presence.value
                if session.bytes_accessed is not None else "unavailable"
            ),
            "request_count": session.request_count,
        }

        # --- sensitivity --------------------------------------------------------
        sens_value = (
            fset.sensitivity_score.value
            if fset is not None and fset.sensitivity_score else None
        )
        sensitivity = {
            "score": sens_value,
            "source": (
                fset.sensitivity_score.provenance
                if fset is not None and fset.sensitivity_score else None
            ),
            "note": "sensitivity comes only from external enrichment (Macie/registry)",
        }

        # --- data movement ---------------------------------------------------------
        egress = (
            fset.egress_score.detail if fset is not None and fset.egress_score else {}
        )
        data_movement = {
            "unique_destinations": session.unique_destinations,
            "unique_asns": session.unique_asns,
            "unique_countries": session.unique_countries,
            "network_egress_bytes": egress.get("network_egress_bytes"),
            "egress_ratio": egress.get("egress_ratio"),
            "external_egress_ratio": egress.get("external_egress_ratio"),
        }

        # --- WHY unusual + WHAT changed: from contributions and rules -----------
        contributions = scored.contributions if scored is not None else {}
        top_contributors = self._top_contributor_phrases(contributions, scored)
        why_unusual = list(top_contributors)
        if scored is not None and scored.fired_rules:
            why_unusual.append("rules fired: " + ", ".join(scored.fired_rules))

        # --- normal baseline -------------------------------------------------------
        normal_baseline = self._baseline_summary(fset)

        # --- what changed (delta vs baseline, when available) -----------------------
        what_changed = self._what_changed(fset, scored)

        # --- supporting / contradicting evidence --------------------------------------
        supporting, contradicting = self._evidence(scored, fset, outcome)

        # --- unavailable telemetry -------------------------------------------------------
        unavailable = self._unavailable_telemetry(fset, session)

        # --- trust grades ---------------------------------------------------------------------
        baseline_quality = self._baseline_quality_grade(fset)
        feature_availability = self._availability_grade(fset)
        model_agreement = self._model_agreement_grade(scored)

        validation_block: dict[str, Any] = {}
        if outcome is not None:
            validation_block = {
                "validation_status": outcome.validation_status.value,
                "robustness_score": outcome.robustness_score,
                "robustness_level": outcome.robustness_level.value,
                "exceptions_applied": outcome.exceptions_applied,
                "downgrade": outcome.downgrade,
                "failed_checks": [
                    c.check_name for c in outcome.checks if c.status is CheckStatus.FAILED
                ],
                "warning_checks": [
                    c.check_name for c in outcome.checks if c.status is CheckStatus.WARNING
                ],
            }

        return FindingExplanation(
            finding_id=finding.finding_id,
            session_id=finding.session_id,
            what_happened=what,
            why_unusual=why_unusual,
            normal_baseline=normal_baseline,
            what_changed=what_changed,
            data_involved=data_involved,
            sensitivity=sensitivity,
            data_movement=data_movement,
            top_contributors=top_contributors,
            supporting_evidence=supporting,
            contradicting_evidence=contradicting,
            baseline_quality=baseline_quality,
            feature_availability=feature_availability,
            model_agreement=model_agreement,
            unavailable_telemetry=unavailable,
            validation=validation_block,
            generated_at_epoch_ms=now_ms,
        )

    # ------------------------------------------------------------------

    def _top_contributor_phrases(
        self,
        contributions: dict[str, float],
        scored: ScoredSession | None,
    ) -> list[str]:
        """Human-readable phrases, e.g. '8.4x normal object access'.

        Descriptions come ONLY from measured evidence in the feature
        details — never invented.
        """
        phrases: list[str] = []
        if not contributions:
            return phrases
        ranked = sorted(contributions.items(), key=lambda kv: kv[1], reverse=True)
        for name, value in ranked[: self._top_n]:
            if value <= 0:
                continue
            phrases.append(f"{self._label(name)} (weighted contribution {value:.2f})")
        return phrases

    @staticmethod
    def _label(component: str) -> str:
        return {
            "volume": "elevated data volume vs baseline",
            "object_count": "unusual object-access count",
            "request_rate": "elevated request rate",
            "destination": "new or risky destination",
            "access_pattern": "unusual access pattern",
            "sensitivity": "sensitive data accessed",
            "time": "unusual access time",
            "actor_resource": "actor-resource relationship novelty",
            "egress": "high network egress",
            "anomaly": "ML anomaly signal",
            "supervised": "supervised model signal",
            "rules": "transparent rule signals",
        }.get(component, component)

    @staticmethod
    def _baseline_summary(fset: BehavioralFeatureSet | None) -> dict[str, Any]:
        if fset is None:
            return {"status": "unavailable"}
        windows = (
            fset.volume_score.detail.get("windows")
            if fset.volume_score is not None else None
        )
        return {
            "baseline_scope": fset.baseline_scope_used,
            "baseline_quality": round(float(fset.baseline_quality), 4),
            "cold_start": fset.cold_start,
            "volume_windows_evaluated": windows or [],
            "note": (
                "baseline compares the session against the actor's trusted "
                "history using median/MAD robust statistics"
            ),
        }

    @staticmethod
    def _what_changed(
        fset: BehavioralFeatureSet | None,
        scored: ScoredSession | None,
    ) -> list[str]:
        changed: list[str] = []
        if fset is None:
            return changed
        checks = (
            ("volume_score", "volume vs history"),
            ("destination_score", "destination mix vs known universe"),
            ("access_pattern_score", "access pattern vs history"),
            ("time_score", "access time vs history"),
            ("actor_resource_score", "actor-resource relationship vs history"),
            ("egress_score", "network egress vs data volume"),
        )
        for attr, label in checks:
            feature = getattr(fset, attr, None)
            if feature is not None and feature.value is not None and feature.value >= 0.4:
                changed.append(label)
        return changed

    @staticmethod
    def _evidence(
        scored: ScoredSession | None,
        fset: BehavioralFeatureSet | None,
        outcome: ValidationOutcome | None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        supporting: list[dict[str, Any]] = []
        contradicting: list[dict[str, Any]] = []

        if scored is not None:
            supporting.append({
                "kind": "fused_risk",
                "value": scored.risk_score,
                "note": "weighted fusion over available behavioral features",
            })
            for rule in scored.fired_rules:
                supporting.append({"kind": "fired_rule", "value": rule})

        if fset is not None:
            quiet_signals = []
            for attr in ("volume_score", "destination_score", "access_pattern_score",
                         "time_score", "actor_resource_score", "egress_score"):
                feature = getattr(fset, attr, None)
                if feature is not None and feature.value is not None and feature.value < 0.2:
                    quiet_signals.append(attr)
            if quiet_signals:
                contradicting.append({
                    "kind": "quiet_signals",
                    "value": quiet_signals,
                    "note": "these behavioral dimensions look normal",
                })
            if fset.cold_start:
                contradicting.append({
                    "kind": "cold_start_baseline",
                    "value": fset.baseline_scope_used,
                    "note": "deviations judged against cold-start/peer baseline",
                })

        if outcome is not None:
            for check in outcome.checks:
                if check.status is CheckStatus.FAILED:
                    contradicting.append({
                        "kind": "failed_validation_check",
                        "value": check.check_name,
                        "note": check.message,
                    })
                elif check.status is CheckStatus.WARNING:
                    contradicting.append({
                        "kind": "validation_warning",
                        "value": check.check_name,
                        "note": check.message,
                    })
            if outcome.exceptions_applied:
                contradicting.append({
                    "kind": "approved_activity_exception",
                    "value": [r["profile_name"] for r in outcome.exceptions_applied if r.get("matched")],
                    "note": "activity matched an approved-activity profile; requires review",
                })
        return supporting, contradicting

    @staticmethod
    def _unavailable_telemetry(
        fset: BehavioralFeatureSet | None,
        session: DataAccessSession,
    ) -> list[str]:
        unavailable: list[str] = []
        if fset is not None:
            availability = fset.feature_availability or {}
            labels = {
                "volume_score": "volume history",
                "object_count_score": "object-count history",
                "request_rate_score": "request-rate history",
                "destination_score": "destination telemetry / known universe",
                "access_pattern_score": "access-pattern history",
                "sensitivity_score": "sensitivity enrichment",
                "time_score": "time-of-day history",
                "actor_resource_score": "actor-resource history",
                "egress_score": "network flow telemetry",
            }
            for name, label in labels.items():
                if availability.get(name) == FeatureAvailability.UNAVAILABLE.value:
                    unavailable.append(label)
        if session.bytes_accessed is None or not session.bytes_accessed.measurements:
            unavailable.append("byte counts (no contributing event measured bytes)")
        if session.network_egress_bytes is None or not session.network_egress_bytes.measurements:
            unavailable.append("network egress bytes (no correlated flow records)")
        if session.sensitivity_summary is None:
            unavailable.append("sensitivity enrichment (no Macie/registry data)")
        # de-duplicate, preserve order
        seen: set[str] = set()
        ordered = [u for u in unavailable if not (u in seen or seen.add(u))]
        return ordered

    @staticmethod
    def _grade(
        value: float | None,
        bands: tuple[tuple[float, str], ...],
        none_label: str,
    ) -> str:
        if value is None:
            return none_label
        for threshold, label in bands:
            if value >= threshold:
                return label
        return bands[-1][1]

    def _baseline_quality_grade(self, fset: BehavioralFeatureSet | None) -> str:
        value = float(fset.baseline_quality) if fset is not None else None
        return self._grade(
            value,
            ((0.75, "GOOD"), (0.4, "FAIR"), (0.05, "POOR")),
            "NONE",
        )

    def _availability_grade(self, fset: BehavioralFeatureSet | None) -> str:
        if fset is None:
            return "UNKNOWN"
        availability = fset.feature_availability or {}
        if not availability:
            return "UNKNOWN"
        share = sum(
            1 for v in availability.values() if v != FeatureAvailability.UNAVAILABLE.value
        ) / len(availability)
        return self._grade(share, ((0.8, "HIGH"), (0.5, "MEDIUM")), "LOW")

    @staticmethod
    def _model_agreement_grade(scored: ScoredSession | None) -> str:
        if scored is None or scored.rules_score is None:
            return "UNKNOWN"
        gap = abs(scored.risk_score - scored.rules_score)
        if gap <= 0.15:
            return "STRONG"
        if gap <= 0.4:
            return "PARTIAL"
        return "WEAK"
