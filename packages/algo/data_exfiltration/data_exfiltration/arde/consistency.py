"""Evidence consistency engine: the ten ARDE validation checks.

Each check challenges the finding from one angle and yields a
``ValidationCheckResult`` with its own machine-readable evidence:

1.  feature_consistency      - do the scored features contradict each other?
2.  provenance_completeness  - how much telemetry was actually present?
3.  volume_consistency       - is the volume story self-consistent?
4.  destination_consistency  - destination evidence vs claimed novelty
5.  sensitivity_consistency  - sensitivity claims backed by named sources?
6.  actor_resource_consistency - actor/resource relationship evidence sane?
7.  temporal_consistency     - timestamps sane and in the past?
8.  network_consistency      - egress/destination halves comparable?
9.  model_rule_agreement     - is the model overreacting to ONE feature?
10. baseline_quality_check   - how much trusted history backs the verdict?

Checks that cannot run abstain. An abstention is evidence of telemetry
incompleteness, never of innocence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoredSession
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession

from .models import CheckSeverity, CheckStatus, ValidationCheckResult

FEATURE_CONTRIBUTION_SHARE = 0.65
"""A single feature contributing more than this share of fused risk means
the model may be overreacting to one signal."""


class ARDEContext:
    """Everything the consistency engine may look at; nothing is mutated."""

    def __init__(
        self,
        *,
        session: DataAccessSession,
        scored: ScoredSession | None = None,
        fset: BehavioralFeatureSet | None = None,
        finding: Any = None,
    ) -> None:
        self.session = session
        self.scored = scored
        self.fset = fset
        self.finding = finding


class ConsistencyEngine:
    """Runs the ten checks. Deterministic, side-effect free."""

    def __init__(
        self,
        *,
        contribution_share: float = FEATURE_CONTRIBUTION_SHARE,
        thin_evidence_checks: int = 3,
        min_baseline_quality: float = 0.5,
    ) -> None:
        self._contribution_share = contribution_share
        self._thin_evidence_checks = thin_evidence_checks
        self._min_baseline_quality = min_baseline_quality

    # ------------------------------------------------------------------

    def run_checks(self, ctx: ARDEContext) -> list[ValidationCheckResult]:
        return [
            self.check_feature_consistency(ctx),
            self.check_provenance_completeness(ctx),
            self.check_volume_consistency(ctx),
            self.check_destination_consistency(ctx),
            self.check_sensitivity_consistency(ctx),
            self.check_actor_resource_consistency(ctx),
            self.check_temporal_consistency(ctx),
            self.check_network_consistency(ctx),
            self.check_model_rule_agreement(ctx),
            self.check_baseline_quality(ctx),
        ]

    # ------------------------------------------------------------------
    # 1. feature consistency
    # ------------------------------------------------------------------

    def check_feature_consistency(self, ctx: ARDEContext) -> ValidationCheckResult:
        """High risk must be corroborated by more than one feature family.

        A finding whose risk rests on a single loud feature while the
        others are quiet is a classic false-positive shape (huge but
        routine backup). Contradiction here is honest: low-corroboration
        high-risk findings get flagged for review.
        """
        result = ValidationCheckResult(
            check_name="feature_consistency",
            severity=CheckSeverity.INFLUENCING,
        )
        scored = ctx.scored
        if scored is None:
            result.status = CheckStatus.ABSTAINED
            result.message = "no scored session available"
            return result

        contributions = scored.contributions or {}
        if not contributions:
            result.status = CheckStatus.ABSTAINED
            result.message = "no contribution breakdown available"
            return result

        total = sum(contributions.values())
        top_name, top_value = max(contributions.items(), key=lambda kv: kv[1])
        share = (top_value / total) if total > 0 else 0.0

        # how many independent families actually contributed
        behavioral_families = {
            k for k in contributions
            if k not in ("anomaly", "rules", "supervised")
        }
        active_families = len(
            [k for k in behavioral_families if contributions.get(k, 0.0) > 0.0]
        )

        result.detail = {
            "top_contributor": top_name,
            "top_share": round(share, 4),
            "contributions": contributions,
            "active_behavioral_families": active_families,
        }

        if scored.risk_score >= 0.5 and share >= self._contribution_share:
            result.status = CheckStatus.FAILED
            result.message = (
                f"risk {scored.risk_score:.2f} dominated by one feature "
                f"({top_name}: {share:.0%} of contributions); possible model overreaction"
            )
            return result

        if scored.risk_score >= 0.5 and active_families < 2:
            result.status = CheckStatus.WARNING
            result.message = "elevated risk carried by a single feature family"
            return result

        result.status = CheckStatus.PASSED
        result.message = "risk is corroborated across feature families"
        return result

    # ------------------------------------------------------------------
    # 2. provenance completeness
    # ------------------------------------------------------------------

    def check_provenance_completeness(self, ctx: ARDEContext) -> ValidationCheckResult:
        """How much of the evidence actually exists?

        Unavailable features shrink the evidence base; a verdict built on
        few available features is fragile and must not sail through as
        PASSED. This is the "could telemetry be incomplete?" check.
        """
        result = ValidationCheckResult(
            check_name="provenance_completeness",
            severity=CheckSeverity.INFLUENCING,
        )
        fset = ctx.fset
        if fset is None:
            result.status = CheckStatus.ABSTAINED
            result.message = "no behavioral feature set available"
            return result

        availability = fset.feature_availability or {
            name: getattr(fset, name).availability.value
            for name in (
                "volume_score", "object_count_score", "request_rate_score",
                "destination_score", "access_pattern_score", "sensitivity_score",
                "time_score", "actor_resource_score", "egress_score",
            )
        }
        total = len(availability)
        available = sum(1 for v in availability.values() if v != FeatureAvailability.UNAVAILABLE.value)
        observed = sum(1 for v in availability.values() if v == FeatureAvailability.OBSERVED.value)
        unavailable = sorted(k for k, v in availability.items() if v == FeatureAvailability.UNAVAILABLE.value)
        share = available / total if total else 0.0

        result.detail = {
            "available_share": round(share, 4),
            "observed_features": observed,
            "unavailable_features": unavailable,
        }

        if share < 0.5:
            result.status = CheckStatus.FAILED
            result.message = (
                f"only {available}/{total} features measurable; "
                "evidence base too thin for an unqualified verdict"
            )
        elif unavailable:
            result.status = CheckStatus.WARNING
            result.message = "some telemetry unavailable: " + ", ".join(unavailable)
        else:
            result.status = CheckStatus.PASSED
            result.message = "all behavioral features were measurable"
        return result

    # ------------------------------------------------------------------
    # 3. volume consistency
    # ------------------------------------------------------------------

    def check_volume_consistency(self, ctx: ARDEContext) -> ValidationCheckResult:
        """The volume story must add up.

        - conflicting byte sources (CloudTrail vs flow logs disagreeing)
          are flagged, never averaged;
        - 'read-like' sessions (reads/lists, no writes) with large
          egress but no destination evidence get a warning;
        - missing bytes keep the check honest (abstain on the byte
          sub-evidence, warn on the session as a whole).
        """
        result = ValidationCheckResult(
            check_name="volume_consistency",
            severity=CheckSeverity.INFLUENCING,
        )
        session = ctx.session
        details: dict[str, Any] = {}
        statuses: list[CheckStatus] = []

        bytes_m = session.bytes_accessed
        if bytes_m is not None and bytes_m.measurements:
            details["bytes_total"] = bytes_m.value
            details["bytes_sources_conflict"] = bytes_m.has_conflict
            if bytes_m.has_conflict:
                statuses.append(CheckStatus.WARNING)
                details["bytes_conflict_detail"] = bytes_m.provenance()["contributions"]
        else:
            statuses.append(CheckStatus.ABSTAINED)
            details["bytes_presence"] = "unavailable"

        egress = session.network_egress_bytes
        if egress is not None and egress.measurements:
            details["network_egress_bytes"] = egress.value
            details["egress_sources_conflict"] = egress.has_conflict
            if egress.has_conflict:
                statuses.append(CheckStatus.WARNING)
        else:
            statuses.append(CheckStatus.ABSTAINED)
            details["egress_presence"] = "unavailable"

        # write-like activity without bytes measured is suspicious of
        # incomplete telemetry; read-only sessions cannot 'upload'
        if (
            session.write_event_count == 0
            and session.read_event_count > 0
            and egress is not None
            and egress.measurements
            and bytes_m is not None
            and bytes_m.measurements
            and (bytes_m.value or 0.0) > 0
            and (egress.value or 0.0) > 4.0 * (bytes_m.value or 0.0)
        ):
            statuses.append(CheckStatus.WARNING)
            details["egress_exceeds_data_access"] = True

        if CheckStatus.WARNING in statuses:
            result.status = CheckStatus.WARNING
            result.message = "volume measurements conflict or look implausible"
        elif all(s is CheckStatus.ABSTAINED for s in statuses):
            result.status = CheckStatus.ABSTAINED
            result.message = "no volume telemetry present"
        elif CheckStatus.ABSTAINED in statuses:
            result.status = CheckStatus.WARNING
            result.message = "volume telemetry partially present"
        else:
            result.status = CheckStatus.PASSED
            result.message = "volume measurements consistent"
        result.detail = details
        return result

    # ------------------------------------------------------------------
    # 4. destination consistency
    # ------------------------------------------------------------------

    def check_destination_consistency(self, ctx: ARDEContext) -> ValidationCheckResult:
        """Destination evidence must match the claimed destination risk.

        If the fusion treated the destination as a contributor, there
        must actually BE destination telemetry; novelty claims require a
        supplied known-universe. 'Unknown because we never looked' is a
        warning, not evidence.
        """
        result = ValidationCheckResult(
            check_name="destination_consistency",
            severity=CheckSeverity.INFLUENCING,
        )
        session = ctx.session
        fset = ctx.fset
        details: dict[str, Any] = {
            "unique_destinations": len(session.unique_destinations),
        }

        dest_feature = fset.destination_score if fset is not None else None
        dest_available = (
            dest_feature is not None and dest_feature.value is not None
        )

        if not session.unique_destinations:
            if dest_available and (dest_feature.value or 0.0) > 0.5:
                result.status = CheckStatus.FAILED
                result.message = (
                    "destination risk scored high with no destination telemetry"
                )
                return result
            result.status = CheckStatus.ABSTAINED
            result.message = "no destination telemetry in session"
            result.detail = details
            return result

        detail_map = dest_feature.detail if dest_feature is not None else {}
        universe_supplied = bool(detail_map.get("known_universe_supplied", {})) and any(
            detail_map.get("known_universe_supplied", {}).values()
        )
        if dest_available and not universe_supplied:
            result.status = CheckStatus.WARNING
            result.message = (
                "destination novelty judged without a supplied known-universe"
            )
        elif dest_available:
            result.status = CheckStatus.PASSED
            result.message = "destination evidence present and classified against a known universe"
        else:
            result.status = CheckStatus.WARNING
            result.message = "destinations observed but destination scoring unavailable"
        result.detail = details
        return result

    # ------------------------------------------------------------------
    # 5. sensitivity consistency
    # ------------------------------------------------------------------

    def check_sensitivity_consistency(self, ctx: ARDEContext) -> ValidationCheckResult:
        """Sensitivity must come from named external sources.

        A high sensitivity score with no identifiable source would mean
        the engine classified content itself — forbidden. Also checks
        the finding's sensitivity claims line up with the session.
        """
        result = ValidationCheckResult(
            check_name="sensitivity_consistency",
            severity=CheckSeverity.INFLUENCING,
        )
        session = ctx.session
        fset = ctx.fset
        details: dict[str, Any] = {}

        sens_feature = fset.sensitivity_score if fset is not None else None
        sens_value = sens_feature.value if sens_feature is not None else None

        session_sens = (
            session.sensitivity_summary.measurement.value
            if session.sensitivity_summary is not None
            and session.sensitivity_summary.measurement is not None
            else None
        )

        details["session_sensitivity"] = session_sens
        details["feature_sensitivity"] = sens_value

        if sens_value is None and session_sens is None:
            result.status = CheckStatus.ABSTAINED
            result.message = "no sensitivity enrichment available"
            return result

        source = sens_feature.provenance if sens_feature is not None else None
        details["sensitivity_source"] = source
        if sens_value is not None and sens_value >= 0.5 and not source:
            result.status = CheckStatus.FAILED
            result.message = "sensitivity scored high with no named source"
            return result

        # feature value should not exceed what the session evidence supports
        # by a wide margin (tolerance for registry-vs-session differences)
        if (
            sens_value is not None
            and session_sens is not None
            and sens_value - session_sens > 0.4
        ):
            result.status = CheckStatus.WARNING
            result.message = "feature sensitivity far exceeds session enrichment evidence"
            return result

        result.status = CheckStatus.PASSED
        result.message = "sensitivity evidence carries a named external source"
        return result

    # ------------------------------------------------------------------
    # 6. actor-resource consistency
    # ------------------------------------------------------------------

    def check_actor_resource_consistency(self, ctx: ARDEContext) -> ValidationCheckResult:
        """Actor/resource novelty evidence must be internally coherent.

        An actor-resource novelty score requires the actor to be
        identifiable. Sessions with no actor identity cannot support
        'unexpected actor' claims.
        """
        result = ValidationCheckResult(
            check_name="actor_resource_consistency",
            severity=CheckSeverity.INFLUENCING,
        )
        session = ctx.session
        fset = ctx.fset

        ar_feature = fset.actor_resource_score if fset is not None else None
        ar_value = ar_feature.value if ar_feature is not None else None

        if ar_value is None:
            result.status = CheckStatus.ABSTAINED
            result.message = "actor-resource relationship history unavailable"
            result.detail = {"actor_id": session.actor_id}
            return result

        if not session.actor_id:
            result.status = CheckStatus.FAILED
            result.message = "actor-resource novelty scored without actor identity"
            return result

        detail = ar_feature.detail or {}
        history_available = detail.get("history_available")
        if ar_value >= 0.5 and history_available is False:
            result.status = CheckStatus.FAILED
            result.message = "actor-resource novelty scored with no relationship history"
            return result

        result.status = CheckStatus.PASSED
        result.message = "actor-resource evidence coherent"
        result.detail = {
            "actor_id": session.actor_id,
            "actor_resource_novelty": ar_value,
            "history_available": history_available,
        }
        return result

    # ------------------------------------------------------------------
    # 7. temporal consistency
    # ------------------------------------------------------------------

    def check_temporal_consistency(self, ctx: ARDEContext) -> ValidationCheckResult:
        """Timestamps must be present, ordered, and not from the future.

        Corrupted clocks (end before start, times years ahead) poison
        every downstream window and must be caught before fusion output
        is trusted.
        """
        result = ValidationCheckResult(
            check_name="temporal_consistency",
            severity=CheckSeverity.CRITICAL,
        )
        session = ctx.session
        start = session.start_time_epoch_ms
        end = session.end_time_epoch_ms

        details: dict[str, Any] = {
            "start_time_epoch_ms": start,
            "end_time_epoch_ms": end,
        }

        if start is None or end is None:
            result.status = CheckStatus.FAILED
            result.message = "session missing start or end timestamp"
            result.detail = details
            return result

        if end < start:
            result.status = CheckStatus.FAILED
            result.message = "session ends before it starts (corrupted timestamps)"
            result.detail = details
            return result

        now_ms = datetime.now(timezone.utc).timestamp() * 1000.0
        skew_tolerance_ms = 15 * 60 * 1000.0
        if end > now_ms + skew_tolerance_ms:
            result.status = CheckStatus.FAILED
            result.message = "session timestamp is in the future (clock skew?)"
            details["now_epoch_ms"] = now_ms
            result.detail = details
            return result

        duration_s = (end - start) / 1000.0
        details["duration_seconds"] = duration_s
        if duration_s <= 0 and session.event_count > 1:
            result.status = CheckStatus.WARNING
            result.message = "multiple events share one timestamp (zero-length session)"
            result.detail = details
            return result

        result.status = CheckStatus.PASSED
        result.message = "timestamps ordered and plausible"
        result.detail = details
        return result

    # ------------------------------------------------------------------
    # 8. network consistency
    # ------------------------------------------------------------------

    def check_network_consistency(self, ctx: ARDEContext) -> ValidationCheckResult:
        """Egress claims need comparable halves.

        egress_ratio requires both network bytes and data-access bytes.
        Where only one half exists, egress-derived risk is unsupported;
        where the halves conflict, the ratio is unstable.
        """
        result = ValidationCheckResult(
            check_name="network_consistency",
            severity=CheckSeverity.INFLUENCING,
        )
        session = ctx.session
        fset = ctx.fset

        egress_feature = fset.egress_score if fset is not None else None
        details: dict[str, Any] = {}

        if egress_feature is None:
            result.status = CheckStatus.ABSTAINED
            result.message = "no egress assessment available"
            return result

        details["availability"] = egress_feature.availability.value
        details["detail"] = {
            k: v for k, v in (egress_feature.detail or {}).items()
            if k in ("egress_ratio", "external_egress_ratio", "network_egress_bytes",
                     "data_access_bytes", "sources_conflict")
        }

        if egress_feature.value is None:
            # no egress score: only a problem if some risk was attributed to egress
            result.status = CheckStatus.ABSTAINED
            result.message = "egress ratio not computable (missing or uncomparable halves)"
            result.detail = details
            return result

        if (egress_feature.detail or {}).get("sources_conflict"):
            result.status = CheckStatus.WARNING
            result.message = "network telemetry sources disagree on egress"
            result.detail = details
            return result

        result.status = CheckStatus.PASSED
        result.message = "network evidence comparable and consistent"
        result.detail = details
        return result

    # ------------------------------------------------------------------
    # 9. model-rule agreement
    # ------------------------------------------------------------------

    def check_model_rule_agreement(self, ctx: ARDEContext) -> ValidationCheckResult:
        """Is the model overreacting to one feature?

        Compares the transparent rules score with the fused risk and
        with the ML anomaly component. Large disagreement (fusion far
        above what the transparent rules support) means the verdict
        rests on opaque components and needs review.
        """
        result = ValidationCheckResult(
            check_name="model_rule_agreement",
            severity=CheckSeverity.INFLUENCING,
        )
        scored = ctx.scored
        if scored is None or scored.rules_score is None:
            result.status = CheckStatus.ABSTAINED
            result.message = "rules score unavailable for comparison"
            return result

        gap = scored.risk_score - scored.rules_score
        anomaly_gap = (
            (scored.anomaly_score - scored.rules_score)
            if scored.anomaly_score is not None else None
        )
        details = {
            "risk_score": scored.risk_score,
            "rules_score": scored.rules_score,
            "fusion_minus_rules": round(gap, 4),
            "anomaly_minus_rules": round(anomaly_gap, 4) if anomaly_gap is not None else None,
        }

        if gap > 0.4:
            result.status = CheckStatus.WARNING
            result.message = (
                f"fused risk exceeds the transparent rules score by {gap:.2f}; "
                "verdict leans on non-rule components"
            )
        else:
            result.status = CheckStatus.PASSED
            result.message = "fused risk consistent with transparent rules"
        result.detail = details
        return result

    # ------------------------------------------------------------------
    # 10. baseline quality
    # ------------------------------------------------------------------

    def check_baseline_quality(self, ctx: ARDEContext) -> ValidationCheckResult:
        """How much trusted history backs the 'this is unusual' claim?

        Cold-start baselines (peer fallback, thin history) cannot prove
        deviation. Deviations asserted from a poor baseline get downgraded
        to warnings; strong deviations on NO baseline are rejected as
        unsupported.
        """
        result = ValidationCheckResult(
            check_name="baseline_quality_check",
            severity=CheckSeverity.INFLUENCING,
        )
        fset = ctx.fset
        if fset is None:
            result.status = CheckStatus.ABSTAINED
            result.message = "no behavioral feature set available"
            return result

        quality = float(fset.baseline_quality)
        scope = fset.baseline_scope_used
        details = {
            "baseline_quality": round(quality, 4),
            "baseline_scope": scope,
            "cold_start": fset.cold_start,
        }

        volume = fset.volume_score.value if fset.volume_score else None
        object_dev = fset.object_count_score.value if fset.object_count_score else None
        strongest = max([v for v in (volume, object_dev) if v is not None], default=None)

        if quality >= self._min_baseline_quality:
            result.status = CheckStatus.PASSED
            result.message = "baseline adequately populated"
        elif strongest is not None and strongest >= 0.5:
            # strong deviation claim on a weak baseline
            if quality <= 0.05:
                result.status = CheckStatus.FAILED
                result.message = (
                    "strong volume deviation asserted with effectively no trusted baseline"
                )
            else:
                result.status = CheckStatus.WARNING
                result.message = (
                    "deviation claim rests on a thin baseline "
                    f"(quality={quality:.2f}, scope={scope})"
                )
        else:
            # weak baseline but no strong deviation claim: fine
            result.status = CheckStatus.PASSED
            result.message = "baseline thin but no strong deviation claim depends on it"
        result.detail = details
        return result
