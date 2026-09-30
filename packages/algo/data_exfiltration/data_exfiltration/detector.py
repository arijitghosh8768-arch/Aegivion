"""Detector orchestration: end-to-end Part 1 pipeline.

    telemetry dicts
        -> EventNormalizer          (provider-specific, provenance-carrying)
        -> enrichment               (Macie sensitivity, geo — optional)
        -> SessionBuilder           (per-actor inactivity-gap sessions)
        -> flow correlation         (VPC flow evidence onto sessions)
        -> ResourceProfileBuilder   (observed resource history)
        -> feature extraction       (deterministic, documented)
        -> analysis modules         (volume / destination / access / sensitivity)
        -> discovery findings       (ARDE evidence documents)
        -> DetectionRepository      (persistence)

Part 1 emits evidence-complete discovery findings; Part 2 profiles
behavior; Part 3 scores risk/confidence/severity; Part 4 (ARDE)
validates and explains candidate findings before they are released.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from algo.data_exfiltration.data_exfiltration.base import AnalysisResult
from algo.data_exfiltration.data_exfiltration.config import DetectorConfig
from algo.data_exfiltration.data_exfiltration.exceptions import (
    MalformedEventError,
    NormalizationError,
    UnsupportedEventError,
)
from algo.data_exfiltration.data_exfiltration.features import attach_features, extract_features
from algo.data_exfiltration.data_exfiltration.finding import build_discovery_finding
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.raw_store import RawEventStore
from algo.data_exfiltration.data_exfiltration.resource_profile import ResourceProfileBuilder
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession, DataResourceProfile, FindingSeverity, Provider, SecurityFinding
from algo.data_exfiltration.data_exfiltration.session import SessionBuilder
from algo.data_exfiltration.data_exfiltration.storage import DetectionRepository

# Analysis modules (imported lazily-tolerant so the module list stays honest)
from algo.data_exfiltration.data_exfiltration.volume import VolumeAnalyzer
from algo.data_exfiltration.data_exfiltration.destination import DestinationAnalyzer
from algo.data_exfiltration.data_exfiltration.access_pattern import AccessPatternAnalyzer
from algo.data_exfiltration.data_exfiltration.sensitivity import SensitivityAnalyzer

# Part 2 behavioral intelligence (type-check-time imports only)
from algo.data_exfiltration.data_exfiltration.intelligence.baseline_guard import BaselineInfluence
from algo.data_exfiltration.data_exfiltration.intelligence.profiler import (
    BehavioralProfiler,
    IntelligenceContext,
)

# Part 4 ARDE validation + explainability (optional stage)
from algo.data_exfiltration.data_exfiltration.arde import ARDEValidator, AuditLog
from algo.data_exfiltration.data_exfiltration.arde.integration import validate_and_attach


@dataclass
class PipelineStats:
    """Honest counters for what the pipeline actually did."""

    events_in: int = 0
    events_normalized: int = 0
    events_skipped_unsupported: int = 0
    events_malformed: int = 0
    flows_in: int = 0
    flows_normalized: int = 0
    flows_skipped_unsupported: int = 0
    flows_malformed: int = 0
    sessions_built: int = 0
    sessions_with_flow_evidence: int = 0
    findings_emitted: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "events_in": self.events_in,
            "events_normalized": self.events_normalized,
            "events_skipped_unsupported": self.events_skipped_unsupported,
            "events_malformed": self.events_malformed,
            "flows_in": self.flows_in,
            "flows_normalized": self.flows_normalized,
            "flows_skipped_unsupported": self.flows_skipped_unsupported,
            "flows_malformed": self.flows_malformed,
            "sessions_built": self.sessions_built,
            "sessions_with_flow_evidence": self.sessions_with_flow_evidence,
            "findings_emitted": self.findings_emitted,
            "errors": list(self.errors),
        }


class DataExfiltrationDetector:
    """Pipeline: normalize -> sessionize -> analyze -> discover ->
    (profile ->) (score ->) ARDE-validate.

    Part 1 stages always run. Part 2 (profiler), Part 3 (scoring stack,
    wired by callers via ``score_sessions``) and Part 4 (ARDE) run when
    their components are supplied.
    """

    def __init__(
        self,
        config: DetectorConfig | None = None,
        raw_store: RawEventStore | None = None,
        repository: DetectionRepository | None = None,
        normalizer: EventNormalizer | None = None,
        analyzers: list | None = None,
        destination_universe: set[str] | None = None,
        expected_consumers: set[str] | None = None,
        macie_enricher=None,
        profiler: "BehavioralProfiler | None" = None,
        intelligence_context: "IntelligenceContext | None" = None,
        baseline_influence: "BaselineInfluence | None" = None,
        arde_validator: "ARDEValidator | None" = None,
        arde_audit_log: "AuditLog | None" = None,
    ) -> None:
        self._config = config or DetectorConfig()
        self._raw_store = raw_store
        self._repo = repository
        self._normalizer = normalizer or EventNormalizer()
        self._analyzers = analyzers or [
            VolumeAnalyzer(),
            DestinationAnalyzer(known_destinations=destination_universe),
            AccessPatternAnalyzer(expected_consumers=expected_consumers),
            SensitivityAnalyzer(),
        ]
        self._stats = PipelineStats()
        # Part 2 behavioral intelligence (optional; features-only, no verdicts)
        self._profiler = profiler
        self._intelligence_context = intelligence_context
        self._baseline_influence = baseline_influence
        # Part 4 ARDE validation (optional; challenge before release)
        self._arde_validator = arde_validator
        self._arde_audit_log = arde_audit_log
        if (
            arde_validator is not None
            and getattr(arde_validator, "audit_log", None) is None
            and arde_audit_log is not None
        ):
            arde_validator._audit_log = arde_audit_log

    @property
    def stats(self) -> PipelineStats:
        return self._stats

    @property
    def arde_validator(self) -> "ARDEValidator | None":
        return self._arde_validator

    # ------------------------------------------------------------------
    # pipeline entry points
    # ------------------------------------------------------------------

    def process_events(
        self,
        cloudtrail_records: list[dict[str, Any]] | None = None,
        vpc_flow_records: list[dict[str, Any]] | None = None,
        provider: Provider = Provider.AWS,
    ) -> DetectorResult:
        """Run the full pipeline over one batch of telemetry.

        Malformed records are collected (never silently dropped) and
        reported in ``result.stats``; the batch still processes.
        """
        self._stats = PipelineStats()
        records = cloudtrail_records or []
        flows = vpc_flow_records or []

        events, flow_events = self._normalize_all(records, flows, provider)

        builder = SessionBuilder(self._config)
        builder.add_events(events)
        sessions = builder.flush()

        sessions = self._correlate_flows(sessions, flow_events)
        sessions = self._attach_feature_records(sessions)

        profile_builder = ResourceProfileBuilder()
        profile_builder.observe(events)
        profiles = profile_builder.build_all()

        findings = [self._build_finding(session, profiles) for session in sessions]

        self._stats.sessions_built = len(sessions)
        self._stats.findings_emitted = len(findings)

        behavioral_features: list = []
        profile_results: list = []
        if self._profiler is not None:
            for session in sessions:
                result = self._profiler.profile(session, events, self._intelligence_context)
                profile_results.append(result)
                behavioral_features.append(result.features)

        # Part 4: ARDE challenges every emitted finding before release.
        # Part 1 discovery findings carry no scored session/feature set, so
        # ARDE runs on the evidence alone; when a scoring stack is wired
        # upstream, pass scored sessions via ``score_sessions``.
        if self._arde_validator is not None:
            fset_by_session = {
                f.session_id: f for f in behavioral_features
            }
            for finding in findings:
                validate_and_attach(
                    finding,
                    session=next(s for s in sessions if s.session_id == finding.session_id),
                    fset=fset_by_session.get(finding.session_id),
                    validator=self._arde_validator,
                )

        if self._repo is not None:
            self._persist(events, flow_events, sessions, profiles, findings)

        return DetectorResult(
            sessions=sessions,
            flow_events=flow_events,
            resource_profiles=profiles,
            findings=findings,
            stats=self._stats,
            behavioral_features=behavioral_features,
            profile_results=profile_results,
        )

    # ------------------------------------------------------------------

    def score_sessions(
        self,
        result: "DetectorResult",
        stack,
        *,
        validator: "ARDEValidator | None" = None,
    ) -> list[SecurityFinding]:
        """Score a processed batch and emit risk-bearing findings (Part 3/4).

        Requires behavioral features, so the detector must have been
        constructed with a ``profiler``. Each session is scored by the
        supplied ``ScoringStack`` (anomaly stacks need a fitted model); the
        result is a scored finding carrying risk/confidence/severity + model
        identity. When a validator is available (argument or constructor),
        ARDE validates and explains every scored finding before release.

        Discovery findings in ``result.findings`` are left untouched — this
        returns the scored set so callers choose which to persist.
        """
        from algo.data_exfiltration.data_exfiltration.finding import build_scored_finding

        fset_by_session = {f.session_id: f for f in result.behavioral_features}
        active_validator = validator or self._arde_validator
        scored_findings: list[SecurityFinding] = []
        for session in result.sessions:
            fset = fset_by_session.get(session.session_id)
            if fset is None:
                continue
            scored = stack.score(fset)
            finding = build_scored_finding(session, scored)
            if active_validator is not None:
                validate_and_attach(
                    finding,
                    session=session,
                    scored=scored,
                    fset=fset,
                    validator=active_validator,
                )
            scored_findings.append(finding)
        return scored_findings

    # ------------------------------------------------------------------

    def _normalize_all(self, records, flows, provider):
        events = []
        for record in records:
            self._stats.events_in += 1
            try:
                event = self._normalizer.normalize(provider, record, raw_store=self._raw_store)
            except UnsupportedEventError as exc:
                self._stats.events_skipped_unsupported += 1
                self._stats.errors.append(f"unsupported: {exc}")
                continue
            except MalformedEventError as exc:
                self._stats.events_malformed += 1
                self._stats.errors.append(f"malformed: {exc}")
                continue
            events.append(event)
            self._stats.events_normalized += 1

        flow_events = []
        for flow in flows:
            self._stats.flows_in += 1
            try:
                flow_event = self._normalizer.normalize_vpc_flow(flow)
            except UnsupportedEventError as exc:
                self._stats.flows_skipped_unsupported += 1
                self._stats.errors.append(f"flow unsupported: {exc}")
                continue
            except MalformedEventError as exc:
                self._stats.flows_malformed += 1
                self._stats.errors.append(f"flow malformed: {exc}")
                continue
            flow_events.append(flow_event)
            self._stats.flows_normalized += 1

        return events, flow_events

    def _correlate_flows(self, sessions, flow_events):
        from algo.data_exfiltration.data_exfiltration.correlate import enrich_session_with_flows

        enriched = []
        for session in sessions:
            updated = enrich_session_with_flows(session, flow_events, self._config)
            if updated is not session:
                self._stats.sessions_with_flow_evidence += 1
            enriched.append(updated)
        return enriched

    def _attach_feature_records(self, sessions):
        return [attach_features(s, extract_features(s)) for s in sessions]

    def _build_finding(self, session, profiles):
        profile = next((p for p in profiles if p.resource_id == (session.resources_accessed or [None])[0]), None)
        context = {}
        if profile is not None:
            context["known_destinations"] = profile.known_destinations
            context["expected_consumers"] = profile.expected_consumers
        analyses = [a.run(session, context) for a in self._analyzers]
        return build_discovery_finding(
            session,
            analyses,
            provider=session.provider,
            account_id=None,
            region=None,
        )

    def _persist(self, events, flow_events, sessions, profiles, findings) -> None:
        self._repo.save_events(events + flow_events)
        self._repo.save_sessions(sessions)
        for profile in profiles:
            self._repo.save_resource_profile(profile)
        for finding in findings:
            self._repo.save_finding(finding)


@dataclass
class DetectorResult:
    """Everything the pipeline produced for one batch."""

    sessions: list[DataAccessSession]
    flow_events: list
    resource_profiles: list[DataResourceProfile]
    findings: list[SecurityFinding]
    stats: PipelineStats
    behavioral_features: list = field(default_factory=list)
    """BehavioralFeatureSet per session (Part 2); empty when profiling off."""

    profile_results: list = field(default_factory=list)
    """Full BehavioralProfileResult objects (assessments per dimension)."""
