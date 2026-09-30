"""Dataset construction: scenario bundles -> labeled temporal corpus.

Builds the session-level labeled dataset from the synthetic scenario
corpus. Sessions carry their ground truth in ``session_features``
(``label``, ``scenario``) so every metric can be traced to its scenario
family. Data is marked synthetic end to end.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from algo.data_exfiltration.data_exfiltration.config import DetectorConfig
from algo.data_exfiltration.data_exfiltration.detector import DataExfiltrationDetector
from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import BehavioralFeatureSet
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession, SecurityFinding
from algo.data_exfiltration.data_exfiltration.session import SessionBuilder

from .scenarios import ScenarioBundle


@dataclass
class LabeledRecord:
    """One labeled session with everything produced for it."""

    session: DataAccessSession
    finding: SecurityFinding | None
    label: int
    scenario: str
    instance: int
    events: list = field(default_factory=list)
    """Normalized events belonging to this session (needed by the
    behavioral profiler for window aggregates and access patterns)."""

    @property
    def session_id(self) -> str:
        return self.session.session_id


def build_sessions_from_bundle(
    bundle: ScenarioBundle,
    config: DetectorConfig | None = None,
) -> list[DataAccessSession]:
    """Normalize + sessionize one scenario's telemetry."""
    config = config or DetectorConfig()
    normalizer = EventNormalizer()
    events = [
        normalizer.normalize(provider="aws", record=rec) for rec in bundle.cloudtrail
    ]
    flow_events = [normalizer.normalize_vpc_flow(f) for f in bundle.flows]

    from algo.data_exfiltration.data_exfiltration.correlate import enrich_session_with_flows

    builder = SessionBuilder(config)
    builder.add_events(events)
    sessions = builder.flush()
    sessions = [enrich_session_with_flows(s, flow_events, config) for s in sessions]
    return sessions


def run_detector_on_corpus(
    bundles: list[ScenarioBundle],
    detector: DataExfiltrationDetector | None = None,
    config: DetectorConfig | None = None,
) -> list[LabeledRecord]:
    """Run the detector over each bundle; return labeled records.

    Each bundle is processed independently (its own normalization +
    sessionization) exactly like an isolated telemetry drop. The sessions
    and findings from that SAME pass are used, so findings attach by the
    id that produced them (no cross-pass id mismatch).

    Session ids are rewritten to a stable, content-addressed form
    (``eval-<scenario>-<instance>-<n>``) because production session ids are
    random UUIDs; without this the evaluation artifacts (which embed
    session ids in error records) would differ on every run. The rewrite is
    an evaluation identifier only -- it changes nothing about the session's
    content.
    """
    detector = detector or DataExfiltrationDetector(config=config)
    records: list[LabeledRecord] = []

    for bundle in bundles:
        result = detector.process_events(
            cloudtrail_records=bundle.cloudtrail,
            vpc_flow_records=bundle.flows,
        )
        if not result.sessions:
            continue
        # session's own events (for the behavioral profiler)
        from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer

        normalizer = EventNormalizer()
        events = [normalizer.normalize(provider="aws", record=rec) for rec in bundle.cloudtrail]
        events += [normalizer.normalize_vpc_flow(f) for f in bundle.flows]
        event_by_id = {e.event_id: e for e in events}
        finding_by_session = {f.session_id: f for f in result.findings}

        ordered = sorted(result.sessions, key=lambda s: s.start_time_epoch_ms or 0.0)
        for index, session in enumerate(ordered):
            original_id = session.session_id
            finding = finding_by_session.get(original_id)
            stable_id = f"eval-{bundle.name}-{bundle.instance}-{index:02d}"
            own = [event_by_id[eid] for eid in session.event_ids if eid in event_by_id]
            session.session_id = stable_id
            if finding is not None:
                finding.session_id = stable_id
            records.append(
                LabeledRecord(
                    session=session,
                    finding=finding,
                    label=bundle.label,
                    scenario=bundle.name,
                    instance=bundle.instance,
                    events=own,
                )
            )
    return records


def attach_labels(
    feature_sets: list[BehavioralFeatureSet],
    records: list[LabeledRecord],
) -> list[tuple[BehavioralFeatureSet, int, dict[str, Any]]]:
    """Zip feature sets with labels + scenario metadata by session id."""
    meta = {r.session_id: (r.label, r.scenario, r.instance) for r in records}
    out: list[tuple[BehavioralFeatureSet, int, dict[str, Any]]] = []
    for fset in feature_sets:
        label, scenario, instance = meta[fset.session_id]
        out.append((fset, label, {"scenario": scenario, "instance": instance}))
    return out
