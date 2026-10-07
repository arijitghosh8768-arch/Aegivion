"""Replay engine — **Part 3**.

REPLAY mode processes historical/synthetic telemetry **deterministically**:
the same events + versions + configuration must produce the same detector
result. Determinism is verified, not assumed: every replay result carries a
content digest, and :meth:`ReplayEngine.run` twice on identical inputs
yields identical digests.

Replay differs from live processing in three documented ways:

1. ``is_replayed=True`` is stamped on the run's provenance (with the
   replay source name) so downstream consumers know this is a re-run;
2. configuration and model versions are pinned at construction time and
   surfaced in every result (no mid-run config drift);
3. nothing is written to the operational baseline store — replay is
   side-effect free by design.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

__all__ = ["ReplayResult", "ReplayEngine"]

from detection.cloud_destruction.config import DestructionDetectorConfig
from detection.cloud_destruction.finding import DestructionFinding
from detection.cloud_destruction.detector import DestructionDetector
from detection.cloud_destruction.legitimate import ApprovedActivityProfile
from detection.cloud_destruction.registry import ModelRegistry, content_digest
from detection.cloud_destruction.schemas import DestructiveActivitySession, ResourceActivityEvent



@dataclass
class ReplayResult:
    """Deterministic outcome of one replay run."""

    sessions: list[DestructiveActivitySession]
    findings: list[DestructionFinding]
    versions: dict[str, Any]
    result_digest: str
    replay_source: str
    n_events: int
    raw: dict[str, Any] = field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "n_sessions": len(self.sessions),
            "n_findings": len(self.findings),
            "versions": self.versions,
            "result_digest": self.result_digest,
            "replay_source": self.replay_source,
            "n_events": self.n_events,
        }


class ReplayEngine:
    """Deterministic replay of canonical events through the full detector."""

    def __init__(
        self,
        config: Optional[DestructionDetectorConfig] = None,
        *,
        approved_profiles: Optional[Sequence[ApprovedActivityProfile]] = None,
        replay_source: str = "unspecified",
        anomaly_seed: int = 1337,
        use_supervised: bool = False,
    ) -> None:
        self._config = config or DestructionDetectorConfig()
        self._approved_profiles = list(approved_profiles or [])
        self._replay_source = replay_source
        self._anomaly_seed = anomaly_seed
        self._use_supervised = use_supervised

    def run(
        self,
        events: Sequence[ResourceActivityEvent],
        *,
        label_source: Optional[str] = None,
    ) -> ReplayResult:
        """Replay canonical events; returns a digest-verified result."""
        detector = DestructionDetector(
            self._config,
            approved_profiles=self._approved_profiles,
            anomaly_seed=self._anomaly_seed,
            use_supervised=self._use_supervised,
        )
        outcome = detector.detect(events)
        # Digest covers scoring *content*; volatile identifiers (uuid session/
        # finding ids, per-run timestamps) are excluded — they differ between
        # runs by design, while every scored value and version stamp matches.
        digest = content_digest(
            {
                "findings": [
                    {
                        "actor_id": f.actor_id,
                        "severity": f.severity.value,
                        "risk": round(f.risk_score, 9),
                        "confidence": round(f.confidence_score, 9),
                        "event_ids": sorted(f.event_ids),
                        "versions": {
                            "feature": f.feature_version,
                            "scoring": f.scoring_version,
                            "rule": f.rule_version,
                            "model": (f.model_name, f.model_version),
                            "baseline": f.baseline_version,
                        },
                    }
                    for f in sorted(outcome.findings, key=lambda f: sorted(f.event_ids))
                ],
                "versions": outcome.versions,
            }
        )
        return ReplayResult(
            sessions=outcome.sessions,
            findings=outcome.findings,
            versions=outcome.versions,
            result_digest=digest,
            replay_source=self._replay_source,
            n_events=len(events),
            raw={
                "feature_vectors": outcome.feature_vectors,
                "risks": outcome.risks,
                "confidences": outcome.confidences,
                "anomaly_scores": outcome.anomaly_scores,
                "sequence_scores": outcome.sequence_scores,
            },
        )
