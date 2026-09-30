"""DataResourceProfile construction from observed event history.

The profile records what has been OBSERVED (actors, hours, volumes,
destinations, workloads). Deriving expectations from this history is the
baseline module's job — here we only accumulate honest counts.

Sensitivity enrichment (e.g. Macie) may be supplied; when absent,
sensitivity stays unavailable rather than defaulted.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Iterable

from algo.data_exfiltration.data_exfiltration.enrichment import MacieEnricher, apply_macie_enrichment
from algo.data_exfiltration.data_exfiltration.measurement import (
    MeasurementConfidence,
    MeasurementSource,
    MultiSourceMeasurement,
    SourceMeasurement,
)
from algo.data_exfiltration.data_exfiltration.schemas import DataActivityEvent, DataResourceProfile, SensitivityLevel

_SEVERITY_ORDER = [
    None,
    SensitivityLevel.NONE,
    SensitivityLevel.PUBLIC,
    SensitivityLevel.INTERNAL,
    SensitivityLevel.CONFIDENTIAL,
    SensitivityLevel.FINANCIAL,
    SensitivityLevel.PII,
    SensitivityLevel.PHI,
    SensitivityLevel.SECRETS,
    SensitivityLevel.CRITICAL,
]

_SEVERITY_RANK = {level: rank for rank, level in enumerate(_SEVERITY_ORDER) if level is not None}


def _severity_rank(level: SensitivityLevel | None) -> int:
    return _SEVERITY_RANK.get(level, 0)


def _hour_bucket(epoch_ms: float | None) -> str | None:
    if epoch_ms is None:
        return None
    hour = datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc).hour
    return f"{hour:02d}"


def _sum_by_category(parts: list[SourceMeasurement]) -> MultiSourceMeasurement:
    """Sum contributions per (source, confidence) category; never mix them."""
    buckets: dict[tuple[str, str], float] = {}
    for part in parts:
        key = (part.source.value, part.confidence.value)
        buckets[key] = buckets.get(key, 0.0) + part.value
    return MultiSourceMeasurement(
        measurements=[
            SourceMeasurement(
                value=value,
                source=MeasurementSource(source),
                confidence=MeasurementConfidence(confidence),
                detail="profile aggregate (sum per source/confidence)",
            )
            for (source, confidence), value in sorted(buckets.items())
        ]
    )


class ResourceProfileBuilder:
    """Accumulates per-resource observations across many events."""

    def __init__(
        self,
        macie_enricher: MacieEnricher | None = None,
        owner_registry: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self._macie = macie_enricher
        # resource_id -> {"owner": ..., "business_unit": ...} from asset inventory
        self._owners = owner_registry or {}
        self._actors: dict[str, Counter] = {}
        self._destinations: dict[str, set[str]] = {}
        self._workloads: dict[str, set[str]] = {}
        self._hours: dict[str, Counter] = {}
        self._volumes: dict[str, list[SourceMeasurement]] = {}
        self._objects: dict[str, list[int]] = {}
        self._requests: dict[str, list[int]] = {}
        self._types: dict[str, str] = {}
        self._arns: dict[str, str] = {}
        self._event_counts: Counter = Counter()
        self._sensitivity: dict[str, tuple[SensitivityLevel | None, MultiSourceMeasurement | None, str]] = {}

    # ------------------------------------------------------------------

    def observe(self, events: Iterable[DataActivityEvent]) -> None:
        """Fold a batch of events into the profiles."""
        for raw in events:
            event = raw
            if self._macie is not None and event.bucket:
                event = apply_macie_enrichment(event, self._macie)
            resource_id = event.resource_id
            if not resource_id:
                continue

            self._event_counts[resource_id] += 1
            self._types.setdefault(resource_id, event.resource_type or "unknown")
            if event.resource_arn:
                self._arns.setdefault(resource_id, event.resource_arn)

            if event.actor_id:
                self._actors.setdefault(resource_id, Counter())[event.actor_id] += 1
            if event.destination_ip:
                self._destinations.setdefault(resource_id, set()).add(event.destination_ip)
            if event.workload_id:
                self._workloads.setdefault(resource_id, set()).add(event.workload_id)
            elif event.user_agent:
                self._workloads.setdefault(resource_id, set()).add(f"ua:{event.user_agent}")

            hour = _hour_bucket(event.event_time_epoch_ms)
            if hour is not None:
                self._hours.setdefault(resource_id, Counter())[hour] += 1

            if event.bytes_accessed is not None:
                self._volumes.setdefault(resource_id, []).extend(event.bytes_accessed.measurements)
            if event.objects_accessed is not None:
                self._objects.setdefault(resource_id, []).append(event.objects_accessed)
            if event.request_count is not None:
                self._requests.setdefault(resource_id, []).append(event.request_count)

            if event.sensitivity_level is not None or event.sensitivity_score is not None:
                # keep the most severe observation; enrichment is external so
                # we record its level/score/source verbatim
                existing = self._sensitivity.get(resource_id)
                if existing is None or _severity_rank(event.sensitivity_level) > _severity_rank(existing[0]):
                    self._sensitivity[resource_id] = (
                        event.sensitivity_level,
                        event.sensitivity_score,
                        event.sensitivity_source or "unknown",
                    )

    # ------------------------------------------------------------------

    def build(self, resource_id: str) -> DataResourceProfile:
        """Materialize the profile for *resource_id*."""
        owner_info = self._owners.get(resource_id, {})
        sensitivity = self._sensitivity.get(resource_id, (None, None, None))

        volumes = self._volumes.get(resource_id, [])
        volume_agg = _sum_by_category(volumes) if volumes else None

        objects = self._objects.get(resource_id, [])
        objects_agg = (
            MultiSourceMeasurement(measurements=[SourceMeasurement(
                value=float(sum(objects)),
                source=MeasurementSource.AGGREGATION,
                confidence=MeasurementConfidence.AGGREGATED,
                detail=f"sum of objects_accessed over {len(objects)} events",
            )])
            if objects else None
        )

        requests = self._requests.get(resource_id, [])
        requests_agg = (
            MultiSourceMeasurement(measurements=[SourceMeasurement(
                value=float(sum(requests)),
                source=MeasurementSource.AGGREGATION,
                confidence=MeasurementConfidence.AGGREGATED,
                detail=f"sum of request_count over {len(requests)} events",
            )])
            if requests else None
        )

        return DataResourceProfile(
            resource_id=resource_id,
            resource_type=self._types.get(resource_id),
            resource_arn=self._arns.get(resource_id),
            owner=owner_info.get("owner"),
            business_unit=owner_info.get("business_unit"),
            sensitivity_level=sensitivity[0],
            sensitivity_score=sensitivity[1],
            sensitivity_source=sensitivity[2] if sensitivity[0] is not None or sensitivity[1] is not None else None,
            expected_consumers=sorted(self._actors.get(resource_id, {})),
            known_actors=sorted(self._actors.get(resource_id, {})),
            known_destinations=sorted(self._destinations.get(resource_id, set())),
            known_workloads=sorted(self._workloads.get(resource_id, set())),
            normal_access_hours=dict(sorted(self._hours.get(resource_id, {}).items())),
            normal_access_volume=volume_agg,
            normal_object_count=objects_agg,
            normal_request_rate=requests_agg,
            history_event_count=self._event_counts.get(resource_id, 0),
        )

    def build_all(self) -> list[DataResourceProfile]:
        return [self.build(rid) for rid in sorted(self._event_counts)]
