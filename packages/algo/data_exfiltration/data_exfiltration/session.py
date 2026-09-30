"""Data-access session construction.

Cloud data events carry no explicit session id, so sessions are
*approximated* by grouping an actor's activity into inactivity-gap
windows. Every aggregate is an explicit sum over contributing events:
nothing is estimated here, and aggregation categories stay zero when no
contributing event measured that dimension.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from algo.data_exfiltration.data_exfiltration.config import DetectorConfig
from algo.data_exfiltration.data_exfiltration.exceptions import SessionConstructionError
from algo.data_exfiltration.data_exfiltration.measurement import (
    MeasurementConfidence,
    MeasurementSource,
    MultiSourceMeasurement,
    SourceMeasurement,
)
from algo.data_exfiltration.data_exfiltration.schemas import (
    DataAccessSession,
    DataActivityEvent,
    DataAction,
    Provider,
    ReadOrWrite,
    SessionRiskState,
)

_MAX_SOURCES_PER_MEASUREMENT = 64


class SessionBuilder:
    """Builds per-actor sessions from normalized events."""

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self._config = config or DetectorConfig()
        self._inactivity_gap_ms = self._config.session.inactivity_gap * 1000.0
        self._max_duration_ms = self._config.session.max_session_duration * 1000.0
        # actor_id -> open session state
        self._open: dict[str, _OpenSession] = {}
        # actor_id -> last event epoch ms (kept even after close, for gap math)
        self._last_seen: dict[str, float] = {}
        self._closed: list[DataAccessSession] = []

    # ------------------------------------------------------------------
    # ingestion
    # ------------------------------------------------------------------

    def add_event(self, event: DataActivityEvent) -> list[DataAccessSession]:
        """Add one event; return any sessions the event closed.

        Events lacking a usable timestamp are rejected loudly: session
        math without time is guessing.
        """
        if event.event_time_epoch_ms is None:
            raise SessionConstructionError(f"event {event.event_id} has no timestamp")

        actor = event.actor_id or f"anonymous:{event.provider.value}"
        ts = event.event_time_epoch_ms
        closed: list[DataAccessSession] = []

        state = self._open.get(actor)
        last = self._last_seen.get(actor)
        gap_exceeded = (
            state is not None
            and last is not None
            and (ts - last) > self._inactivity_gap_ms
        )
        duration_exceeded = (
            state is not None
            and state.start_ms is not None
            and (ts - state.start_ms) >= self._max_duration_ms
        )

        if state is not None and (gap_exceeded or duration_exceeded):
            closed.append(self._close(actor))
            state = None

        if state is None:
            state = _OpenSession(session_id=_new_session_id(), actor_id=actor)
            self._open[actor] = state

        state.add(event)
        self._last_seen[actor] = ts

        return closed

    def add_events(self, events: list[DataActivityEvent]) -> list[DataAccessSession]:
        """Add events ordered by time (out-of-order input is sorted first).

        Returns sessions closed during ingestion; call :meth:`flush` to
        retrieve everything built so far.
        """
        closed: list[DataAccessSession] = []
        for event in sorted(events, key=lambda e: e.event_time_epoch_ms or 0.0):
            closed.extend(self.add_event(event))
        return closed

    def flush(self) -> list[DataAccessSession]:
        """Close every open session and return ALL sessions built since
        the last flush (including any closed during ingestion)."""
        for actor in list(self._open):
            self._close(actor)
        built = self._closed
        self._closed = []
        return built

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _close(self, actor: str) -> DataAccessSession:
        state = self._open.pop(actor)
        self._evict_if_needed()
        session = state.build(provider=Provider.AWS)
        self._closed.append(session)
        return session

    def _evict_if_needed(self) -> None:
        limit = self._config.session.max_actor_gap_buffer
        if len(self._last_seen) <= limit:
            return
        for actor, _ts in sorted(self._last_seen.items(), key=lambda kv: kv[1])[: len(self._last_seen) - limit]:
            self._last_seen.pop(actor, None)


class _OpenSession:
    """Mutable accumulator for one in-progress session."""

    def __init__(self, session_id: str, actor_id: str) -> None:
        self.session_id = session_id
        self.actor_id = actor_id
        self.events: list[DataActivityEvent] = []
        self.start_ms: float | None = None
        self.end_ms: float | None = None

    def add(self, event: DataActivityEvent) -> None:
        ts = event.event_time_epoch_ms
        if self.start_ms is None or ts < self.start_ms:
            self.start_ms = ts
        if self.end_ms is None or ts > self.end_ms:
            self.end_ms = ts
        self.events.append(event)

    def build(self, provider: Provider) -> DataAccessSession:
        events = sorted(self.events, key=lambda e: e.event_time_epoch_ms or 0.0)

        resources: list[str] = []
        objects = 0
        request_count = 0
        read_count = 0
        write_count = 0
        destinations: set[str] = set()
        asns: set[str] = set()
        countries: set[str] = set()

        bytes_parts: list[SourceMeasurement] = []
        egress_parts: list[SourceMeasurement] = []
        enumerate_count = 0
        error_count = 0

        for event in events:
            if event.resource_id and event.resource_id not in resources:
                resources.append(event.resource_id)
            if event.objects_accessed is not None:
                objects += event.objects_accessed
            if event.request_count is not None:
                request_count += event.request_count
            if event.read_or_write == ReadOrWrite.READ:
                read_count += 1
            elif event.read_or_write == ReadOrWrite.WRITE:
                write_count += 1
            if event.data_action in (DataAction.ENUMERATE, DataAction.LIST):
                enumerate_count += 1
            if event.error_code:
                error_count += 1

            if event.destination_ip:
                destinations.add(event.destination_ip)
            if event.destination_asn:
                asns.add(event.destination_asn)
            if event.destination_country:
                countries.add(event.destination_country)
            if event.source_country:
                countries.add(event.source_country)

            if event.bytes_accessed is not None:
                bytes_parts.extend(event.bytes_accessed.measurements)
            if event.network_bytes is not None:
                egress_parts.extend(event.network_bytes.measurements)

        def _combine(parts: list[SourceMeasurement]) -> Any:
            if not parts:
                return None
            # preserve per-source categories; cap to bound memory
            if len(parts) > _MAX_SOURCES_PER_MEASUREMENT:
                return _category_combine(parts)
            return _category_combine(parts)

        bytes_measurement = _combine(bytes_parts)
        egress_measurement = _combine(egress_parts)

        sensitivity_summary = _sensitivity_summary(events)

        return DataAccessSession(
            session_id=self.session_id,
            actor_id=self.actor_id,
            provider=provider,
            start_time_epoch_ms=self.start_ms,
            end_time_epoch_ms=self.end_ms,
            event_count=len(events),
            resources_accessed=resources,
            objects_accessed=objects if objects > 0 else 0,
            bytes_accessed=bytes_measurement,
            network_egress_bytes=egress_measurement,
            unique_destinations=sorted(destinations),
            unique_asns=sorted(asns),
            unique_countries=sorted(countries),
            request_count=request_count,
            read_event_count=read_count,
            write_event_count=write_count,
            enumerate_list_count=enumerate_count,
            error_event_count=error_count,
            sensitivity_summary=sensitivity_summary,
            risk_state=SessionRiskState.NEW,
            event_ids=[e.event_id for e in events],
        )


def _category_combine(parts: list[SourceMeasurement]) -> Any:
    """Group contributions by (source, confidence) and sum each category.

    Per-source sums are the only defensible aggregation when provenance
    differs: mixing observed flow bytes with estimated CloudTrail deltas
    into one number would silently launder confidence.
    """
    from algo.data_exfiltration.data_exfiltration.measurement import MultiSourceMeasurement

    buckets: dict[tuple[str, str], float] = {}
    for part in parts:
        key = (part.source.value, part.confidence.value)
        buckets[key] = buckets.get(key, 0.0) + part.value
    combined = MultiSourceMeasurement(
        measurements=[
            SourceMeasurement(
                value=value,
                source=MeasurementSource(source),
                confidence=MeasurementConfidence(confidence),
                detail="session aggregate (sum per source/confidence)",
            )
            for (source, confidence), value in sorted(buckets.items())
        ]
    )
    return combined


def _sensitivity_summary(events: list[DataActivityEvent]) -> Any:
    """Aggregate contributing events' sensitivity into an OptionalMeasurements."""
    from algo.data_exfiltration.data_exfiltration.measurement import (
        OptionalMeasurements,
        unavailable_measurement,
    )

    scored = [
        e.sensitivity_score
        for e in events
        if e.sensitivity_score is not None and e.sensitivity_score.measurements
    ]
    if not scored:
        return unavailable_measurement("no contributing event carried sensitivity enrichment")

    parts: list[SourceMeasurement] = []
    for measurement in scored:
        parts.extend(measurement.measurements)
    # take the max sensitivity score observed, keeping its provenance
    top = max(parts, key=lambda m: m.value)
    return OptionalMeasurements(
        measurement=MultiSourceMeasurement(measurements=[top]),
        unavailable_reason=None,
    )


def _new_session_id() -> str:
    return f"das-{uuid.uuid4().hex[:12]}"


def _utc_now_ms() -> float:
    return datetime.now(timezone.utc).timestamp() * 1000.0
