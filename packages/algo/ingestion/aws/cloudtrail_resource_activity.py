"""AWS CloudTrail → canonical events ingestion.

Thin batch layer over :class:`ResourceActivityNormalizer`. Distinguishes three
record dispositions so nothing is silently dropped:

- ``normalized``  — became a canonical :class:`ResourceActivityEvent`
- ``skipped``     — valid but out of scope (e.g. ``ConsoleLogin``)
- ``quarantined`` — malformed; unusable as evidence

In strict mode malformed records raise; in lenient mode they are quarantined
with their error attached.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from detection.cloud_destruction.config import NORMALIZER_VERSION
from detection.cloud_destruction.exceptions import (
    MalformedEventError,
    UnsupportedEventError,
)
from detection.cloud_destruction.normalizer import ResourceActivityNormalizer
from detection.cloud_destruction.protection import ProtectionCatalog
from detection.cloud_destruction.schemas import CloudProvider, ResourceActivityEvent


@dataclass
class IngestResult:
    """Outcome of one ingestion batch."""

    events: list[ResourceActivityEvent] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    quarantined: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.events) + len(self.skipped) + len(self.quarantined)

    @property
    def ok(self) -> bool:
        return not self.quarantined


def _unwrap_records(payload: Any) -> list[dict[str, Any]]:
    """Accept ``[...]`` or ``{"Records": [...]}`` (Kinesis/S3 delivery shape)."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("Records"), list):
        return payload["Records"]
    raise MalformedEventError(
        "payload must be a list of records or {'Records': [...]}",
        raw_event=payload if isinstance(payload, dict) else None,
    )


class CloudTrailResourceActivityIngestor:
    """Normalizes batches of CloudTrail records into canonical events."""

    def __init__(
        self,
        catalog: Optional[ProtectionCatalog] = None,
        *,
        strict: bool = True,
        max_records_per_batch: int = 1000,
    ) -> None:
        self._catalog = catalog
        self._strict = strict
        self._max_records = max_records_per_batch

    def ingest_batch(
        self,
        payload: Any,
        *,
        is_replayed: bool = False,
        is_synthetic: bool = False,
        generator: Optional[str] = None,
    ) -> IngestResult:
        """Normalize a batch; returns per-record dispositions."""
        records = _unwrap_records(payload)
        if len(records) > self._max_records:
            raise MalformedEventError(
                f"batch exceeds max_records_per_batch ({self._max_records})",
                context={"got": len(records)},
            )

        normalizer = ResourceActivityNormalizer(catalog=self._catalog)
        result = IngestResult()
        for index, record in enumerate(records):
            try:
                event = normalizer.normalize_cloudtrail(
                    record,
                    raw_event_reference=raw_reference_for(record, index),
                    raw_record_index=index,
                    is_replayed=is_replayed,
                    is_synthetic=is_synthetic,
                    generator=generator,
                )
                result.events.append(event)
            except UnsupportedEventError:
                result.skipped.append({"index": index, "reason": "unsupported_event"})
            except MalformedEventError as exc:
                if self._strict:
                    raise
                result.quarantined.append(
                    {
                        "index": index,
                        "error": str(exc),
                        "record": record,
                    }
                )
        return result


def raw_reference_for(record: dict[str, Any], index: int) -> str:
    """Stable reference to the raw record (no payload duplication)."""
    event_id = record.get("eventID") if isinstance(record, dict) else None
    return f"cloudtrail://{event_id or index}"
