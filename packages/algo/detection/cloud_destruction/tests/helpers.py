"""Shared test helpers: canonical event factory + time utilities."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from detection.cloud_destruction.provenance import DataProvenance
from detection.cloud_destruction.schemas import (
    ActionCategory,
    ActorType,
    BusinessCriticality,
    CloudProvider,
    OperationType,
    ResourceActivityEvent,
    ResourceType,
)

BASE_TIME = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str = "evt-1",
    timestamp: datetime | None = None,
    actor_id: str | None = "alice.admin",
    actor_type: ActorType = ActorType.IAM_USER,
    resource_id: str | None = "fin-prod-archive",
    resource_type: ResourceType = ResourceType.S3_OBJECT,
    resource_arn: str | None = "arn:aws:s3:::fin-prod-archive/reports/x.json",
    action_category: ActionCategory = ActionCategory.DELETE,
    operation_type: OperationType = OperationType.SINGLE,
    provider: CloudProvider = CloudProvider.AWS,
    account_id: str | None = "111122223333",
    region: str | None = "us-east-1",
    **overrides: object,
) -> ResourceActivityEvent:
    """Build a canonical event with sensible defaults for tests."""
    payload: dict[str, object] = {
        "event_id": event_id,
        "timestamp": timestamp or BASE_TIME,
        "provider": provider,
        "account_id": account_id,
        "region": region,
        "actor_id": actor_id,
        "actor_type": actor_type,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "resource_arn": resource_arn,
        "action": action_category.value,
        "action_category": action_category,
        "operation_type": operation_type,
        "raw_action": "s3:DeleteObject",
        "feature_availability": (),
        "data_provenance": DataProvenance(
            source_type="synthetic", ingestion_pipeline="tests", is_synthetic=True
        ),
    }
    payload.update(overrides)
    return ResourceActivityEvent(**payload)  # type: ignore[arg-type]


def advance(start: datetime, seconds: float) -> datetime:
    return start + timedelta(seconds=seconds)


__all__ = ["BASE_TIME", "advance", "make_event"]
