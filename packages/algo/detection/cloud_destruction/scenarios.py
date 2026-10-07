"""Safe synthetic / replay scenarios for the final-stage evaluation.

The eighteen scenarios mandated by the Algorithm #3 final stage:

1.  normal writes                    (benign)
2.  normal cleanup                   (benign)
3.  lifecycle expiration             (benign)
4.  backup retention cleanup         (benign)
5.  normal deployment                (benign)
6.  large legitimate migration       (benign)
7.  mass object modification         (destructive)
8.  mass object deletion             (destructive)
9.  mass version deletion            (destructive)
10. snapshot deletion                (destructive)
11. backup / recovery-point deletion (destructive)
12. protection degradation           (destructive)
13. mass rewrite pattern             (destructive)
14. slow destructive behavior        (destructive)
15. compound destructive behavior    (destructive)
16. mixed benign + malicious-looking (destructive)
17. missing telemetry                (destructive)
18. out-of-order events              (destructive)

Every builder is deterministic: same ``start`` time ⇒ same events.
Events are built directly from the canonical schemas (no cloud
SDK, no real identifiers, no production data) and carry synthetic
data provenance. Each scenario declares whether its destructive
activity should be detected (``expected_positive``); the evaluator
measures — never assumes — the detector's actual behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Optional

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

__all__ = ["ATTACK_CHAIN", "Scenario", "SCENARIOS", "acceptance_attack_chain", "scenario_by_number"]


def _event(
    event_id: str,
    timestamp: datetime,
    *,
    actor_id: str,
    action_category: ActionCategory,
    resource_id: str,
    resource_type: ResourceType = ResourceType.S3_OBJECT,
    resource_arn: Optional[str] = None,
    operation_type: OperationType = OperationType.SINGLE,
    raw_action: Optional[str] = None,
    actor_type: ActorType = ActorType.IAM_USER,
    account_id: Optional[str] = "111122223333",
    region: Optional[str] = "us-east-1",
    **overrides: object,
) -> ResourceActivityEvent:
    """Build one synthetic canonical event."""
    payload: dict[str, object] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "provider": CloudProvider.AWS,
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
        "raw_action": raw_action or f"s3:{action_category.value}",
        "feature_availability": (),
        "data_provenance": DataProvenance(
            source_type="synthetic",
            ingestion_pipeline="detection.cloud_destruction.scenarios",
            is_synthetic=True,
            generator="final-stage-scenarios",
        ),
    }
    payload.update(overrides)
    return ResourceActivityEvent(**payload)  # type: ignore[arg-type]


# ---------------------------------------------------------------------- #
# Scenario builders — each returns the scenario's canonical events
# ---------------------------------------------------------------------- #


def _normal_writes(start: datetime) -> list[ResourceActivityEvent]:
    """1. Steady, low-rate writes to a small working set."""
    events: list[ResourceActivityEvent] = []
    for i in range(24):
        events.append(
            _event(
                f"nw-{i:03d}",
                start + timedelta(seconds=30 * i),
                actor_id="alice.admin",
                action_category=ActionCategory.CREATE,
                resource_id=f"fin-prod-archive/report-{i % 3}.json",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/report-{i % 3}.json",
                raw_action="s3:PutObject",
            )
        )
    return events


def _normal_cleanup(start: datetime) -> list[ResourceActivityEvent]:
    """2. Small-scale, spaced-out cleanup of stale objects."""
    events: list[ResourceActivityEvent] = []
    for i in range(12):
        events.append(
            _event(
                f"nc-{i:03d}",
                start + timedelta(minutes=5 * i),
                actor_id="alice.admin",
                action_category=ActionCategory.READ,
                resource_id=f"fin-prod-archive/report-{i % 3}.json",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/report-{i % 3}.json",
                raw_action="s3:GetObject",
            )
        )
    for i in range(4):
        events.append(
            _event(
                f"nc-del-{i:03d}",
                start + timedelta(minutes=60, seconds=300 * i),
                actor_id="alice.admin",
                action_category=ActionCategory.DELETE,
                resource_id=f"fin-prod-archive/stale-{i}.log",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/stale-{i}.log",
                raw_action="s3:DeleteObject",
            )
        )
    return events


def _lifecycle_expiration(start: datetime) -> list[ResourceActivityEvent]:
    """3. Lifecycle service expiring old objects at a slow cadence."""
    events: list[ResourceActivityEvent] = []
    for i in range(6):
        events.append(
            _event(
                f"le-{i:03d}",
                start + timedelta(minutes=50 * i),
                actor_id="lifecycle-bot",
                actor_type=ActorType.AWS_SERVICE,
                action_category=ActionCategory.DELETE,
                resource_id=f"fin-prod-archive/aged-{i}.dat",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/aged-{i}.dat",
                raw_action="s3:LifecycleExpiration",
            )
        )
    return events


def _backup_retention_cleanup(start: datetime) -> list[ResourceActivityEvent]:
    """4. Scheduled backup retention deleting few recovery points."""
    events: list[ResourceActivityEvent] = []
    for i in range(3):
        events.append(
            _event(
                f"br-{i:03d}",
                start + timedelta(hours=1 + i),
                actor_id="backup-scheduler",
                actor_type=ActorType.SERVICE_ACCOUNT,
                action_category=ActionCategory.RECOVERY_POINT_DELETE,
                resource_id=f"backup-plan-fin/ rp-{i}",
                resource_type=ResourceType.RECOVERY_POINT,
                resource_arn=f"arn:aws:backup:us-east-1:111122223333:recovery-point:plan-fin-{i}",
                raw_action="backup:DeleteRecoveryPoint",
                recovery_point_id=f"rp-plan-fin-{i}",
            )
        )
    return events


def _normal_deployment(start: datetime) -> list[ResourceActivityEvent]:
    """5. A deployment writing new versions of a handful of resources."""
    events: list[ResourceActivityEvent] = []
    for i in range(20):
        events.append(
            _event(
                f"nd-{i:03d}",
                start + timedelta(seconds=60 * i),
                actor_id="deploy-bot",
                actor_type=ActorType.SERVICE_ACCOUNT,
                action_category=ActionCategory.CREATE,
                resource_id=f"fin-prod-app/config-{i % 5}.yaml",
                resource_arn=f"arn:aws:s3:::fin-prod-app/config-{i % 5}.yaml",
                raw_action="s3:PutObject",
            )
        )
    return events


def _large_legitimate_migration(start: datetime) -> list[ResourceActivityEvent]:
    """6. A large but paced migration with matching actor history.

    The migrator's own baseline (two prior write sessions at ~60
    events/hour over ~12 resources) makes the migration's pace and
    scope ordinary for this actor — a legitimate large migration.
    """
    events: list[ResourceActivityEvent] = []
    # prior history: two ordinary write sessions (baseline material)
    for session_index in range(2):
        base = start - timedelta(hours=24 * (2 - session_index))
        for i in range(30):
            events.append(
                _event(
                    f"mig-h{session_index}-{i:03d}",
                    base + timedelta(seconds=60 * i),
                    actor_id="migrator.bot",
                    actor_type=ActorType.SERVICE_ACCOUNT,
                    action_category=ActionCategory.CREATE,
                    resource_id=f"fin-prod-store/part-{i % 12}.bin",
                    resource_arn=f"arn:aws:s3:::fin-prod-store/part-{i % 12}.bin",
                    raw_action="s3:PutObject",
                )
            )
    # the migration itself: 90 writes over 2 hours, 24 resources
    for i in range(90):
        events.append(
            _event(
                f"mig-{i:03d}",
                start + timedelta(seconds=80 * i),
                actor_id="migrator.bot",
                actor_type=ActorType.SERVICE_ACCOUNT,
                action_category=ActionCategory.CREATE,
                resource_id=f"fin-prod-store/part-{i % 24}.bin",
                resource_arn=f"arn:aws:s3:::fin-prod-store/part-{i % 24}.bin",
                raw_action="s3:PutObject",
            )
        )
    return events


def _mass_object_modification(start: datetime) -> list[ResourceActivityEvent]:
    """7. Sudden burst of modifications across many production objects."""
    events: list[ResourceActivityEvent] = []
    for i in range(20):
        events.append(
            _event(
                f"mm-{i:03d}",
                start + timedelta(seconds=6 * i),
                actor_id="attacker.burst",
                action_category=ActionCategory.MODIFY,
                resource_id=f"fin-prod-db/record-{i}.json",
                resource_arn=f"arn:aws:s3:::fin-prod-db/record-{i}.json",
                raw_action="s3:PutObject",
            )
        )
    return events


def _mass_object_deletion(
    start: datetime, *, event_id_prefix: str = "md"
) -> list[ResourceActivityEvent]:
    """8. Rapid mass deletion across distinct production objects."""
    events: list[ResourceActivityEvent] = []
    for i in range(20):
        events.append(
            _event(
                f"{event_id_prefix}-{i:03d}",
                start + timedelta(seconds=6 * i),
                actor_id="attacker.burst",
                action_category=ActionCategory.DELETE,
                resource_id=f"fin-prod-archive/object-{i}.dat",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/object-{i}.dat",
                raw_action="s3:DeleteObject",
            )
        )
    return events


def _mass_version_deletion(start: datetime) -> list[ResourceActivityEvent]:
    """9. Deletion of many object versions (history destruction)."""
    events: list[ResourceActivityEvent] = []
    for i in range(20):
        events.append(
            _event(
                f"mv-{i:03d}",
                start + timedelta(seconds=6 * i),
                actor_id="attacker.burst",
                action_category=ActionCategory.VERSION_DELETE,
                resource_id=f"fin-prod-archive/object-{i % 6}.dat",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/object-{i % 6}.dat",
                operation_type=OperationType.VERSIONED,
                raw_action="s3:DeleteObjectVersion",
                version_id=f"v{i:04d}",
            )
        )
    return events


def _snapshot_deletion(start: datetime) -> list[ResourceActivityEvent]:
    """10. Deletion of snapshots across regions."""
    events: list[ResourceActivityEvent] = []
    regions = ("us-east-1", "eu-west-1")
    for i in range(12):
        events.append(
            _event(
                f"sn-{i:03d}",
                start + timedelta(seconds=15 * i),
                actor_id="attacker.burst",
                action_category=ActionCategory.SNAPSHOT_DELETE,
                resource_id=f"snap-prod-{i:04d}",
                resource_type=ResourceType.EBS_SNAPSHOT,
                resource_arn=f"arn:aws:ec2::{regions[i % 2]}:snapshot/snap-prod-{i:04d}",
                region=regions[i % 2],
                raw_action="ec2:DeleteSnapshot",
                snapshot_id=f"snap-prod-{i:04d}",
            )
        )
    return events


def _backup_recovery_point_deletion(start: datetime) -> list[ResourceActivityEvent]:
    """11. Deletion of backups / recovery points."""
    events: list[ResourceActivityEvent] = []
    for i in range(12):
        events.append(
            _event(
                f"rp-{i:03d}",
                start + timedelta(seconds=15 * i),
                actor_id="attacker.burst",
                action_category=ActionCategory.RECOVERY_POINT_DELETE,
                resource_id=f"recovery-point-fin-{i:04d}",
                resource_type=ResourceType.RECOVERY_POINT,
                resource_arn=f"arn:aws:backup:us-east-1:111122223333:recovery-point:fin-{i:04d}",
                raw_action="backup:DeleteRecoveryPoint",
                recovery_point_id=f"recovery-point-fin-{i:04d}",
            )
        )
    return events


def _protection_degradation(start: datetime) -> list[ResourceActivityEvent]:
    """12. Disabling versioning / backup / snapshot protection."""
    events: list[ResourceActivityEvent] = []
    for i in range(8):
        events.append(
            _event(
                f"pd-{i:03d}",
                start + timedelta(seconds=40 * i),
                actor_id="attacker.burst",
                action_category=ActionCategory.PROTECTION_CHANGE,
                resource_id=f"fin-prod-store/bucket-{i % 4}",
                resource_type=ResourceType.S3_BUCKET,
                resource_arn=f"arn:aws:s3:::fin-prod-store-bucket-{i % 4}",
                raw_action="s3:PutBucketVersioning",
            )
        )
    return events


def _mass_rewrite_pattern(start: datetime) -> list[ResourceActivityEvent]:
    """13. Many in-place rewrites (copy-overwrite) across objects."""
    events: list[ResourceActivityEvent] = []
    for i in range(20):
        events.append(
            _event(
                f"rw-{i:03d}",
                start + timedelta(seconds=15 * i),
                actor_id="attacker.burst",
                action_category=ActionCategory.REWRITE,
                resource_id=f"fin-prod-archive/object-{i}.dat",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/object-{i}.dat",
                raw_action="s3:CopyObject",
            )
        )
    return events


def _slow_destructive_behavior(start: datetime) -> list[ResourceActivityEvent]:
    """14. Slow-paced destruction: 30 deletions over 10 hours.

    Volume never spikes in any single burst window — only the
    temporal slow-destruction indicators and the destructive
    share of the session expose it.
    """
    events: list[ResourceActivityEvent] = []
    for i in range(30):
        events.append(
            _event(
                f"sd-{i:03d}",
                start + timedelta(minutes=20 * i),
                actor_id="attacker.slow",
                action_category=ActionCategory.DELETE,
                resource_id=f"fin-prod-archive/object-{i}.dat",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/object-{i}.dat",
                raw_action="s3:DeleteObject",
            )
        )
    return events


def _compound_destructive_behavior(start: datetime) -> list[ResourceActivityEvent]:
    """15. Modification + deletion + version + snapshot + protection."""
    events: list[ResourceActivityEvent] = []
    for i in range(8):
        events.append(
            _event(
                f"cb-m-{i:03d}",
                start + timedelta(seconds=10 * i),
                actor_id="attacker.compound",
                action_category=ActionCategory.MODIFY,
                resource_id=f"fin-prod-db/record-{i}.json",
                resource_arn=f"arn:aws:s3:::fin-prod-db/record-{i}.json",
                raw_action="s3:PutObject",
            )
        )
    for i in range(8):
        events.append(
            _event(
                f"cb-d-{i:03d}",
                start + timedelta(seconds=90, milliseconds=10 * i),
                actor_id="attacker.compound",
                action_category=ActionCategory.DELETE,
                resource_id=f"fin-prod-archive/object-{i}.dat",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/object-{i}.dat",
                raw_action="s3:DeleteObject",
            )
        )
    for i in range(4):
        events.append(
            _event(
                f"cb-v-{i:03d}",
                start + timedelta(seconds=180, milliseconds=10 * i),
                actor_id="attacker.compound",
                action_category=ActionCategory.VERSION_DELETE,
                resource_id=f"fin-prod-archive/object-{i}.dat",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/object-{i}.dat",
                operation_type=OperationType.VERSIONED,
                raw_action="s3:DeleteObjectVersion",
                version_id=f"vcv-{i:04d}",
            )
        )
    for i in range(2):
        events.append(
            _event(
                f"cb-s-{i:03d}",
                start + timedelta(seconds=240, milliseconds=10 * i),
                actor_id="attacker.compound",
                action_category=ActionCategory.SNAPSHOT_DELETE,
                resource_id=f"snap-prod-{i:04d}",
                resource_type=ResourceType.EBS_SNAPSHOT,
                resource_arn=f"arn:aws:ec2:us-east-1:111122223333:snapshot/snap-prod-{i:04d}",
                raw_action="ec2:DeleteSnapshot",
                snapshot_id=f"snap-prod-{i:04d}",
            )
        )
    for i in range(2):
        events.append(
            _event(
                f"cb-p-{i:03d}",
                start + timedelta(seconds=300, milliseconds=10 * i),
                actor_id="attacker.compound",
                action_category=ActionCategory.PROTECTION_CHANGE,
                resource_id=f"fin-prod-store/bucket-{i}",
                resource_type=ResourceType.S3_BUCKET,
                resource_arn=f"arn:aws:s3:::fin-prod-store-bucket-{i}",
                raw_action="s3:PutBucketVersioning",
            )
        )
    return events


def _mixed_benign_malicious(start: datetime) -> list[ResourceActivityEvent]:
    """16. Benign traffic plus an embedded destructive burst."""
    events: list[ResourceActivityEvent] = []
    for i in range(30):
        events.append(
            _event(
                f"mx-b-{i:03d}",
                start + timedelta(seconds=20 * i),
                actor_id="alice.admin",
                action_category=ActionCategory.READ,
                resource_id=f"fin-prod-archive/report-{i % 4}.json",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/report-{i % 4}.json",
                raw_action="s3:GetObject",
            )
        )
    burst_base = start + timedelta(minutes=20)
    for i in range(12):
        events.append(
            _event(
                f"mx-a-{i:03d}",
                burst_base + timedelta(seconds=5 * i),
                actor_id="attacker.burst",
                action_category=ActionCategory.DELETE,
                resource_id=f"fin-prod-archive/object-{i}.dat",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/object-{i}.dat",
                raw_action="s3:DeleteObject",
            )
        )
    return events


def _missing_telemetry(start: datetime) -> list[ResourceActivityEvent]:
    """17. Destructive burst with degraded telemetry fields."""
    events: list[ResourceActivityEvent] = []
    for i in range(10):
        events.append(
            _event(
                f"mt-{i:03d}",
                start + timedelta(seconds=6 * i),
                actor_id="attacker.burst",
                action_category=ActionCategory.DELETE,
                resource_id=f"fin-prod-archive/object-{i}.dat",
                resource_type=ResourceType.UNKNOWN,
                resource_arn=None,
                account_id=None,
                region=None,
                raw_action="s3:DeleteObject",
            )
        )
    return events


def _out_of_order_events(start: datetime) -> list[ResourceActivityEvent]:
    """18. A destructive burst delivered out of chronological order."""
    ordered = _mass_object_deletion(
        start, event_id_prefix="oo"
    )
    # deterministic shuffle: even indices first, then odd, reversed
    shuffled = ordered[::2] + ordered[1::2][::-1]
    return shuffled


def acceptance_attack_chain(start: datetime) -> list[ResourceActivityEvent]:
    """Final acceptance scenario: the full kill chain from a legitimate identity.

    A **legitimate cloud identity** (``alice.admin``, an IAM user with
    ordinary write history) suddenly:

    1. bursts modifications across a large set of production objects;
    2. begins mass deletion;
    3. deletes object versions (history destruction);
    4. deletes snapshots and recovery points (recovery destruction);
    5. weakens recovery protection (bucket versioning switched off).

    Two benign write sessions 48h/24h earlier give the identity a real
    behavioral baseline, so step 3 of the acceptance test (compare
    against resource baseline) is a genuine baseline comparison, not a
    no-op. All attack-phase events fall inside one session (well under
    the 30-minute idle timeout). Deterministic: same ``start`` ⇒ same
    events. Production resources carry CRITICAL business criticality.
    """
    events: list[ResourceActivityEvent] = []

    def _critical(overrides: dict[str, object]) -> dict[str, object]:
        overrides.setdefault(
            "business_criticality", BusinessCriticality.CRITICAL
        )
        return overrides

    # --- legitimate history: two ordinary write sessions (baseline) ---
    for session_index in range(2):
        base = start - timedelta(hours=24 * (2 - session_index))
        for i in range(20):
            events.append(
                _event(
                    f"ac-h{session_index}-{i:03d}",
                    base + timedelta(seconds=30 * i),
                    actor_id="alice.admin",
                    action_category=ActionCategory.CREATE,
                    resource_id=f"fin-prod-archive/report-{i % 5}.json",
                    resource_arn=f"arn:aws:s3:::fin-prod-archive/report-{i % 5}.json",
                    raw_action="s3:PutObject",
                )
            )

    attack = start

    # 1) sudden burst of modifications across many production objects
    for i in range(16):
        events.append(
            _event(
                f"ac-m-{i:03d}",
                attack + timedelta(seconds=6 * i),
                actor_id="alice.admin",
                action_category=ActionCategory.MODIFY,
                resource_id=f"fin-prod-db/record-{i}.json",
                resource_arn=f"arn:aws:s3:::fin-prod-db/record-{i}.json",
                raw_action="s3:PutObject",
                **_critical({}),
            )
        )

    # 2) mass deletion begins
    for i in range(16):
        events.append(
            _event(
                f"ac-d-{i:03d}",
                attack + timedelta(seconds=120 + 4 * i),
                actor_id="alice.admin",
                action_category=ActionCategory.DELETE,
                resource_id=f"fin-prod-archive/object-{i}.dat",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/object-{i}.dat",
                raw_action="s3:DeleteObject",
                **_critical({}),
            )
        )

    # 3) versions are deleted
    for i in range(8):
        events.append(
            _event(
                f"ac-v-{i:03d}",
                attack + timedelta(seconds=200 + 4 * i),
                actor_id="alice.admin",
                action_category=ActionCategory.VERSION_DELETE,
                resource_id=f"fin-prod-archive/object-{i}.dat",
                resource_arn=f"arn:aws:s3:::fin-prod-archive/object-{i}.dat",
                operation_type=OperationType.VERSIONED,
                raw_action="s3:DeleteObjectVersion",
                version_id=f"acv-{i:04d}",
                **_critical({}),
            )
        )

    # 4) snapshots / recovery points are deleted
    for i in range(4):
        events.append(
            _event(
                f"ac-s-{i:03d}",
                attack + timedelta(seconds=260 + 5 * i),
                actor_id="alice.admin",
                action_category=ActionCategory.SNAPSHOT_DELETE,
                resource_id=f"snap-prod-{i:04d}",
                resource_type=ResourceType.EBS_SNAPSHOT,
                resource_arn=f"arn:aws:ec2:us-east-1:111122223333:snapshot/snap-prod-{i:04d}",
                raw_action="ec2:DeleteSnapshot",
                snapshot_id=f"snap-prod-{i:04d}",
                **_critical({}),
            )
        )
    for i in range(4):
        events.append(
            _event(
                f"ac-r-{i:03d}",
                attack + timedelta(seconds=285 + 5 * i),
                actor_id="alice.admin",
                action_category=ActionCategory.RECOVERY_POINT_DELETE,
                resource_id=f"recovery-point-fin-{i:04d}",
                resource_type=ResourceType.RECOVERY_POINT,
                resource_arn=f"arn:aws:backup:us-east-1:111122223333:recovery-point:fin-{i:04d}",
                raw_action="backup:DeleteRecoveryPoint",
                recovery_point_id=f"recovery-point-fin-{i:04d}",
                **_critical({}),
            )
        )

    # 5) recovery protection is weakened
    for i in range(2):
        events.append(
            _event(
                f"ac-p-{i:03d}",
                attack + timedelta(seconds=320 + 10 * i),
                actor_id="alice.admin",
                action_category=ActionCategory.PROTECTION_CHANGE,
                resource_id=f"fin-prod-store/bucket-{i}",
                resource_type=ResourceType.S3_BUCKET,
                resource_arn=f"arn:aws:s3:::fin-prod-store-bucket-{i}",
                raw_action="s3:PutBucketVersioning",
                **_critical({}),
            )
        )

    return events


# ---------------------------------------------------------------------- #
# Scenario registry
# ---------------------------------------------------------------------- #


@dataclass(frozen=True)
class Scenario:
    """One evaluation scenario with its ground-truth label."""

    number: int
    name: str
    expected_positive: bool
    description: str
    build: Callable[[datetime], list[ResourceActivityEvent]]

    def events(self, start: datetime) -> list[ResourceActivityEvent]:
        return self.build(start)


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(1, "normal_writes", False, "steady low-rate writes", _normal_writes),
    Scenario(2, "normal_cleanup", False, "small spaced cleanup", _normal_cleanup),
    Scenario(3, "lifecycle_expiration", False, "lifecycle service expirations", _lifecycle_expiration),
    Scenario(4, "backup_retention_cleanup", False, "scheduled retention cleanup", _backup_retention_cleanup),
    Scenario(5, "normal_deployment", False, "deployment writes", _normal_deployment),
    Scenario(6, "large_legitimate_migration", False, "paced migration with actor history", _large_legitimate_migration),
    Scenario(7, "mass_object_modification", True, "burst of modifications", _mass_object_modification),
    Scenario(8, "mass_object_deletion", True, "rapid mass deletion", _mass_object_deletion),
    Scenario(9, "mass_version_deletion", True, "object version destruction", _mass_version_deletion),
    Scenario(10, "snapshot_deletion", True, "snapshot deletion across regions", _snapshot_deletion),
    Scenario(11, "backup_recovery_point_deletion", True, "recovery-point deletion", _backup_recovery_point_deletion),
    Scenario(12, "protection_degradation", True, "protection state weakened", _protection_degradation),
    Scenario(13, "mass_rewrite_pattern", True, "mass copy-overwrite rewrites", _mass_rewrite_pattern),
    Scenario(14, "slow_destructive_behavior", True, "slow-paced destruction over hours", _slow_destructive_behavior),
    Scenario(15, "compound_destructive_behavior", True, "multi-signal compound attack", _compound_destructive_behavior),
    Scenario(16, "mixed_benign_malicious", True, "benign traffic with embedded burst", _mixed_benign_malicious),
    Scenario(17, "missing_telemetry", True, "destructive burst with degraded telemetry", _missing_telemetry),
    Scenario(18, "out_of_order_events", True, "destructive burst delivered out of order", _out_of_order_events),
)


def scenario_by_number(number: int) -> Scenario:
    for scenario in SCENARIOS:
        if scenario.number == number:
            return scenario
    raise ValueError(f"no scenario numbered {number}")


#: The final acceptance scenario — distinct from the 18 evaluation
#: scenarios (number 0 marks it as the acceptance gate, not an
#: evaluation scenario).
ATTACK_CHAIN = Scenario(
    0,
    "acceptance_attack_chain",
    True,
    "legitimate identity runs the full destruction kill chain",
    acceptance_attack_chain,
)


# Business-criticality enrichment used by evaluation harnesses: mark
# production resources critical so criticality signals are measurable.
def mark_critical(events: list[ResourceActivityEvent]) -> list[ResourceActivityEvent]:
    """Return events with business criticality set on production resources."""
    enriched: list[ResourceActivityEvent] = []
    for event in events:
        if event.resource_id and "fin-prod" in str(event.resource_id):
            enriched.append(
                event.model_copy(
                    update={"business_criticality": BusinessCriticality.CRITICAL}
                )
            )
        else:
            enriched.append(event)
    return enriched
