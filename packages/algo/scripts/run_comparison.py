"""Run the Part 3 comparative evaluation over the synthetic fixture corpus.

Builds a labeled corpus (label_source="synthetic") from the synthetic
fixtures:

- positives: mass_deletion, version_deletion, snapshot_deletion,
  recovery_point_deletion, and the compromised contractor's activity in
  mixed_normal_destructive;
- negatives: normal_writes, normal_lifecycle_cleanup,
  scheduled_backup_cleanup, and the benign actors in
  mixed_normal_destructive.

Usage:

    python scripts/run_comparison.py

Label discipline: all labels here are SYNTHETIC (fixture-derived). Results
are reported with that provenance and are not production performance.

Do not proceed to Part 4 until this comparison runs successfully.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.cloud_destruction.evaluation import (  # noqa: E402
    LabeledCorpus,
    evaluate_variants,
)
from detection.cloud_destruction.normalizer import ResourceActivityNormalizer  # noqa: E402
from detection.cloud_destruction.session import DestructiveSessionBuilder  # noqa: E402
from detection.cloud_destruction.tests.helpers import BASE_TIME  # noqa: E402
from detection.cloud_destruction.tests.test_part2_behavior import (  # noqa: E402
    hist_session,
    mass_session,
)

SYNTH = Path(__file__).resolve().parents[1] / "detection" / "cloud_destruction" / "tests" / "fixtures" / "synthetic"

POSITIVE_SCENARIOS = (
    "mass_deletion",
    "version_deletion",
    "snapshot_deletion",
    "recovery_point_deletion",
)
NEGATIVE_SCENARIOS = (
    "normal_writes",
    "normal_lifecycle_cleanup",
    "scheduled_backup_cleanup",
)


def load_scenario_records(name: str) -> list[dict]:
    payload = json.loads((SYNTH / name / "raw.json").read_text(encoding="utf-8"))
    return payload["records"]


def normalize_all(records: list[dict]):
    normalizer = ResourceActivityNormalizer()
    events = []
    for index, record in enumerate(records):
        try:
            events.append(normalizer.normalize_cloudtrail(record))
        except Exception:
            continue  # malformed fixture records contribute nothing here
    return events


COMPROMISED_ACTOR_MARKER = "compromised-session"


def build_corpus() -> LabeledCorpus:
    """Assemble the labeled synthetic corpus from fixtures + generated actors."""
    from detection.cloud_destruction.schemas import ResourceActivityEvent

    positive_event_ids: set[str] = set()
    negative_event_ids: set[str] = set()
    events: list[ResourceActivityEvent] = []

    # fixture scenarios -> positive (destructive) and negative (benign)
    for name in POSITIVE_SCENARIOS:
        for event in normalize_all(load_scenario_records(name)):
            positive_event_ids.add(event.event_id)
            events.append(event)
    for name in NEGATIVE_SCENARIOS:
        for event in normalize_all(load_scenario_records(name)):
            negative_event_ids.add(event.event_id)
            events.append(event)

    # mixed scenario: split by actor
    for event in normalize_all(load_scenario_records("mixed_normal_destructive")):
        if event.actor_id and COMPROMISED_ACTOR_MARKER in event.actor_id:
            positive_event_ids.add(event.event_id)
        else:
            negative_event_ids.add(event.event_id)
        events.append(event)

    # generated per-actor history so baselines have something to learn from:
    # 6 calm actors, 4 burst attackers (labels follow the generator)
    for i in range(6):
        session, session_events = hist_session(
            f"calm-svc-{i}", 12, start=BASE_TIME + timedelta(hours=50 * i)
        )
        negative_event_ids.update(e.event_id for e in session_events)
        events.extend(session_events)
    for i in range(4):
        session, session_events = mass_session(
            n=14, actor=f"burst-attacker-{i}", start=BASE_TIME + timedelta(hours=50 * i)
        )
        positive_event_ids.update(e.event_id for e in session_events)
        events.extend(session_events)

    return LabeledCorpus(
        events=tuple(events),
        positive_event_ids=frozenset(positive_event_ids),
        negative_event_ids=frozenset(negative_event_ids),
        label_source="synthetic",
        description=(
            "synthetic: fixture destructive scenarios + generated bursts vs "
            "benign fixture scenarios + generated calm history"
        ),
    )


def main() -> int:
    corpus = build_corpus()
    print("=" * 74)
    print("Aegivion Algorithm #3 — Part 3 comparative evaluation")
    print(f"events: {len(corpus.events)}  label_source: {corpus.label_source}")
    print(f"positive events: {len(corpus.positive_event_ids)}  negative events: {len(corpus.negative_event_ids)}")
    print("=" * 74)

    results = evaluate_variants(corpus, threshold=0.3)

    header = (
        f"{'variant':<20}{'precision':>10}{'recall':>9}{'f1':>8}"
        f"{'PR-AUC':>9}{'FPR':>8}{'ms/sess':>9}"
    )
    print(header)
    print("-" * len(header))
    for name in (
        "rules_only",
        "rules_baseline",
        "rules_sequence",
        "rules_baseline_ml",
        "full",
    ):
        row = results[name].to_log_dict()
        print(
            f"{row['variant']:<20}{row['precision']:>10.3f}{row['recall']:>9.3f}"
            f"{row['f1']:>8.3f}{row['pr_auc']:>9.3f}{row['false_positive_rate']:>8.3f}"
            f"{row['latency_ms_per_session']:>9.2f}"
        )
    print("-" * len(header))
    print(
        "NOTE: label_source='synthetic' — these numbers measure detector "
        "behavior on\nsynthetic fixtures, NOT production performance."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
