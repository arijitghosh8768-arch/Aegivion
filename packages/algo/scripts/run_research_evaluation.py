"""Run the complete Aegivion Algorithm #1 research evaluation.

Executes: dataset build -> train/val/test temporal split -> four-system
comparison with val-only threshold tuning -> ablation -> FP analysis ->
cross-identity -> drift -> performance benchmark -> artifact generation.

Usage:
    python scripts/run_research_evaluation.py [output_dir]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.datasets import build_research_dataset, SCENARIO_COMPROMISE, SCENARIO_MULTI, SCENARIO_NORMAL, SCENARIO_SINGLE
from research.evaluation import (
    SystemRunner,
    evaluate_system,
    temporal_three_way_split,
)
from detection.credential_compromise.detector import CredentialCompromiseDetector
from research.performance import run_performance_benchmark
from research.reporting import write_research_artifacts


def main() -> int:
    output_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("research/artifacts")

    print("Building controlled dataset ...")
    scenarios = build_research_dataset(
        n_identities=8,
        n_benign=180,
        n_single=30,
        n_multi=30,
        n_attack=8,
        seed=2026,
    )
    summary: dict[str, dict] = {}
    for scenario in scenarios:
        bucket = summary.setdefault(scenario.scenario, {"streams": 0, "events": 0, "positives": 0})
        bucket["streams"] += 1
        bucket["events"] += len(scenario)
        bucket["positives"] += sum(scenario.labels)
    for name, bucket in summary.items():
        print(f"  {name}: {bucket['events']} events / {bucket['positives']} positives / {bucket['streams']} streams")

    # Chronological splits per stream, then concatenated.
    train: list = []
    validation: list = []
    test: list = []
    for scenario in scenarios:
        tr, va, te = temporal_three_way_split(scenario.events, scenario.labels)
        train.extend(tr)
        validation.extend(va)
        test.extend(te)
    print(f"Split sizes: train={len(train)} validation={len(validation)} test={len(test)}")

    runner = SystemRunner()
    evaluations = {}

    print("Evaluating System A (rules only) ...")
    scorer_a = runner.system_a()
    evaluations["A: rules only"] = evaluate_system(
        "A: rules only", scorer_a, validation=validation, test=test
    )

    print("Evaluating System B (rules + baseline) ...")
    scorer_b, _ = runner.system_b(train)
    evaluations["B: rules + baseline"] = evaluate_system(
        "B: rules + baseline", scorer_b, validation=validation, test=test
    )

    print("Evaluating System C (rules + baseline + ML) ...")
    scorer_c, forest = runner.system_c(train)
    if forest is None:
        print("  WARNING: forest not fitted (insufficient rows); C falls back to B")
    evaluations["C: rules + baseline + ML"] = evaluate_system(
        "C: rules + baseline + ML", scorer_c, validation=validation, test=test
    )

    print("Evaluating System D (full pipeline + ARDE) ...")
    scorer_d, _ = runner.system_d(train)
    evaluations["D: full pipeline"] = evaluate_system(
        "D: full pipeline", scorer_d, validation=validation, test=test
    )

    # Ablation: full pipeline minus one layer at a time.
    print("Running ablation study ...")
    ablation: dict = {}
    from detection.credential_compromise.config import DetectorConfig, RuleEngineConfig
    from detection.credential_compromise.rules import RULE_CATALOGUE

    base_config = DetectorConfig()

    # without rules: disable the whole catalogue
    all_rule_ids = tuple(rule.rule_id for rule in RULE_CATALOGUE)
    config_no_rules = base_config.model_copy(
        deep=True,
        update={"rules": RuleEngineConfig(disabled_rules=all_rule_ids)},
    )
    runner_no_rules = SystemRunner(config=config_no_rules)
    scorer_no_rules, _ = runner_no_rules.system_d(train)
    ablation["without_rules"] = evaluate_system(
        "without_rules", scorer_no_rules, validation=validation, test=test
    )

    # without ML: D but the detector has no forest (System B's scorer with D config)
    ablation["without_ml"] = evaluate_system(
        "without_ml", scorer_b, validation=validation, test=test
    )

    # without privilege features: zero their weight in scoring
    from detection.credential_compromise.config import DEFAULT_WEIGHTS, ScoringConfig

    weights_no_priv = dict(DEFAULT_WEIGHTS)
    weights_no_priv["privilege"] = 0.0
    weights_no_priv["api"] = weights_no_priv["api"] + 0.15
    config_no_priv = base_config.model_copy(
        deep=True,
        update={"scoring": ScoringConfig(weights=weights_no_priv)},
    )
    runner_no_priv = SystemRunner(config=config_no_priv)
    scorer_no_priv, _ = runner_no_priv.system_d(train)
    ablation["without_privilege_features"] = evaluate_system(
        "without_privilege_features", scorer_no_priv, validation=validation, test=test
    )

    # without temporal: zero the temporal weight in fusion
    from detection.credential_compromise.config import FusionConfig

    config_no_temporal = base_config.model_copy(
        deep=True,
        update={
            "fusion": FusionConfig(
                w_behavior=0.50, w_rule=0.30, w_anomaly=0.10, w_temporal=0.0, w_privilege=0.10
            )
        },
    )
    runner_no_temporal = SystemRunner(config=config_no_temporal)
    scorer_no_temporal, _ = runner_no_temporal.system_d(train)
    ablation["without_temporal"] = evaluate_system(
        "without_temporal", scorer_no_temporal, validation=validation, test=test
    )

    # without ARDE: use System C's scorer (no validation layer in the loop).
    ablation["without_arde"] = evaluate_system(
        "without_arde", scorer_c, validation=validation, test=test
    )

    # Drift simulation: feed benign drift phases (device/travel/hours/API),
    # then a late attack. The detector must adapt without learning the attack.
    print("Running drift simulation ...")
    from research.evaluation import drift_stream
    from detection.credential_compromise.detector import DetectionMode

    compromise_scenarios = [s for s in scenarios if s.scenario == SCENARIO_COMPROMISE]
    drift_results = {}
    if compromise_scenarios:
        drift_events, drift_labels, drift_tags = drift_stream(
            compromise_scenarios[0], phase_benign=120,
            drift_phases=("device_change", "travel", "hours_shift", "new_api"),
            per_phase=30,
        )
        drift_detector_obj = CredentialCompromiseDetector(config=base_config)
        history = [e for e, t, tag in zip(drift_events, drift_labels, drift_tags) if tag == "history"]
        drift_detector_obj.learn(sorted(history, key=lambda e: e.timestamp))
        drift_findings = 0
        attack_caught = None
        for event, label, tag in zip(drift_events, drift_labels, drift_tags):
            if tag == "history":
                continue
            result = drift_detector_obj.detect(event, mode=DetectionMode.REPLAY)
            if tag != "attack" and result.is_finding:
                drift_findings += 1
            if tag == "attack" and result.is_finding and attack_caught is None:
                attack_caught = event.event_name
        drift_results = {
            "drift_phases": ["device_change", "travel", "hours_shift", "new_api"],
            "drift_events_scored": sum(1 for t in drift_tags if t not in ("history", "attack")),
            "drift_events_flagged_as_findings": drift_findings,
            "late_attack_detected": attack_caught is not None,
            "late_attack_caught_at": attack_caught,
            "note": (
                "flagged drift events above zero indicate the risk-aware baseline "
                "update cadence is conservative; none of them are suppressed silently"
            ),
        }
        print(f"  drift flagged: {drift_findings}, late attack detected: {attack_caught is not None}")

    # Cross-identity: per-stream test metrics on System D.
    print("Running cross-identity evaluation ...")
    from research.evaluation import cross_identity_evaluation

    scorer_d_frozen, _ = runner.system_d(train)
    train_by_identity: dict[str, list] = {}
    test_by_identity: dict[str, list] = {}
    for event, label in train:
        train_by_identity.setdefault(event.identity_key, []).append((event, label))
    for event, label in test:
        test_by_identity.setdefault(event.identity_key, []).append((event, label))

    def factory():
        return scorer_d_frozen, None

    cross_identity = cross_identity_evaluation(
        scorer_factory=factory,
        train_by_identity=train_by_identity,
        test_by_identity=test_by_identity,
        threshold=evaluations["D: full pipeline"].threshold,
    )
    print(f"  identities evaluated: {len(cross_identity)}")

    print("Benchmarking performance ...")
    performance = run_performance_benchmark(n_history=300, n_bench=1500)
    print(f"  {performance.events_per_second:.0f} events/s, p95 {performance.p95_latency_ms:.2f} ms")

    print("Writing artifacts ...")
    paths = write_research_artifacts(
        output_dir,
        evaluations=evaluations,
        ablation=ablation,
        cross_identity=cross_identity,
        drift=drift_results or None,
        scenarios=scenarios,
        performance=performance,
    )
    for name, path in paths.items():
        print(f"  {name}: {path}")
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
