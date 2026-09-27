"""Research harness + API tests (final stage)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from research.datasets import (
    SCENARIO_COMPROMISE,
    SCENARIO_MULTI,
    SCENARIO_NORMAL,
    SCENARIO_SINGLE,
    build_research_dataset,
)
from research.evaluation import (
    SystemRunner,
    evaluate_system,
    temporal_three_way_split,
    tune_threshold,
)
from research.metrics import (
    ConfusionMatrix,
    brier_score,
    expected_calibration_error,
    latency_stats,
    pr_auc,
    precision_at_recall,
    recall_at_fpr,
    roc_auc,
)
from research.performance import run_performance_benchmark
from research.reporting import SYNTHETIC_DISCLAIMER, write_research_artifacts


# --------------------------------------------------------------------------- #
# Metrics math (hand-computed references)
# --------------------------------------------------------------------------- #


class TestMetrics:
    def test_confusion_matrix_properties(self):
        cm = ConfusionMatrix(tp:=0, 0, 0, 0) if False else ConfusionMatrix(8, 2, 2, 88)
        assert cm.precision == 0.8
        assert cm.recall == 0.8
        assert cm.f1 == 0.8
        assert cm.fpr == pytest.approx(2 / 90, abs=1e-6)
        assert cm.fnr == 0.2

    def test_pr_auc_perfect_classifier(self):
        labels = [0, 0, 1, 1]
        scores = [0.1, 0.2, 0.8, 0.9]
        assert pr_auc(labels, scores) == 1.0

    def test_roc_auc_matches_rank_statistic(self):
        labels = [0, 0, 1, 1]
        scores = [0.1, 0.2, 0.8, 0.9]
        assert roc_auc(labels, scores) == 1.0
        # Reversed ranking must yield 0.
        assert roc_auc(labels, [0.9, 0.8, 0.2, 0.1]) == 0.0
        # Random-ish tie handling: all-equal scores -> 0.5.
        assert roc_auc(labels, [0.5, 0.5, 0.5, 0.5]) == 0.5

    def test_calibration_metrics_bounded(self):
        probs = [0.1, 0.2, 0.9, 0.95]
        labels = [0, 0, 1, 1]
        assert brier_score(probs, labels) < 0.05
        # Hand-computed: bins {0.1->0.1err, 0.2->0.2err, 0.925->0.075err}.
        assert expected_calibration_error(probs, labels) == pytest.approx(0.1125, abs=1e-6)
        # A perfectly calibrated pair scores 0.
        assert expected_calibration_error([0.5], [1]) == pytest.approx(0.5, abs=1e-6)
        assert expected_calibration_error([1.0, 0.0], [1, 0]) == pytest.approx(0.0, abs=1e-9)

    def test_precision_at_recall_and_recall_at_fpr(self):
        labels = [0] * 8 + [1] * 2
        scores = [0.95, 0.9, 0.3, 0.25, 0.2, 0.15, 0.1, 0.05, 0.85, 0.8]
        # At recall 1.0 (threshold 0.8), precision is 2/4.
        assert precision_at_recall(labels, scores, 1.0) == pytest.approx(0.5)
        # The two negatives at 0.95/0.9 outrank both positives, so reaching
        # recall 1.0 costs 2 FPs (FPR 0.25). At FPR <= 0.125 recall is 0.
        assert recall_at_fpr(labels, scores, 0.125) == pytest.approx(0.0)
        assert recall_at_fpr(labels, scores, 0.25) == pytest.approx(1.0)

    def test_latency_stats_lead_time(self):
        t0 = datetime(2026, 6, 1, tzinfo=timezone.utc)
        labels = [0, 0, 1, 1]
        predicted = [False, False, True, True]
        stamps = [t0, t0 + timedelta(minutes=1), t0 + timedelta(minutes=2), t0 + timedelta(minutes=3)]
        stats = latency_stats(labels, predicted, stamps)
        assert stats.detection_latency_events == 0
        assert stats.detection_lead_time_minutes == 0.0


# --------------------------------------------------------------------------- #
# Dataset & split integrity
# --------------------------------------------------------------------------- #


class TestDatasets:
    def test_dataset_has_all_four_scenario_classes(self):
        scenarios = build_research_dataset(n_identities=4, n_benign=60, seed=3)
        kinds = {s.scenario for s in scenarios}
        assert {SCENARIO_NORMAL, SCENARIO_SINGLE, SCENARIO_MULTI, SCENARIO_COMPROMISE} <= kinds

    def test_compromise_labels_exist_and_benign_streams_are_clean(self):
        scenarios = build_research_dataset(n_identities=4, n_benign=60, seed=3)
        compromise = [s for s in scenarios if s.scenario == SCENARIO_COMPROMISE]
        assert compromise and all(sum(s.labels) > 0 for s in compromise)
        normal = [s for s in scenarios if s.scenario == SCENARIO_NORMAL]
        assert all(sum(s.labels) == 0 for s in normal)
        single = [s for s in scenarios if s.scenario == SCENARIO_SINGLE]
        multi = [s for s in scenarios if s.scenario == SCENARIO_MULTI]
        assert all(sum(s.labels) == 0 for s in single + multi)

    def test_three_way_split_is_chronological_and_disjoint(self):
        scenarios = build_research_dataset(n_identities=2, n_benign=60, seed=3)
        stream = scenarios[0]
        train, val, test = temporal_three_way_split(stream.events, stream.labels)
        assert train and val and test
        assert train[-1][0].timestamp <= val[0][0].timestamp
        assert val[-1][0].timestamp <= test[0][0].timestamp
        ids = ({e.event_id for e, _ in train}, {e.event_id for e, _ in val}, {e.event_id for e, _ in test})
        assert not (ids[0] & ids[1]) and not (ids[1] & ids[2]) and not (ids[0] & ids[2])


# --------------------------------------------------------------------------- #
# System comparison
# --------------------------------------------------------------------------- #


class TestSystemComparison:
    @pytest.fixture(scope="class")
    def prepared(self):
        scenarios = build_research_dataset(
            n_identities=4, n_benign=120, n_single=20, n_multi=20, n_attack=8, seed=11
        )
        runner = SystemRunner()
        evaluations: dict[str, object] = {}
        for name, builder in (
            ("A: rules only", lambda: runner.system_a()),
            ("B: rules + baseline", lambda: runner.system_b(prepared_train)[0]),
            ("C: + ML", lambda: runner.system_c(prepared_train)[0]),
            ("D: full pipeline", lambda: runner.system_d(prepared_train)[0]),
        ):
            _ = builder  # built lazily below per split
        # Build per-stream splits, then concatenate into global splits.
        train: list = []
        validation: list = []
        test: list = []
        for scenario in scenarios:
            tr, va, te = temporal_three_way_split(scenario.events, scenario.labels)
            train.extend(tr)
            validation.extend(va)
            test.extend(te)
        prepared_train = train
        prepared_val = validation
        prepared_test = test

        # A: stateless scorer.
        scorer_a = runner.system_a()
        evaluations["A: rules only"] = evaluate_system(
            "A: rules only", scorer_a, validation=prepared_val, test=prepared_test
        )
        scorer_b, _det_b = runner.system_b(prepared_train)
        evaluations["B: rules + baseline"] = evaluate_system(
            "B: rules + baseline", scorer_b, validation=prepared_val, test=prepared_test
        )
        scorer_c, forest_c = runner.system_c(prepared_train)
        assert forest_c is not None, "training data must support the forest"
        evaluations["C: + ML"] = evaluate_system(
            "C: + ML", scorer_c, validation=prepared_val, test=prepared_test
        )
        scorer_d, _det_d = runner.system_d(prepared_train)
        evaluations["D: full pipeline"] = evaluate_system(
            "D: full pipeline", scorer_d, validation=prepared_val, test=prepared_test
        )
        return evaluations, (prepared_train, prepared_val, prepared_test)

    def test_all_four_systems_produce_metrics(self, prepared):
        evaluations, _ = prepared
        assert set(evaluations) == {
            "A: rules only", "B: rules + baseline", "C: + ML", "D: full pipeline",
        }
        for evaluation in evaluations.values():
            metrics = evaluation.metrics_dict()
            assert metrics["precision"] is not None
            assert metrics["recall"] is not None
            assert metrics["f1"] is not None
            assert metrics["pr_auc"] is not None
            assert metrics["roc_auc"] is not None

    def test_baseline_systems_beat_rules_only(self, prepared):
        """The core research question, answered on this synthetic dataset."""
        evaluations, _ = prepared
        rules_only_f1 = evaluations["A: rules only"].confusion.f1 or 0.0
        baseline_f1 = evaluations["B: rules + baseline"].confusion.f1 or 0.0
        full_f1 = evaluations["D: full pipeline"].confusion.f1 or 0.0
        # Hybrid layers must not be worse than static rules here...
        assert baseline_f1 >= rules_only_f1
        assert full_f1 >= rules_only_f1
        # ...and the full pipeline must achieve usable precision on the
        # compromise class (synthetic data - relative claim only).
        full_precision = evaluations["D: full pipeline"].confusion.precision
        assert full_precision is not None and full_precision >= 0.5

    def test_thresholds_frozen_from_validation(self, prepared):
        evaluations, (train, validation, _test) = prepared
        # Threshold must equal what val-only tuning produces (spot check B).
        scorer_b, _ = SystemRunner().system_b(train)
        val_scores = [scorer_b(e)[0] for e, _ in validation]
        val_labels = [label for _, label in validation]
        expected = tune_threshold(val_scores, val_labels)
        assert evaluations["B: rules + baseline"].threshold == pytest.approx(expected, abs=0.01)


# --------------------------------------------------------------------------- #
# Performance benchmark smoke test
# --------------------------------------------------------------------------- #


class TestPerformance:
    def test_benchmark_runs_and_reports_all_fields(self):
        result = run_performance_benchmark(n_history=120, n_bench=200)
        payload = result.as_dict()
        for field in (
            "events_per_second", "mean_latency_ms", "p95_latency_ms",
            "max_latency_ms", "memory_delta_mb",
        ):
            assert field in payload
        assert payload["events_per_second"] > 0
        assert payload["mean_latency_ms"] >= 0
        # p95 >= mean sanity
        assert payload["p95_latency_ms"] >= payload["mean_latency_ms"]


# --------------------------------------------------------------------------- #
# Artifact generation
# --------------------------------------------------------------------------- #


class TestArtifacts:
    def test_write_research_artifacts(self, tmp_path):
        from research.evaluation import SystemEvaluation

        cm = ConfusionMatrix(8, 2, 2, 88)
        from research.metrics import LatencyStats

        evaluation = SystemEvaluation(
            system="A: rules only",
            threshold=60.0,
            confusion=cm,
            latency=LatencyStats(0, 0.0, 0),
            pr_auc=0.9,
            roc_auc=0.95,
            brier=0.05,
            ece=0.03,
            precision_at_recall_08=0.9,
            recall_at_fpr_01=0.8,
        )
        paths = write_research_artifacts(
            tmp_path,
            evaluations={"A: rules only": evaluation},
            scenarios=build_research_dataset(n_identities=2, n_benign=30, seed=5),
        )
        assert {"metrics.json", "evaluation_report.json", "research_report.md"} <= set(paths)
        metrics = paths["metrics.json"].read_text(encoding="utf-8")
        assert "SYNTHETIC" in metrics
        report = paths["research_report.md"].read_text(encoding="utf-8")
        assert "## Results" in report
        assert "## Limitations" in report
        assert "SYNTHETIC" in report
