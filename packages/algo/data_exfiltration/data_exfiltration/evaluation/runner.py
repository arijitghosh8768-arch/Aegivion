"""Final-stage evaluation runner (A–E comparison + ablation + errors).

Orchestrates the full final-stage evaluation over the 15-scenario
synthetic corpus:

1. build the labeled session corpus (temporal order preserved),
2. chronological train/validation/test split (no leakage),
3. score variants A–E — E applies ARDE to alerted sessions,
4. compute the full metric set per variant,
5. leave-one-component-out ablation,
6. error analysis (structured FP/FN records),
7. write deterministic artifacts marked synthetic.

Nothing here claims production accuracy: the dataset is synthetic and
every artifact repeats that.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from algo.data_exfiltration.data_exfiltration.arde import ARDEValidator, ApprovedActivityRegistry
from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import BehavioralFeatureSet
from algo.data_exfiltration.data_exfiltration.ml.evaluation import _r
from algo.data_exfiltration.data_exfiltration.ml.isolation_forest import IsolationForest
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack
from algo.data_exfiltration.data_exfiltration.ml.replay import TemporalSplit, temporal_split

from .dataset import LabeledRecord, run_detector_on_corpus
from .error_analysis import analyze_errors
from .metrics import full_metrics
from .scenarios import build_instances
from .variants import run_variants

EVAL_SEED = 42


def prepare_feature_records(
    records: list[LabeledRecord],
) -> list[LabeledRecord]:
    """Attach behavioral feature sets to records, chronology-safe.

    Mirrors production operation in two phases per session, in session
    end-time order:

    1. RECORD the closed sessions that precede this session into the
       baseline engine — poisoning-gated: only label-0 (benign) sessions
       shape trusted statistics (the evaluation's ground truth plays the
       role of the production risk gate);
    2. PROFILE the session against the history that existed before it —
       the future does not exist yet (no leakage).

    Also builds each actor's access universe from past benign sessions
    only, and only after at least ``_MIN_UNIVERSE_EVENTS`` observations,
    so cold start stays honest.
    """
    from algo.data_exfiltration.data_exfiltration.intelligence.access_pattern_intelligence import (
        KnownAccessUniverse,
        build_access_universe,
    )
    from algo.data_exfiltration.data_exfiltration.intelligence.baseline_guard import BaselineInfluence
    from algo.data_exfiltration.data_exfiltration.intelligence.profiler import (
        BehavioralProfiler,
        IntelligenceContext,
    )
    from algo.data_exfiltration.data_exfiltration.ml.feature_vector import build_feature_vector

    profiler = BehavioralProfiler()
    ordered = sorted(records, key=lambda r: r.session.end_time_epoch_ms or 0.0)

    past_events_by_actor: dict[str, list] = {}
    universes: dict[str, KnownAccessUniverse] = {}
    _MIN_UNIVERSE_EVENTS = 30

    for record in ordered:
        if record.session.session_features.get("_behavioral_feature_set") is not None:
            continue
        actor = record.session.actor_id or "unknown"

        # history recording must precede profiling of THIS session, but
        # contains only earlier sessions (we record lazily right before
        # profiling the next session of the same actor — see below).
        universe = universes.get(actor)
        if universe is not None:
            universe = universe.universe  # KnownAccessUniverse from the profile
        context = IntelligenceContext(known_access=universe)

        result = profiler.profile(record.session, record.events, context)
        fset: BehavioralFeatureSet = result.features
        # Build the frozen ML feature vector so the C/D/E variants actually
        # exercise the anomaly model. Without this the Isolation Forest has
        # nothing to fit or score, and "+ ML" would be a label with no ML.
        vector = build_feature_vector(fset, subject_id=actor)
        fset.session_features["feature_vector"] = vector.ordered_values()
        fset.session_features["feature_vector_obj"] = vector
        record.session.session_features["_behavioral_feature_set"] = fset
        record.session.session_features["session_duration_s"] = (
            (record.session.end_time_epoch_ms or 0.0)
            - (record.session.start_time_epoch_ms or 0.0)
        ) / 1000.0

        # after profiling, this session closes into history (it will only
        # influence LATER sessions)
        influence = BaselineInfluence.ELIGIBLE if record.label == 0 else BaselineInfluence.BLOCKED
        profiler.record_history(
            record.events,
            [record.session],
            influence=influence,
            risk="low" if record.label == 0 else "high",
        )
        past = past_events_by_actor.setdefault(actor, [])
        if record.label == 0:
            past.extend(record.events)
            if len(past) >= _MIN_UNIVERSE_EVENTS and actor not in universes:
                universes[actor] = build_access_universe(past)


def evaluate(
    per_family: int = 6,
    *,
    validator: ARDEValidator | None = None,
    exceptions: ApprovedActivityRegistry | None = None,
) -> dict[str, Any]:
    """Run the complete final-stage evaluation. Returns the report dict."""
    validator = validator or ARDEValidator(exceptions=exceptions)
    bundles = build_instances(per_family=per_family)
    records = run_detector_on_corpus(bundles)
    prepare_feature_records(records)

    # chronological split over sessions (train unused except provenance:
    # the IF for C/D is fitted on label-0 rows of the TRAIN period only)
    split = temporal_split(
        records,
        timestamps=[r.session.end_time_epoch_ms or 0.0 for r in records],
    )

    def _vectors(rs: list[LabeledRecord]) -> list[list[float]]:
        return [
            r.session.session_features["_behavioral_feature_set"]
            .session_features["feature_vector"]
            for r in rs
            if r.session.session_features["_behavioral_feature_set"]
            .session_features.get("feature_vector") is not None
        ]

    model = None
    train_rows = [
        r.session.session_features["_behavioral_feature_set"].session_features["feature_vector"]
        for r in split.train
        if r.label == 0
        and r.session.session_features["_behavioral_feature_set"].session_features.get("feature_vector")
        is not None
    ]
    if len(train_rows) >= 10:
        model = IsolationForest(n_estimators=100, max_samples=64, seed=EVAL_SEED)
        model.fit(train_rows)

    stacks = {
        "A": ScoringStack(variant="A", baseline_version="bl-final-stage"),
        "B": ScoringStack(variant="B", baseline_version="bl-final-stage"),
        "C": ScoringStack(variant="C", anomaly_model=model, baseline_version="bl-final-stage"),
        "D": ScoringStack(variant="D", anomaly_model=model, baseline_version="bl-final-stage"),
        "E": ScoringStack(variant="D", anomaly_model=model, baseline_version="bl-final-stage"),
    }

    test_records = split.test
    scored_by_variant = run_variants(
        test_records,
        stacks,
        validator=validator,
        sessions_by_id={r.session_id: r.session for r in records},
        threshold=0.5,
    )

    variant_results: dict[str, Any] = {}
    for name, scored_list in sorted(scored_by_variant.items()):
        scores = [s.risk_score for s in scored_list]
        labels = [next(r.label for r in test_records if r.session_id == s.session_id) for s in scored_list]
        m = full_metrics(scores, labels, threshold=0.5)
        variant_results[name] = {
            "variant": name,
            "metrics": m,
            "alerts": sum(1 for s in scored_list if s.alert),
        }

    arde_by_session = {
        s.session_id: s.validation_status
        for s in scored_by_variant.get("E", [])
        if s.validation_status is not None
    }
    robustness_by_session = {
        s.session_id: s.robustness_score
        for s in scored_by_variant.get("E", [])
        if s.robustness_score is not None
    }
    errors = analyze_errors(
        test_records,
        {s.session_id: s for s in scored_by_variant.get("D", [])},
        threshold=0.5,
        arde_by_session=arde_by_session,
        robustness_by_session=robustness_by_session,
    )

    # ---- ablation: leave one component out at a time ---------------------
    ablation = _run_ablation_study(
        test_records, stacks["E"], validator=validator,
        baseline_metrics=variant_results["E"]["metrics"],
    )

    # ---- threshold tuning: selected on VALIDATION only, frozen for test --
    tuning = _run_threshold_tuning(records)

    return {
        "synthetic": True,
        "data_source": "final_stage_scenarios_15_families",
        "per_family": per_family,
        "corpus_size": len(records),
        "test_size": len(test_records),
        "split_boundaries": split.boundaries,
        "variants": variant_results,
        "ablation": ablation,
        "arde_interventions": {
            "rejected_alerts": sum(
                1 for s in scored_by_variant.get("E", [])
                if s.validation_status == "REJECTED"
            ),
            "review_required_alerts": sum(
                1 for s in scored_by_variant.get("E", [])
                if s.validation_status == "REVIEW_REQUIRED"
            ),
        },
        "error_analysis": errors.model_dump(),
        "threshold_tuning": tuning,
        "if_fitted": model is not None,
        "seed": EVAL_SEED,
    }


def _run_threshold_tuning(records: list[LabeledRecord]) -> dict[str, Any]:
    """Tune the operating threshold on validation, then freeze for test.

    Uses the full C/D-style stack (anomaly model fitted on benign training
    rows only). The selected threshold is chosen on the validation period;
    the test period is scored once, at both the selected threshold and the
    0.5 default, so the effect is measurable rather than asserted.
    """
    from .tuning import run_threshold_tuning

    stack = ScoringStack(variant="D", baseline_version="bl-final-stage")
    return run_threshold_tuning(records, stack, metric="f1", seed=EVAL_SEED)


def _run_ablation_study(
    test_records: list[LabeledRecord],
    full_stack: ScoringStack,
    *,
    validator: ARDEValidator,
    baseline_metrics: dict[str, Any],
) -> dict[str, Any]:
    """Leave-one-component-out ablation incl. the ARDE component."""
    from .ablation import AblationResult, run_ablation
    from .metrics import full_metrics
    from .variants import run_variants

    def score_fn(_component, stack, records_iter):
        pairs = list(records_iter)
        scores, labels = [], []
        for record, fset in pairs:
            scored = stack.score(fset)
            scores.append(scored.risk_score)
            labels.append(record.label)
        return scores, labels, {}

    results: list[dict[str, Any]] = []
    for result in run_ablation(
        test_records, full_stack,
        score_fn=score_fn,
        baseline_metrics=baseline_metrics,
        components=("volume", "destination", "sensitivity", "access_pattern",
                    "time", "network_egress", "ml"),
    ):
        results.append({
            "component": result.component,
            "metrics": result.metrics,
            "delta_f1": result.delta_f1,
            "delta_recall": result.delta_recall,
            "delta_precision": result.delta_precision,
            "delta_fpr": result.delta_fpr,
            "delta_pr_auc": result.delta_pr_auc,
        })

    # ARDE ablation: E without the validator
    no_arde = run_variants(test_records, {"E-noARDE": full_stack}, validator=None, threshold=0.5)
    scores = [s.risk_score for s in no_arde["E-noARDE"]]
    labels = [next(r.label for r in test_records if r.session_id == s.session_id) for s in no_arde["E-noARDE"]]
    m = full_metrics(scores, labels, threshold=0.5)
    results.append({
        "component": "arde",
        "metrics": m,
        "delta_f1": _r((m["f1"] or 0) - (baseline_metrics.get("f1") or 0)),
        "delta_recall": _r((m["recall"] or 0) - (baseline_metrics.get("recall") or 0)),
        "delta_precision": _r((m["precision"] or 0) - (baseline_metrics.get("precision") or 0)),
        "delta_fpr": _r((m["false_positive_rate"] or 0) - (baseline_metrics.get("false_positive_rate") or 0)),
        "delta_pr_auc": _r(m["pr_auc"] - baseline_metrics.get("pr_auc", 0.0)),
        "note": "E without ARDE; delta shows what the validation layer changes",
    })
    return {"baseline": "E", "components": results}


def write_report(report: dict[str, Any], out_dir: str | Path) -> dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    for name, payload in (
        ("final_metrics.json", {
            "variants": {
                k: v["metrics"] for k, v in report["variants"].items()
            },
            "synthetic": report["synthetic"],
            "data_source": report["data_source"],
            "note": "metrics describe the synthetic 15-family fixture only",
        }),
        ("final_ablation.json", {
            **report.get("ablation", {}),
            "synthetic": report["synthetic"],
            "note": "leave-one-component-out deltas on the synthetic test period",
        }),
        ("final_error_analysis.json", {
            **report["error_analysis"],
            "synthetic": report["synthetic"],
        }),
        ("final_arde_impact.json", {
            **report["arde_interventions"],
            "synthetic": report["synthetic"],
            "variant_E_definition": (
                "full detector: behavior+volume+destination+sensitivity+"
                "access+temporal+network+ML+risk fusion+ARDE"
            ),
        }),
        ("final_threshold_tuning.json", report.get("threshold_tuning", {})),
    ):
        path = out / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        paths[name] = str(path)
    return paths
