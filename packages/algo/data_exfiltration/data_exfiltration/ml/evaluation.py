"""Comparative evaluation framework: A vs B vs C vs D.

Variants:
  A: rules only
  B: rules + baseline fusion
  C: rules + baseline fusion + Isolation Forest
  D: full model (C + gated supervised component)

Nothing is assumed: each variant is measured on the SAME test period
with precision, recall, F1, PR-AUC, FPR, detection latency proxies, and
calibration metrics. Synthetic evaluation data stays marked synthetic in
every artifact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import BehavioralFeatureSet
from algo.data_exfiltration.data_exfiltration.ml.pipeline import VARIANT_COMPONENTS, ScoringStack, ScoredSession
from algo.data_exfiltration.data_exfiltration.ml.replay import replay_sessions
from algo.data_exfiltration.data_exfiltration.ml.versioning import MODEL_NAME, MODEL_VERSION, SCORING_VERSION


@dataclass
class EvaluationDataset:
    """Feature sets with ground truth, explicitly marked synthetic or not."""

    features: list[BehavioralFeatureSet]
    labels: list[int]
    synthetic: bool = True
    source: str = "synthetic_scenarios"

    def __post_init__(self) -> None:
        if len(self.features) != len(self.labels):
            raise ValueError("features and labels must align")


@dataclass
class VariantResult:
    variant: str
    scored: list[ScoredSession]
    metrics: dict[str, Any] = field(default_factory=dict)


# ----------------------------------------------------------------------
# metrics
# ----------------------------------------------------------------------


def classification_metrics(
    scores: Sequence[float],
    labels: Sequence[int],
    threshold: float = 0.5,
) -> dict[str, float | int | None]:
    if len(scores) != len(labels) or not scores:
        raise ValueError("scores/labels must align and be non-empty")
    tp = fp = tn = fn = 0
    for s, y in zip(scores, labels):
        pred = 1 if s >= threshold else 0
        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 0:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "threshold": threshold,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": _r(precision),
        "recall": _r(recall),
        "f1": _r(f1),
        "false_positive_rate": _r(fpr),
    }


def pr_auc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Area under the precision-recall curve (step interpolation)."""
    pairs = sorted(zip(scores, labels), key=lambda p: -p[0])
    total_pos = sum(labels)
    if total_pos == 0:
        return 0.0
    tp = fp = 0
    area = 0.0
    prev_recall = 0.0
    for _s, y in pairs:
        if y == 1:
            tp += 1
        else:
            fp += 1
        recall = tp / total_pos
        precision = tp / (tp + fp)
        area += precision * (recall - prev_recall)
        prev_recall = recall
    return _r(area)


def roc_curve(scores: Sequence[float], labels: Sequence[int]) -> list[dict[str, float]]:
    """ROC points (FPR, TPR) across all thresholds."""
    total_pos = sum(1 for y in labels if y == 1)
    total_neg = len(labels) - total_pos
    pairs = sorted(zip(scores, labels), key=lambda p: -p[0])
    points: list[dict[str, float]] = [{"fpr": 0.0, "tpr": 0.0}]
    tp = fp = 0
    seen: set[float] = set()
    for s, y in pairs:
        if y == 1:
            tp += 1
        else:
            fp += 1
        if s in seen:
            continue
        seen.add(s)
        points.append({
            "fpr": _r(fp / total_neg) if total_neg else 0.0,
            "tpr": _r(tp / total_pos) if total_pos else 0.0,
            "threshold": _r(s),
        })
    points.append({"fpr": 1.0, "tpr": 1.0})
    return points


def _r(value: float | None) -> float | None:
    return round(value, 6) if value is not None else None


# ----------------------------------------------------------------------
# harness
# ----------------------------------------------------------------------


class EvaluationHarness:
    """Runs variants A-D over one temporally split dataset."""

    def __init__(
        self,
        stacks: dict[str, ScoringStack],
        *,
        positive_threshold: float = 0.5,
        latency_field: str | None = None,
    ) -> None:
        if not stacks:
            raise ValueError("at least one scoring stack is required")
        self._stacks = stacks
        self._threshold = positive_threshold
        self._latency_field = latency_field

    def run(
        self,
        dataset: EvaluationDataset,
        *,
        proportions: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        labels = dataset.labels
        split_by_variant: dict[str, list[ScoredSession]] = {}
        boundaries: dict[str, Any] | None = None

        for name, stack in sorted(self._stacks.items()):
            replay = replay_sessions(
                dataset.features,
                stack,
                proportions=proportions,
                fit_on_train=(name in ("C", "D")),
            )
            split_by_variant[name] = replay["scored"]
            boundaries = replay["split"].boundaries

        results: dict[str, Any] = {}
        scored_store: dict[str, list[ScoredSession]] = {}
        for name in sorted(self._stacks):
            scored = split_by_variant[name]
            scored_store[name] = scored
            # align labels with scored sessions (test period only)
            id_to_label = {
                f.session_id: y
                for f, y in zip(dataset.features, labels)
            }
            y_true = [id_to_label[s.session_id] for s in scored]
            y_score = [s.risk_score for s in scored]

            metrics = classification_metrics(y_score, y_true, threshold=self._threshold)
            metrics["pr_auc"] = pr_auc(y_score, y_true)
            metrics["roc_auc"] = _roc_auc(
                [s.risk_score for s in scored],
                y_true,
            )
            if self._latency_field:
                latencies = [
                    getattr(s, self._latency_field)
                    for s in scored
                    if getattr(s, self._latency_field, None) is not None
                ]
                if latencies:
                    metrics["detection_latency_mean"] = _r(sum(latencies) / len(latencies))

            results[name] = {
                "variant": name,
                "components": VARIANT_COMPONENTS.get(name, []),
                "metrics": metrics,
                "model": {
                    "model_name": MODEL_NAME,
                    "model_version": MODEL_VERSION,
                    "scoring_version": SCORING_VERSION,
                },
            }

        return {
            "variants": results,
            "scored_by_variant": scored_store,
            "_id_to_label": {f.session_id: y for f, y in zip(dataset.features, labels)},
            "split_boundaries": boundaries,
            "synthetic": dataset.synthetic,
            "data_source": dataset.source,
            "positive_threshold": self._threshold,
            "test_session_count": len(next(iter(split_by_variant.values()))) if split_by_variant else 0,
        }

    # ------------------------------------------------------------------
    # artifacts
    # ------------------------------------------------------------------

    def write_artifacts(self, report: dict[str, Any], out_dir) -> dict[str, str]:
        from pathlib import Path

        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths: dict[str, str] = {}

        # metrics.json: headline comparison
        metrics = {
            name: res["metrics"] for name, res in report["variants"].items()
        }
        paths["metrics.json"] = _write(out / "metrics.json", {
            "variants": metrics,
            "split_boundaries": report["split_boundaries"],
            "synthetic": report["synthetic"],
            "data_source": report["data_source"],
        })

        # precision_recall.json: full threshold sweep per variant
        precision_recall: dict[str, Any] = {}
        roc_data: dict[str, Any] = {}
        for name, scored in report.get("scored_by_variant", {}).items():
            id_to_label = report["_id_to_label"]
            y_true = [id_to_label[s.session_id] for s in scored]
            y_score = [s.risk_score for s in scored]
            precision_recall[name] = {
                "note": "threshold sweep over test-period risk scores",
                "sweep": _threshold_sweep(y_score, y_true),
                "pr_auc": pr_auc(y_score, y_true),
            }
            roc_data[name] = {
                "points": roc_curve(y_score, y_true),
                "roc_auc": _roc_auc(y_score, y_true),
            }
        paths["precision_recall.json"] = _write(out / "precision_recall.json", precision_recall)
        paths["roc_data.json"] = _write(out / "roc_data.json", roc_data)

        # ablation_base.json: what each layer added
        base = report["variants"].get("A", {}).get("metrics", {})
        ablation = {}
        for name, res in report["variants"].items():
            m = res["metrics"]
            ablation[name] = {
                "components": res["components"],
                "delta_f1_vs_A": _r((m["f1"] or 0) - (base.get("f1") or 0)),
                "delta_precision_vs_A": _r((m["precision"] or 0) - (base.get("precision") or 0)),
                "delta_recall_vs_A": _r((m["recall"] or 0) - (base.get("recall") or 0)),
                "delta_fpr_vs_A": _r((m["false_positive_rate"] or 0) - (base.get("false_positive_rate") or 0)),
                "delta_pr_auc_vs_A": _r(m["pr_auc"] - base.get("pr_auc", 0.0)),
            }
        paths["ablation_base.json"] = _write(out / "ablation_base.json", {
            "baseline_variant": "A",
            "ablation": ablation,
        })

        return paths

    def write_calibration_artifact(
        self,
        dataset: EvaluationDataset,
        stack: ScoringStack,
        out_dir,
        *,
        n_bins: int = 10,
    ) -> str:
        """calibration.json: reliability curve + Brier + ECE for one variant."""
        from algo.data_exfiltration.data_exfiltration.ml.confidence_engine import (
            brier_score,
            expected_calibration_error,
        )
        from algo.data_exfiltration.data_exfiltration.ml.replay import temporal_split

        out = Path(out_dir)
        split = temporal_split(list(dataset.features), proportions=None)
        id_to_label = {f.session_id: y for f, y in zip(dataset.features, dataset.labels)}

        scored = [stack.score(f) for f in split.test]
        y_true = [id_to_label[s.session_id] for s in scored]
        probabilities = [s.risk_score for s in scored]

        bins = []
        for b in range(n_bins):
            lo, hi = b / n_bins, (b + 1) / n_bins
            idx = [
                i for i in range(len(probabilities))
                if lo <= probabilities[i] < hi or (b == n_bins - 1 and probabilities[i] == hi)
            ]
            bins.append({
                "bin": b,
                "lower": lo,
                "upper": hi,
                "count": len(idx),
                "mean_predicted": _r(sum(probabilities[i] for i in idx) / len(idx)) if idx else None,
                "fraction_positive": _r(sum(y_true[i] for i in idx) / len(idx)) if idx else None,
            })

        payload = {
            "variant": stack.variant,
            "brier_score": brier_score(probabilities, y_true),
            "expected_calibration_error": expected_calibration_error(probabilities, y_true),
            "bins": bins,
            "note": (
                "risk_score treated as probability ONLY for measurement; "
                "findings keep risk and confidence separate"
            ),
            "synthetic": dataset.synthetic,
        }
        (out / "calibration.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return str(out / "calibration.json")


def _threshold_sweep(
    scores: Sequence[float], labels: Sequence[int], steps: int = 21
) -> list[dict[str, Any]]:
    sweep = []
    for i in range(steps):
        threshold = i / (steps - 1)
        m = classification_metrics(scores, labels, threshold=threshold)
        sweep.append({
            "threshold": _r(threshold),
            "precision": m["precision"],
            "recall": m["recall"],
            "fpr": m["false_positive_rate"],
        })
    return sweep


def _roc_auc(scores: Sequence[float], labels: Sequence[int]) -> float | None:
    points = roc_curve(scores, labels)
    area = 0.0
    for i in range(1, len(points)):
        width = points[i]["fpr"] - points[i - 1]["fpr"]
        height = (points[i]["tpr"] + points[i - 1]["tpr"]) / 2.0
        area += width * height
    return _r(area)


def _write(path, payload: dict[str, Any]) -> str:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return str(path)
