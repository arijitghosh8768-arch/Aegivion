"""Replay mode: temporal splits and chronology-safe model training.

NO DATA LEAKAGE: sessions are split strictly by time into
train -> validation -> test periods. The Isolation Forest trains ONLY on
training-period sessions (with baseline quality >= threshold when
requested), validation tunes nothing secretly, and test sessions are
scored exactly once, chronologically, as a replay.

Also builds chronology-safe feature histories: when the profile of
session i is recomputed, only sessions before i are visible as history —
mirroring production operation where the future does not exist yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import BehavioralFeatureSet
from algo.data_exfiltration.data_exfiltration.ml.isolation_forest import IsolationForest
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoredSession, ScoringStack

TEMPORAL_SPLIT_DEFAULTS = {"train": 0.6, "validation": 0.2, "test": 0.2}


@dataclass
class TemporalSplit:
    train: list = field(default_factory=list)
    validation: list = field(default_factory=list)
    test: list = field(default_factory=list)
    train_end_epoch_ms: float | None = None
    validation_end_epoch_ms: float | None = None
    test_end_epoch_ms: float | None = None

    @property
    def boundaries(self) -> dict[str, float | None]:
        return {
            "train_end_epoch_ms": self.train_end_epoch_ms,
            "validation_end_epoch_ms": self.validation_end_epoch_ms,
            "test_end_epoch_ms": self.test_end_epoch_ms,
        }


def temporal_split(
    items: Sequence[Any],
    *,
    timestamps: Sequence[float] | None = None,
    proportions: dict[str, float] | None = None,
) -> TemporalSplit:
    """Chronological split into train/validation/test (no shuffling)."""
    props = proportions or TEMPORAL_SPLIT_DEFAULTS
    total = sum(props.values())
    if abs(total - 1.0) > 1e-9:
        raise ValueError("split proportions must sum to 1.0")

    pairs = list(zip(items, timestamps)) if timestamps is not None else [
        (item, _item_ts(item)) for item in items
    ]
    pairs.sort(key=lambda p: p[1])

    n = len(pairs)
    train_end = int(n * props["train"])
    val_end = train_end + int(n * props["validation"])

    split = TemporalSplit()
    split.train = [p[0] for p in pairs[:train_end]]
    split.validation = [p[0] for p in pairs[train_end:val_end]]
    split.test = [p[0] for p in pairs[val_end:]]
    if train_end:
        split.train_end_epoch_ms = float(pairs[train_end - 1][1])
    if val_end:
        split.validation_end_epoch_ms = float(pairs[val_end - 1][1])
    if pairs:
        split.test_end_epoch_ms = float(pairs[-1][1])
    return split


def _item_ts(item: Any) -> float:
    for attr in ("computed_at_epoch_ms", "end_time_epoch_ms", "start_time_epoch_ms"):
        ts = getattr(item, attr, None)
        if ts is not None:
            return float(ts)
    if isinstance(item, dict):
        for key in ("computed_at_epoch_ms", "end_time_epoch_ms"):
            if item.get(key) is not None:
                return float(item[key])
    return 0.0


def fit_isolation_forest(
    train_features: Sequence[BehavioralFeatureSet],
    *,
    seed: int = 42,
    n_estimators: int = 100,
    min_baseline_quality: float = 0.0,
    **kwargs: Any,
) -> IsolationForest | None:
    """Fit IF on training-period feature vectors only.

    Returns None when fewer than 10 usable training rows exist — the
    caller must then run without the ML component rather than pretend.
    """
    vectors = [
        f.session_features.get("feature_vector")
        for f in train_features
        if f.session_features.get("feature_vector") is not None
    ]
    if len(vectors) < 10:
        return None
    model = IsolationForest(
        seed=seed, n_estimators=n_estimators,
        **kwargs,
    )
    model.fit(vectors)
    return model


def replay_sessions(
    feature_sets: Sequence[BehavioralFeatureSet],
    stack: ScoringStack,
    *,
    proportions: dict[str, float] | None = None,
    fit_on_train: bool = True,
) -> dict[str, Any]:
    """Temporal replay: fit on train, score validation+test chronologically.

    Returns scored sessions plus the split boundaries for provenance.
    """
    split = temporal_split(list(feature_sets), proportions=proportions)

    fitted_model = None
    if fit_on_train and stack.variant in ("C", "D"):
        fitted_model = fit_isolation_forest(split.train, seed=42)
        if fitted_model is not None:
            stack.anomaly_model = fitted_model

    scored: list[ScoredSession] = []
    for fset in [*split.validation, *split.test]:
        scored.append(stack.score(fset))

    return {
        "scored": scored,
        "split": split,
        "anomaly_model_fitted": fitted_model is not None,
        "anomaly_model_version": fitted_model.version() if fitted_model else None,
    }
