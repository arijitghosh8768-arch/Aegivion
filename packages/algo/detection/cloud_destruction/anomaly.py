"""Unsupervised anomaly scoring — **Part 3** (Isolation Forest, no ML deps).

Why Isolation Forest first: real destruction labels are rare, so
unsupervised isolation of *unusual feature combinations* is the right
first model. Implementation is a faithful, dependency-free, pure-python
iForest:

- random feature + random split-point trees (standard ``sqrt(d)`` feature
  subspace per node, as in the original algorithm, with seeding for
  determinism);
- path-length scoring against the average successful-search path
  ``c(n)`` — the standard iForest score ``s = 2^(-E[h]/c(n))`` reads
  "higher = more anomalous" (short isolation paths → s → 1).

Rules honored:

- Deterministic: fixed seed → same forest → same scores (replay-safe).
- Never invents evidence: a missing feature value is recorded and the
  neutral default is used, with availability surfaced alongside the score.
- No verdicts by itself: ``anomaly_score`` is one fusion input, not a risk.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Optional, Sequence

from detection.cloud_destruction.registry import ModelDescriptor, content_digest

__all__ = ["IsolationForestModel", "IsolationForestResult"]


def _c(n: float) -> float:
    """Average path length of unsuccessful BST search (Harmonic numbers)."""
    if n <= 1:
        return 0.0
    return 2.0 * (math.log(n - 1.0) + 0.5772156649) - 2.0 * (n - 1.0) / n


@dataclass
class _Node:
    feature_index: int = -1
    split_value: float = 0.0
    size: int = 0
    depth: int = 0
    left: Optional["_Node"] = None
    right: Optional["_Node"] = None


class _Tree:
    def __init__(self, rows: list[list[float]], depth_limit: int, rng: random.Random) -> None:
        self.root = self._build(rows, 0, depth_limit, rng)

    def _build(self, rows: list[list[float]], depth: int, depth_limit: int, rng: random.Random) -> _Node:
        node = _Node(size=len(rows), depth=depth)
        if depth >= depth_limit or len(rows) <= 1:
            return node
        # distinct values per feature within this subspace
        n_features = len(rows[0])
        candidates = [
            j for j in range(n_features) if len({row[j] for row in rows}) > 1
        ]
        if not candidates:
            return node
        feature_index = rng.choice(candidates)
        values = [row[feature_index] for row in rows]
        low, high = min(values), max(values)
        split = rng.uniform(low, high)
        left_rows = [r for r in rows if r[feature_index] < split]
        right_rows = [r for r in rows if r[feature_index] >= split]
        # numeric guard against float-degenerate splits
        if not left_rows or not right_rows:
            return node
        node.feature_index = feature_index
        node.split_value = split
        node.left = self._build(left_rows, depth + 1, depth_limit, rng)
        node.right = self._build(right_rows, depth + 1, depth_limit, rng)
        node.size = len(rows)
        return node

    def path_length(self, row: Sequence[float]) -> float:
        node = self.root
        depth = 0
        while node.feature_index >= 0:
            if row[node.feature_index] < node.split_value:
                node = node.left
            else:
                node = node.right
            depth += 1
            if node is None:  # defensive; splits always route into a child
                break
        if node is None:
            return float(depth)
        # add c(size) adjustment when stopping at an external node
        return depth + _c(node.size)


class IsolationForestModel:
    """Deterministic Isolation Forest over the versioned feature vector."""

    def __init__(
        self,
        n_trees: int = 100,
        sample_size: int = 256,
        seed: int = 1337,
    ) -> None:
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.seed = seed
        self._trees: Optional[list[_Tree]] = None
        self._n_features = 0

    # ------------------------------------------------------------------ #
    # Training
    # ------------------------------------------------------------------ #

    def fit(self, rows: Sequence[Sequence[float]]) -> "IsolationForestModel":
        if not rows:
            raise ValueError("IsolationForestModel.fit requires at least one row")
        self._n_features = len(rows[0])
        n = len(rows)
        rng = random.Random(self.seed)
        sample = min(self.sample_size, n)
        depth_limit = math.ceil(math.log2(max(sample, 2)))
        trees: list[_Tree] = []
        for _ in range(self.n_trees):
            if n > sample:
                subset = rng.sample(list(rows), sample)
            else:
                subset = list(rows)
            trees.append(_Tree(subset, depth_limit, rng))
        self._trees = trees
        return self

    @property
    def is_fitted(self) -> bool:
        return self._trees is not None

    def descriptor(self) -> ModelDescriptor:
        params = {
            "n_trees": self.n_trees,
            "sample_size": self.sample_size,
            "seed": self.seed,
        }
        return ModelDescriptor(
            model_name="isolation_forest",
            model_version="1.0.0",
            component="anomaly",
            params_digest=content_digest(params),
            extra=params,
        )

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #

    def score_row(self, row: Sequence[float]) -> float:
        """Isolation score for one row, in ``[0, 1]``, higher = more anomalous."""
        if not self.is_fitted or not self._trees:
            raise RuntimeError("model is not fitted")
        if len(row) != self._n_features:
            raise ValueError(
                f"feature mismatch: expected {self._n_features}, got {len(row)}"
            )
        total = 0.0
        for tree in self._trees:
            total += tree.path_length(row)
        mean_path = total / len(self._trees)
        n = float(self.sample_size)
        denom = _c(n)
        if denom <= 0:
            return 0.0
        # Standard iForest score s = 2^(-E[h]/c(n)): anomalies isolate fast
        # (short paths → s → 1), normal points need long paths (s → 0).
        # So the standard score already reads "higher = more anomalous".
        score = 2.0 ** (-mean_path / denom)
        return max(0.0, min(1.0, score))

    def score_many(self, rows: Sequence[Sequence[float]]) -> list[float]:
        return [self.score_row(row) for row in rows]


class IsolationForestResult:
    """Score + availability provenance for one session's anomaly value."""

    def __init__(self, session_id: str, score: float, missing_features: Sequence[str]) -> None:
        self.session_id = session_id
        self.score = score
        self.missing_features = tuple(missing_features)

    @property
    def confidence(self) -> float:
        """Evidence-coverage heuristic: share of features actually present."""
        from detection.cloud_destruction.feature_vector import FEATURE_ORDER

        if not self.missing_features:
            return 1.0
        coverage = 1.0 - (len(self.missing_features) / len(FEATURE_ORDER))
        return max(0.0, coverage)
