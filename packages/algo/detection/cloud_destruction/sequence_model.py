"""Sequence modeling — **Part 3**.

Reasons about *event sequences* (MODIFY→MODIFY→DELETE, READ→REWRITE→DELETE,
PROTECTION_CHANGE→DELETE, SNAPSHOT_DELETE→BACKUP_DELETE, VERSION_DELETE→
DELETE, …) without depending on pre-written attack signatures.

Signal families (all deterministic):

- **transition frequency** — how often each category→category transition
  occurs in the session;
- **transition rarity** — how unusual each transition is versus the actor's
  trusted history transition table (Laplace smoothing; unknown
  transitions are novel by definition);
- **sequence length** — long action chains carry more structure;
- **sequence compression** — LZ77-style repetition factor over the
  category alphabet (highly repetitive cleanup loops vs varied
  destructive chains);
- **resource breadth** — distinct targets in the destructive tail;
- **action diversity** — distinct categories in the destructive tail;
- **time between actions** — pacing of the destructive tail.

Output: one ``sequence_anomaly_score`` in ``[0, 1]`` plus the raw
transition tables for audit. The Part 2 *ordering* check
(``analyze_sequences``) remains available; this model adds the
history-relative view. History tables are learned from **trusted**
(LOW-contamination) sessions only — poisoning defense applies here too.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Sequence

from detection.cloud_destruction.baseline import BaselineContamination, classify_contamination
from detection.cloud_destruction.registry import SEQUENCE_MODEL_VERSION
from detection.cloud_destruction.schemas import (
    ActionCategory,
    DESTRUCTIVE_CATEGORIES,
    DestructiveActivitySession,
    ResourceActivityEvent,
)

__all__ = [
    "SequenceTransitionModel",
    "SequenceModelResult",
    "sequence_anomaly_score",
]


def _tail(events: Sequence[ResourceActivityEvent]) -> list[ResourceActivityEvent]:
    """Events from the first destructive event onward (the destructive tail)."""
    for index, event in enumerate(events):
        if event.action_category in DESTRUCTIVE_CATEGORIES:
            return list(events[index:])
    return []


@dataclass
class SequenceModelResult:
    """Deterministic sequence-model output for one session."""

    score: float
    method: str
    contributors: tuple[str, ...] = ("sequence_model",)
    raw: dict[str, object] = field(default_factory=dict)


class SequenceTransitionModel:
    """History-relative sequence model with a learned transition table."""

    def __init__(
        self,
        smoothing: float = 1.0,
        history_limit: int = 500,
        contamination_cfg=None,
    ) -> None:
        self.smoothing = smoothing
        self.history_limit = history_limit
        self._transitions: Counter = Counter()
        self._totals: Counter = Counter()
        self._categories: set[str] = set()
        self._trained_sessions = 0
        self._excluded_sessions = 0

    # ------------------------------------------------------------------ #
    # Learning from trusted history
    # ------------------------------------------------------------------ #

    def observe(
        self,
        session: DestructiveActivitySession,
        events: Sequence[ResourceActivityEvent],
        *,
        contamination: Optional[BaselineContamination] = None,
    ) -> None:
        """Feed one historical session into the transition tables.

        Poisoning defense: HIGH/CRITICAL sessions never contribute.
        """
        level = contamination or classify_contamination(session)
        if level in (BaselineContamination.HIGH, BaselineContamination.CRITICAL):
            self._excluded_sessions += 1
            return
        self._train(list(events))

    def _train(self, events: list[ResourceActivityEvent]) -> None:
        if not events:
            return
        ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
        categories = [e.action_category.value for e in ordered]
        self._categories.update(categories)
        for prev, nxt in zip(categories, categories[1:]):
            self._transitions[(prev, nxt)] += 1
            self._totals[prev] += 1
        self._trained_sessions += 1
        if self._trained_sessions > self.history_limit:
            self._transitions = Counter(dict(self._transitions.most_common(self.history_limit * 20)))
            self._totals = Counter(
                {k: v for k, v in self._totals.items() if k in dict(self._totals)}
            )

    # ------------------------------------------------------------------ #
    # Inference
    # ------------------------------------------------------------------ #

    def _transition_surprise(self, prev: str, nxt: str) -> float:
        """P(nxt | prev) with Laplace smoothing → surprise = 1 - p."""
        total = self._totals.get(prev, 0)
        vocab = max(len(self._categories), 1)
        count = self._transitions.get((prev, nxt), 0)
        probability = (count + self.smoothing) / (total + self.smoothing * vocab)
        return 1.0 - probability

    def score(
        self,
        session: DestructiveActivitySession,
        events: Sequence[ResourceActivityEvent],
    ) -> SequenceModelResult:
        """Score one session's destructive tail against history."""
        ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
        tail = _tail(ordered)
        categories = [e.action_category.value for e in tail]
        raw: dict[str, object] = {
            "tail_length": len(tail),
            "has_model_history": self._trained_sessions > 0,
        }
        if not tail:
            return SequenceModelResult(score=0.0, method="no_destructive_tail", raw=raw)

        # --- transition frequency ------------------------------------------
        freq: Counter = Counter(zip(categories, categories[1:]))
        raw["transition_frequency"] = {f"{a}->{b}": c for (a, b), c in freq.most_common(8)}

        # --- transition rarity vs history -----------------------------------
        if self._trained_sessions > 0:
            surprises = [
                self._transition_surprise(a, b) for a, b in zip(categories, categories[1:])
            ]
            rarity = (sum(surprises) / len(surprises)) if surprises else 0.0
        else:
            rarity = None
        raw["transition_rarity"] = rarity

        # --- sequence length -------------------------------------------------
        length_strength = min(1.0, len(tail) / 25.0)

        # --- sequence compression (repetition factor) --------------------------
        compression = self._repetition_factor(categories)
        raw["compression"] = compression
        # varied (low-compression) chains are more deliberate than loops
        variety_strength = 1.0 - compression

        # --- resource breadth + action diversity -------------------------------
        breadth = {
            e.resource_arn or e.resource_id or e.object_key for e in tail if e.resource_arn or e.resource_id or e.object_key
        }
        breadth_strength = min(1.0, len(breadth) / 10.0)
        diversity = len(set(categories))
        diversity_strength = min(1.0, diversity / 5.0)
        raw.update(
            {
                "unique_tail_resources": len(breadth),
                "action_diversity": diversity,
            }
        )

        # --- time between actions ------------------------------------------------
        gaps = [
            (b.timestamp - a.timestamp).total_seconds()
            for a, b in zip(tail, tail[1:])
        ]
        fast_share = (
            sum(1 for g in gaps if g <= 300.0) / len(gaps) if gaps else 0.0
        )
        raw["fast_transition_share"] = fast_share

        # --- aggregate (documented, configuration-free composition) --------------
        components = [
            0.30 * length_strength,
            0.25 * breadth_strength,
            0.20 * diversity_strength,
            0.15 * fast_share,
            0.10 * variety_strength,
        ]
        if rarity is not None:
            components.append(0.25 * rarity)
            denominator = 1.25
        else:
            denominator = 1.0
        score = max(0.0, min(1.0, sum(components) / denominator))
        raw["weights"] = {
            "length": 0.30,
            "breadth": 0.25,
            "diversity": 0.20,
            "fast_share": 0.15,
            "variety": 0.10,
            "rarity": 0.25 if rarity is not None else 0.0,
        }
        return SequenceModelResult(
            score=score,
            method="transition_structure",
            contributors=("sequence_model",),
            raw=raw,
        )

    @staticmethod
    def _repetition_factor(categories: list[str]) -> float:
        """LZ77-style repetition ratio in ``[0, 1]``: 1 = maximally repetitive.

        Counts greedy back-references: ``1 - literals / tokens`` estimates
        how much of the sequence is repetition.
        """
        if len(categories) < 3:
            return 0.0
        literals = 0
        i = 0
        while i < len(categories):
            best_len = 0
            for offset in range(1, min(i, 24) + 1):
                length = 0
                while (
                    i + length < len(categories)
                    and length < offset
                    and categories[i + length] == categories[i - offset + length]
                ):
                    length += 1
                if length > best_len:
                    best_len = length
            if best_len >= 2:
                i += best_len  # back-reference consumes a repeated run
            else:
                literals += 1
                i += 1
        repetition = 1.0 - (literals / max(1, len(categories)))
        return min(1.0, max(0.0, repetition))

    def descriptor(self) -> dict[str, object]:
        return {
            "model_name": "sequence_transition_model",
            "model_version": SEQUENCE_MODEL_VERSION,
            "trained_sessions": self._trained_sessions,
            "excluded_sessions": self._excluded_sessions,
            "known_categories": len(self._categories),
            "known_transitions": len(self._transitions),
        }


def sequence_anomaly_score(
    model: SequenceTransitionModel,
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> SequenceModelResult:
    """Convenience entry point: score one session's sequence structure."""
    return model.score(session, events)
