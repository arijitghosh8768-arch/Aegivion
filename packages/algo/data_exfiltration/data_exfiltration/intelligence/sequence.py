"""Sequence analysis: statistical deviation of ordered activity.

We track the ordered data-action sequence of each session and compare it
against the actor's historical action n-gram distribution. There are no
attack signatures: a sequence scores high when it uses n-grams rarely
seen in this actor's history, and low when its n-grams are familiar.

Cold start (no history): the score is unavailable, not suspicious.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Sequence

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.schemas import DataActivityEvent, DataAccessSession

_N = 2  # bigrams: good balance of specificity vs sample efficiency


class SequenceResult(BaseModel):
    session_id: str
    access_sequence_score: float | None = None
    availability: str = "unavailable"
    """``observed`` | ``cold_start`` | ``unavailable``."""
    sequence: list[str] = Field(default_factory=list)
    novel_ngrams: list[str] = Field(default_factory=list)
    history_ngram_count: int = 0
    detail: dict[str, Any] = Field(default_factory=dict)


def session_action_sequence(session: DataAccessSession, events: Sequence[DataActivityEvent] | None = None) -> list[str]:
    """Ordered data-action names for a session (event-time sorted).

    Uses the session's stored event ids against the provided event stream;
    when events are not supplied, the session must carry them via
    ``session_features["actions"]`` (profiler pre-assembly).
    """
    if events is not None:
        ordered = sorted(
            (e for e in events if e.event_id in set(session.event_ids)),
            key=lambda e: e.event_time_epoch_ms or 0.0,
        )
        return [e.data_action.value for e in ordered]
    actions = session.session_features.get("actions")
    if isinstance(actions, list):
        return [str(a) for a in actions]
    return []


def _ngrams(sequence: Sequence[str], n: int = _N) -> list[tuple[str, ...]]:
    if len(sequence) < n:
        return [tuple(sequence)] if sequence else []
    return [tuple(sequence[i:i + n]) for i in range(len(sequence) - n + 1)]


def build_ngram_model(sequences: Sequence[Sequence[str]], n: int = _N) -> Counter:
    """Aggregate n-gram counts over historical sequences."""
    model: Counter = Counter()
    for seq in sequences:
        model.update(_ngrams(seq, n))
    return model


def score_sequence(
    sequence: Sequence[str],
    history: Sequence[Sequence[str]],
    n: int = _N,
) -> SequenceResult:
    """Score *sequence* against historical n-gram distribution.

    The score is the share of the sequence's n-grams that were never
    observed historically (0.0 = fully familiar, 1.0 = entirely novel).
    With no history the result is ``cold_start`` with score None — a new
    actor's ordinary ListBucket→GetObject flow is not an anomaly.
    """
    grams = _ngrams(sequence, n)
    if not history:
        return SequenceResult(
            session_id="",
            availability="cold_start",
            sequence=list(sequence),
            detail={"reason": "no historical sequences for this actor"},
        )
    model = build_ngram_model(history, n)
    if not grams:
        return SequenceResult(
            session_id="",
            availability="observed",
            sequence=list(sequence),
            access_sequence_score=0.0,
            history_ngram_count=len(model),
        )
    novel = [g for g in grams if model.get(g, 0) == 0]
    score = len(novel) / len(grams)
    return SequenceResult(
        session_id="",
        access_sequence_score=round(score, 4),
        availability="observed",
        sequence=list(sequence),
        novel_ngrams=["→".join(g) for g in novel],
        history_ngram_count=len(model),
        detail={"n": n, "ngram_total": len(grams), "ngram_novel": len(novel)},
    )
