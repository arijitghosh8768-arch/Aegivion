"""Model / version registry for the Cloud Destructive Activity Detector.

Every detection artifact must be reproducible and auditable: findings record
*which* feature extractor, baseline, anomaly model, scoring configuration
and rule pack produced them. This module defines those version stamps.

- ``FEATURE_VERSION``, ``RULE_VERSION``, ``SCORING_VERSION``: module-level
  constants bumped deliberately when their semantics change.
- :class:`ModelDescriptor` / :class:`ModelRegistry`: descriptors for
  trained models (Isolation Forest, optional supervised model) with content
  digests so "same events + same versions + same config ⇒ same result".

Nothing here computes risk or confidence — this is bookkeeping only.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

#: Version of the behavioral feature vector (Part 2 feature contract).
#: Bump when feature semantics change (fields added/removed/renamed/reweighted).
FEATURE_VERSION = "2.0.0"

#: Version of the sequence model (transition features + rarity tables).
SEQUENCE_MODEL_VERSION = "1.0.0"

#: Version of the temporal feature engine (window grid + metrics).
TEMPORAL_MODEL_VERSION = "1.0.0"

#: Version of the deterministic rule signals consumed by fusion.
RULE_VERSION = "2.0.0"

#: Version of the risk-fusion configuration (weights + policy).
SCORING_VERSION = "1.0.0"

#: Version of the confidence model.
CONFIDENCE_VERSION = "1.0.0"

#: Version of the severity policy.
SEVERITY_VERSION = "1.0.0"

#: Version of the response playbook (Part 4 severity -> actions mapping).
RESPONSE_VERSION = "1.0.0"

#: Version of the ARDE validation layer (Part 6, ten checks).
ARDE_VERSION = "1.0.0"

#: Version of the false-positive context / exception vocabulary (Part 6).
CONTEXT_VERSION = "1.0.0"

#: Version of the destructive-behavior categorization (Part 6).
CATEGORIZATION_VERSION = "1.0.0"

#: Version of the machine-readable explanation schema (Part 6).
EXPLANATION_VERSION = "1.0.0"

#: Version of the audit-log format (Part 6).
AUDIT_VERSION = "1.0.0"


@dataclass(frozen=True)
class ModelDescriptor:
    """Description of one trained model (or rule/statistical component)."""

    model_name: str
    model_version: str
    component: str
    """Logical component: ``anomaly``, ``supervised``, ``fusion``, ..."""
    trained_at_epoch_ms: Optional[float] = None
    params_digest: Optional[str] = None
    """SHA-256 digest of the model hyperparameters/settings."""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "component": self.component,
            "trained_at_epoch_ms": self.trained_at_epoch_ms,
            "params_digest": self.params_digest,
            "extra": dict(self.extra),
        }


def content_digest(payload: Any) -> str:
    """Stable SHA-256 digest of JSON-serializable content (for audit stamps)."""
    if isinstance(payload, bytes):
        raw = payload
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        import json

        raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class ModelRegistry:
    """In-memory registry of model descriptors used by a detector run.

    The registry is the single place findings look up version stamps, and
    the replay engine compares descriptors to guarantee determinism.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelDescriptor] = {}

    def register(self, descriptor: ModelDescriptor) -> None:
        key = f"{descriptor.component}:{descriptor.model_name}"
        self._models[key] = descriptor

    def get(self, component: str, model_name: str) -> Optional[ModelDescriptor]:
        return self._models.get(f"{component}:{model_name}")

    def descriptors(self) -> list[ModelDescriptor]:
        return list(self._models.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_version": FEATURE_VERSION,
            "sequence_model_version": SEQUENCE_MODEL_VERSION,
            "temporal_model_version": TEMPORAL_MODEL_VERSION,
            "rule_version": RULE_VERSION,
            "scoring_version": SCORING_VERSION,
            "confidence_version": CONFIDENCE_VERSION,
            "severity_version": SEVERITY_VERSION,
            "models": sorted(self._models),
            "models_detail": [self._models[k].to_dict() for k in sorted(self._models)],
        }

    def descriptors_digest(self) -> str:
        return content_digest(self.to_dict())


__all__ = [
    "ARDE_VERSION",
    "AUDIT_VERSION",
    "CATEGORIZATION_VERSION",
    "CONFIDENCE_VERSION",
    "CONTEXT_VERSION",
    "EXPLANATION_VERSION",
    "FEATURE_VERSION",
    "ModelDescriptor",
    "ModelRegistry",
    "RESPONSE_VERSION",
    "RULE_VERSION",
    "SCORING_VERSION",
    "SEQUENCE_MODEL_VERSION",
    "SEVERITY_VERSION",
    "TEMPORAL_MODEL_VERSION",
    "content_digest",
]
