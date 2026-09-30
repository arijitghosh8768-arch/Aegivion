"""Model registry & versioning - **Part 2**.

Every ML-assisted finding records *which* model, feature schema, baseline,
rule catalogue and scoring configuration produced it. Without these stamps a
detection result cannot be reproduced or audited, which for a security tool
means it cannot be trusted.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from algo.detection.credential_compromise.anomaly import FEATURE_VERSION
from algo.detection.credential_compromise.rules import RULE_CATALOGUE

#: Version of the rule catalogue semantics (ids + severity defaults).
RULE_VERSION = "rules-r001-r014-v1"
#: Version of the scoring/fusion semantics.
SCORING_VERSION = "fusion-v2-2026.09"
MODEL_NAME = "isolation_forest"
MODEL_VERSION = "if-pure-py-v1"


class ModelCard(BaseModel):
    """Declarative description of a trained model artifact."""

    model_config = ConfigDict(frozen=True)

    model_name: str
    model_version: str
    feature_version: str
    trained_at: Optional[str] = None
    training_rows: int = 0
    synthetic_labels: bool = False
    label_source: str = "unlabeled"
    notes: str = ""


class ComponentVersions(BaseModel):
    """The version stamps attached to every finding."""

    model_config = ConfigDict(frozen=True)

    model_name: str = MODEL_NAME
    model_version: str = MODEL_VERSION
    feature_version: str = FEATURE_VERSION
    baseline_version: int = 0
    rule_version: str = RULE_VERSION
    scoring_version: str = SCORING_VERSION

    def to_dict(self) -> dict[str, object]:
        return self.model_dump()


def rule_fingerprint() -> str:
    """Stable fingerprint of the active rule catalogue (ids + severities)."""
    payload = ";".join(f"{rule.rule_id}:{rule.severity.value}" for rule in RULE_CATALOGUE)
    return payload


def model_card_for(
    *,
    training_rows: int,
    synthetic_labels: bool = False,
    label_source: str = "unlabeled",
    notes: str = "",
) -> ModelCard:
    return ModelCard(
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        feature_version=FEATURE_VERSION,
        training_rows=training_rows,
        synthetic_labels=synthetic_labels,
        label_source=label_source,
        notes=notes,
    )


__all__ = [
    "ComponentVersions",
    "MODEL_NAME",
    "MODEL_VERSION",
    "ModelCard",
    "RULE_VERSION",
    "SCORING_VERSION",
    "model_card_for",
    "rule_fingerprint",
]
