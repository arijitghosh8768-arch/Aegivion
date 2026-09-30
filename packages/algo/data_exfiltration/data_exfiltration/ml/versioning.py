"""Model versioning: every finding carries the full model identity."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field

SCORING_VERSION = "scoring-3.0.0"
MODEL_NAME = "aegivion.data_exfiltration"
MODEL_VERSION = "3.0.0"
RULE_VERSION = "data-exfil-rules-3.0.0"
"""Version of the transparent rule policy in ``ml/rules.py``. Rules are
inspectable and change on their own schedule, so they carry their own
identity separate from the model/scoring versions."""


class ModelVersionInfo(BaseModel):
    """Version identity of the scoring stack that produced a finding."""

    model_name: str = MODEL_NAME
    model_version: str = MODEL_VERSION
    feature_version: str
    baseline_version: str | None = None
    scoring_version: str = SCORING_VERSION
    rule_version: str = RULE_VERSION
    variant: str | None = None
    """A | B | C | D when produced by the evaluation harness."""
    extra: dict[str, Any] = Field(default_factory=dict)

    def as_metadata(self) -> dict[str, Any]:
        return self.model_dump()
