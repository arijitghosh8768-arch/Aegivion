"""Sensitivity intelligence: multi-source, criticality-separated.

Sensitivity can come from Macie, Aegivion classification, resource tags,
business metadata, or manual classification. Two axes are kept strictly
separate:

- ``data_sensitivity``     — how sensitive the DATA is (Macie, tags)
- ``business_criticality`` — how critical the SYSTEM is (asset registry)

External Macie findings are never silently equated with business
criticality; conflating the two requires an explicit mapping supplied by
the organization.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.measurement import (
    MeasurementConfidence,
    MeasurementSource,
    SourceMeasurement,
)
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession, SensitivityLevel

_LEVEL_TO_SCORE = {
    SensitivityLevel.NONE: 0.0,
    SensitivityLevel.PUBLIC: 0.1,
    SensitivityLevel.INTERNAL: 0.3,
    SensitivityLevel.CONFIDENTIAL: 0.55,
    SensitivityLevel.RESTRICTED: 0.75,
    SensitivityLevel.CRITICAL: 0.95,
    SensitivityLevel.PII: 0.7,
    SensitivityLevel.PHI: 0.85,
    SensitivityLevel.FINANCIAL: 0.8,
    SensitivityLevel.SECRETS: 1.0,
}


class SensitivityAssessment(BaseModel):
    session_id: str
    sensitivity_score: float | None = None
    """Max data-sensitivity across touched resources (0..1)."""
    sensitivity_source: str | None = None
    sensitivity_confidence: str | None = None
    business_criticality: float | None = None
    """From the asset registry; NOT derived from Macie."""
    availability: str = "unavailable"
    detail: dict[str, Any] = Field(default_factory=dict)


def _score_for_level(level: SensitivityLevel | None) -> float | None:
    return _LEVEL_TO_SCORE.get(level)


def sensitivity_signals(
    session: DataAccessSession,
    *,
    resource_sensitivity: dict[str, tuple[SensitivityLevel, str, str]] | None = None,
    resource_criticality: dict[str, float] | None = None,
) -> SensitivityAssessment:
    """Assess sensitivity from session enrichment + supplied registries.

    ``resource_sensitivity``: resource_id -> (level, source, confidence).
    ``resource_criticality``: resource_id -> 0..1 business criticality
    from the asset registry (tags/business metadata), never from Macie.
    """
    assessment = SensitivityAssessment(session_id=session.session_id)

    contributions: list[tuple[float, str, str, str]] = []
    # 1) session-carried enrichment (e.g. Macie applied during normalization)
    summary = session.sensitivity_summary
    if summary is not None and summary.measurement is not None:
        for m in summary.measurement.measurements:
            contributions.append((m.value, m.source.value, m.confidence.value, "session_enrichment"))

    # 2) resource registries (tags, Aegivion classification, manual)
    if resource_sensitivity:
        for resource_id in session.resources_accessed:
            entry = resource_sensitivity.get(resource_id)
            if entry is None:
                continue
            level, source, confidence = entry
            score = _score_for_level(level)
            if score is not None:
                contributions.append((score, source, confidence, f"registry:{resource_id}"))

    if contributions:
        top = max(contributions, key=lambda c: c[0])
        assessment.sensitivity_score = round(top[0], 4)
        assessment.sensitivity_source = top[1]
        assessment.sensitivity_confidence = top[2]
        assessment.availability = "observed"
        assessment.detail["contributions"] = [
            {"score": c[0], "source": c[1], "confidence": c[2], "origin": c[3]}
            for c in sorted(contributions, key=lambda c: c[0], reverse=True)
        ]
    else:
        assessment.availability = "unavailable"
        assessment.detail["reason"] = "no sensitivity enrichment or registry entry for touched resources"

    if resource_criticality:
        criticalities = [
            resource_criticality[r] for r in session.resources_accessed if r in resource_criticality
        ]
        if criticalities:
            assessment.business_criticality = round(max(criticalities), 4)
            assessment.detail["criticality_source"] = "asset_registry"

    return assessment
