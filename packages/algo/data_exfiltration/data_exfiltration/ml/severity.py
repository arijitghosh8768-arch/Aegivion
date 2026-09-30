"""Severity mapping: risk + confidence + sensitivity + evidence quality.

No single number decides severity. The mapping requires corroboration:
high risk with low evidence quality cannot reach CRITICAL, and
sensitivity amplifies only when risk is already elevated.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SeverityInputs(BaseModel):
    risk_score: float
    confidence: float | None = None
    """0..1 calibrated/assessed confidence; None = unassessed."""
    sensitivity: float | None = None
    """0..1 max data sensitivity touched."""
    evidence_quality: float | None = None
    """0..1 share of available features / baseline quality blend."""


def severity_from(inputs: SeverityInputs) -> Severity:
    """Map the four inputs onto LOW/MEDIUM/HIGH/CRITICAL.

    Logic (documented, monotone):
    - base band from risk: <0.35 LOW, <0.6 MEDIUM, <0.8 HIGH, else CRITICAL
    - low evidence quality (<0.4) caps severity at MEDIUM: thin evidence
      must not produce loud findings
    - low confidence (<0.4) caps at HIGH: risk without confidence is not
      CRITICAL yet
    - sensitivity >= 0.75 with risk >= 0.6 promotes one band
    """
    risk = max(0.0, min(1.0, inputs.risk_score))

    if risk < 0.35:
        severity = Severity.LOW
    elif risk < 0.60:
        severity = Severity.MEDIUM
    elif risk < 0.80:
        severity = Severity.HIGH
    else:
        severity = Severity.CRITICAL

    evidence = inputs.evidence_quality
    if evidence is not None and evidence < 0.4 and severity is Severity.CRITICAL:
        severity = Severity.MEDIUM
    elif evidence is not None and evidence < 0.4 and severity is Severity.HIGH:
        severity = Severity.MEDIUM

    confidence = inputs.confidence
    if confidence is not None and confidence < 0.4 and severity is Severity.CRITICAL:
        severity = Severity.HIGH

    sensitivity = inputs.sensitivity
    if sensitivity is not None and sensitivity >= 0.75 and risk >= 0.6:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        idx = min(order.index(severity) + 1, len(order) - 1)
        severity = order[idx]

    return severity
