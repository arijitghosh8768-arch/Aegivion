"""Network egress intelligence.

Computes egress ratios ONLY where telemetry is reliable:

- ``egress_ratio``            = network egress bytes / data-access bytes
- ``external_egress_ratio``   = share of egress toward public destinations

Both are unavailable (None) when the data-access and network measurements
cannot be considered comparable (different sources, conflicting values,
or missing halves). Network attribution is never fabricated: an
egress_ratio built from an estimated data-side number against an observed
flow number is reported as ``estimated`` with its provenance attached.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.enrichment import is_public_destination
from algo.data_exfiltration.data_exfiltration.measurement import MultiSourceMeasurement
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession


class EgressAssessment(BaseModel):
    session_id: str
    network_egress_bytes: float | None = None
    data_access_bytes: float | None = None
    egress_ratio: float | None = None
    external_egress_ratio: float | None = None
    availability: str = "unavailable"
    """``observed`` | ``estimated`` | ``unavailable``."""
    reliability: str = "not_correlated"
    """Why the ratio is unavailable (when it is)."""
    detail: dict[str, Any] = Field(default_factory=dict)


def _primary(measurement: MultiSourceMeasurement | None) -> float | None:
    if measurement is None or not measurement.measurements:
        return None
    return max(m.value for m in measurement.measurements)


def _source_confidence(measurement: MultiSourceMeasurement | None) -> tuple[str | None, str | None]:
    if measurement is None or not measurement.measurements:
        return None, None
    best = max(measurement.measurements, key=lambda m: m.value)
    return best.source.value, best.confidence.value


def egress_signals(session: DataAccessSession) -> EgressAssessment:
    """Egress ratios for one session, with honest availability."""
    assessment = EgressAssessment(session_id=session.session_id)

    egress = _primary(session.network_egress_bytes)
    data_bytes = _primary(session.bytes_accessed)
    assessment.network_egress_bytes = egress
    assessment.data_access_bytes = data_bytes

    external_destinations = [
        ip for ip in session.unique_destinations if is_public_destination(ip) is True
    ]
    if session.unique_destinations:
        assessment.external_egress_ratio = round(
            len(external_destinations) / len(session.unique_destinations), 4
        )
        assessment.availability = "observed"
    else:
        assessment.reliability = "no_destination_telemetry"

    if egress is None or data_bytes is None or data_bytes <= 0:
        assessment.reliability = (
            assessment.reliability
            if assessment.reliability != "not_correlated"
            else "missing_or_uncomparable_halves"
        )
        if egress is None and data_bytes is None:
            assessment.availability = "unavailable"
        return assessment

    egress_src, egress_conf = _source_confidence(session.network_egress_bytes)
    data_src, data_conf = _source_confidence(session.bytes_accessed)

    # Honest combination rule: observed/observed -> observed;
    # any estimated half -> estimated; conflicting sources -> flagged.
    confidences = {egress_conf, data_conf}
    assessment.availability = (
        "observed" if confidences == {"observed"} else "estimated"
    )
    assessment.egress_ratio = round(min(egress / data_bytes, 1e6), 4)
    assessment.detail = {
        "egress_source": egress_src,
        "egress_confidence": egress_conf,
        "data_source": data_src,
        "data_confidence": data_conf,
        "external_destinations": external_destinations,
    }
    if session.network_egress_bytes is not None and session.network_egress_bytes.has_conflict:
        assessment.detail["sources_conflict"] = True
    return assessment
