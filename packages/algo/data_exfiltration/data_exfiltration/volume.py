"""Volume analysis: evidence about how much data moved.

Part 1 produces structured signals only (bytes, rates, per-category
breakdown, data-completeness flags). Deciding whether a volume is
*abnormal* requires baselines + risk fusion, which arrive in Part 2.
"""

from __future__ import annotations

from typing import Any

from algo.data_exfiltration.data_exfiltration.base import AnalysisModule, AnalysisResult
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession


class VolumeAnalyzer(AnalysisModule):
    name = "volume"

    def analyze(self, session: DataAccessSession, context: dict[str, Any] | None = None) -> AnalysisResult:
        signals: dict[str, Any] = {"session_id": session.session_id}

        bytes_measurement = session.bytes_accessed
        if bytes_measurement is not None and bytes_measurement.measurements:
            signals["bytes_total"] = bytes_measurement.value
            signals["bytes_provenance"] = bytes_measurement.provenance()
            signals["bytes_presence"] = bytes_measurement.presence.value
            signals["bytes_has_conflict"] = bytes_measurement.has_conflict
        else:
            signals["bytes_presence"] = "unavailable"
            signals["bytes_unavailable_reason"] = "no contributing event measured bytes_accessed"

        if session.start_time_epoch_ms and session.end_time_epoch_ms:
            duration_s = max(0.0, (session.end_time_epoch_ms - session.start_time_epoch_ms) / 1000.0)
            signals["duration_seconds"] = duration_s
            if bytes_measurement is not None and bytes_measurement.value and duration_s > 0:
                signals["bytes_per_second"] = bytes_measurement.value / duration_s

        egress = session.network_egress_bytes
        if egress is not None and egress.measurements:
            signals["network_egress_bytes"] = egress.value
            signals["network_egress_provenance"] = egress.provenance()
            signals["network_egress_presence"] = egress.presence.value
        else:
            signals["network_egress_presence"] = "unavailable"
            signals["network_egress_unavailable_reason"] = (
                "no VPC flow records were correlated with this session"
            )

        signals["objects_accessed"] = session.objects_accessed
        signals["request_count"] = session.request_count
        signals["read_event_count"] = session.read_event_count
        signals["write_event_count"] = session.write_event_count

        return AnalysisResult(analysis_name=self.name, signals=signals)
