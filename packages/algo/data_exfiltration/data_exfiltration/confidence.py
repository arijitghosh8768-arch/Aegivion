"""Confidence calibration interface.

Calibration maps raw model outputs onto honest confidence values. Part 1
defines the contract; the stub raises rather than returning fake
confidence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from algo.data_exfiltration.data_exfiltration.schemas import SecurityFinding


class ConfidenceCalibrator(ABC):
    """Contract for Part 2 confidence calibration."""

    @abstractmethod
    def calibrate(self, finding: SecurityFinding) -> SecurityFinding:
        """Return a copy of *finding* with calibrated ``confidence``."""


class NotImplementedConfidenceCalibrator(ConfidenceCalibrator):
    """Part 1 stub: confidence stays unset until calibration exists."""

    def calibrate(self, finding: SecurityFinding) -> SecurityFinding:
        raise NotImplementedError(
            "confidence calibration ships in a later part; Part 1 emits discovery records only"
        )
