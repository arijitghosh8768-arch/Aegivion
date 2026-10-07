"""Aegivion Attack Algorithm #3 — Cloud Destructive Activity Detector.

This package is a DEFENSIVE detection engine. It never performs destructive
actions: all malicious scenarios are represented as synthetic or replayed
telemetry. It operates fully independently of the Credential Compromise
(Algorithm #1) and Data Exfiltration (Algorithm #2) detectors — the only
allowed future interaction is through Aegivion Threat Correlation.
"""

from algo.detection.cloud_destruction import config, exceptions, provenance, schemas

__all__ = ["config", "exceptions", "provenance", "schemas"]
