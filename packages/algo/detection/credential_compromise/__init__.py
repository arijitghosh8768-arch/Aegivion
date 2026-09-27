"""Algorithm #1 - Cloud Credential Compromise Detector.

Part 1 (this commit) implements the *foundation*:

    schemas -> normalizer -> identity resolution -> sessions -> profiles -> storage

Behavioral features, rules, baselines, anomaly detection, risk fusion and
finding generation are Part 2 and live in the sibling modules of this package
(``features.py``, ``rules.py``, ``baseline.py``, ``anomaly.py``, ``scorer.py``,
``confidence.py``, ``finding.py``, ``detector.py``).
"""

from .config import DetectorConfig, ScoringConfig, load_config
from .schemas import (
    ApiFamilies,
    AccessType,
    BaselineCategory,
    BaselineQuality,
    CloudProvider,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    IdentityProfile,
    IdentitySession,
    PrincipalType,
    ResolvedIdentity,
    Severity,
)

__all__ = [
    "AccessType",
    "ApiFamilies",
    "BaselineCategory",
    "BaselineQuality",
    "CloudProvider",
    "DetectorConfig",
    "EventCategory",
    "IdentityActivityEvent",
    "IdentityKind",
    "IdentityProfile",
    "IdentitySession",
    "PrincipalType",
    "ResolvedIdentity",
    "ScoringConfig",
    "Severity",
    "load_config",
]
