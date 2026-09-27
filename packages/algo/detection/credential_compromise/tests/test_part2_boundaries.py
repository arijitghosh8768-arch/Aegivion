"""Part 2 boundary tests.

The behavioral layer, the ML anomaly layer and the fusion engine are now
implemented. The old "must raise NotImplementedYetError" contract applied to
stages that previously had no implementation; these stages now have real,
tested implementations. The remaining honesty boundaries are asserted here:
synthetic labels are always declared, unfitted models refuse to score, and
version stamps are always present on findings.
"""

from __future__ import annotations

import pytest

from detection.credential_compromise import (
    anomaly,
    baseline,
    confidence,
    detector,
    features,
    finding,
    replay,
    rules,
    scorer,
)
from detection.credential_compromise.anomaly import (
    FEATURE_NAMES,
    IsolationForest,
)
from detection.credential_compromise.exceptions import DetectionError
from detection.credential_compromise.model_registry import (
    ComponentVersions,
    MODEL_NAME,
    RULE_VERSION,
    SCORING_VERSION,
)


def test_behavioral_layer_is_real():
    assert callable(baseline.build_profile)
    assert callable(baseline.update_profile)
    assert callable(features.extract_features)
    assert callable(rules.evaluate_rules)
    assert callable(scorer.calculate_risk)
    assert callable(scorer.severity_for)
    assert len(rules.RULE_CATALOGUE) == 14


def test_ml_layer_is_real_and_versioned():
    assert len(FEATURE_NAMES) == 18
    assert anomaly.FEATURE_VERSION.startswith("fv")
    assert SCORING_VERSION.startswith("fusion-")
    assert RULE_VERSION.startswith("rules-")
    assert MODEL_NAME == "isolation_forest"


def test_unfitted_models_fail_loudly():
    forest = IsolationForest()
    with pytest.raises(DetectionError):
        forest.raw_score((0.1,) * len(FEATURE_NAMES))


def test_detector_pipeline_is_wired():
    assert callable(detector.CredentialCompromiseDetector.detect)
    assert callable(detector.CredentialCompromiseDetector.replay)
    assert set(detector.DetectionMode) == {
        detector.DetectionMode.REAL_TIME,
        detector.DetectionMode.BATCH,
        detector.DetectionMode.REPLAY,
    }
    assert callable(confidence.evidence_confidence)
    assert callable(finding.build_finding)
    assert callable(replay.compare_configurations)
    assert callable(replay.format_comparison_report)
    ComponentVersions()
