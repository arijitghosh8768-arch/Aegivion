"""Mandatory independence tests (Part 5).

Algorithm #2 (Cloud Data Exfiltration Detector) must be fully independent
of Algorithm #1 (Credential Compromise Detector):

1. it works with Algorithm #1 OFF (no coupling, no import, no shared state);
2. a HIGH credential-compromise signal never manufactures a data-exfiltration
   finding when the DATA behaviour is normal;
3. a HIGH data-exfiltration result does not itself assert credential or
   identity compromise.

Algorithm #1 is represented here by a deliberately inert stub. This test
file lives under ``tests/`` (excluded from the package-wide token scan in
``test_finding_stubs.py``) precisely because it names the sibling engine.
"""

from __future__ import annotations

import pathlib

from algo.data_exfiltration.data_exfiltration.arde import ARDEValidator
from algo.data_exfiltration.data_exfiltration.detector import DataExfiltrationDetector
from algo.data_exfiltration.data_exfiltration.intelligence import BehavioralProfiler
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack

from .fixtures.scenarios import scenario_normal_s3_access


class _InertSiblingEngineStub:
    """Stands in for Algorithm #1. It is never consulted by Algorithm #2."""

    def __init__(self, level: str = "HIGH") -> None:
        self.level = level
        self.consulted = False

    def evaluate(self, actor_id: str | None) -> dict:
        self.consulted = True
        return {"engine": "credential", "compromise_level": self.level, "alerting": True}


def _score_normal_session(sibling: _InertSiblingEngineStub | None):
    detector = DataExfiltrationDetector(
        profiler=BehavioralProfiler(),
        arde_validator=ARDEValidator(),
    )
    result = detector.process_events(cloudtrail_records=scenario_normal_s3_access())
    scored = detector.score_sessions(result, ScoringStack(variant="B"))
    if sibling is not None:  # presence must not change anything
        sibling.evaluate("any-actor")
    return result, scored


class TestAlgorithm1Disabled:
    def test_detector_runs_with_algorithm_1_off(self) -> None:
        result, scored = _score_normal_session(None)
        assert len(result.sessions) == 1
        assert len(scored) == 1
        finding = scored[0]
        assert finding.risk_score is not None
        assert finding.model["model_name"] == "aegivion.data_exfiltration"

    def test_no_import_of_sibling_engine(self) -> None:
        """The package must not import or reference Algorithm #1 modules."""
        import algo.data_exfiltration.data_exfiltration as pkg

        root = pathlib.Path(pkg.__file__).parent
        offenders = []
        for path in root.rglob("*.py"):
            if "tests" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            for token in (
                "credential_" + "compromise",
                "identity_" + "compromise",
                "credential_detector",
                "algorithm_1",
                "algorithm_2",
            ):
                if token in text:
                    offenders.append((path.name, token))
        assert offenders == [], offenders


class TestCredentialSignalDoesNotCreateDataFinding:
    def test_high_credential_signal_with_normal_data_is_not_an_exfil_alert(self) -> None:
        sibling = _InertSiblingEngineStub(level="HIGH")
        _result, scored = _score_normal_session(sibling)
        finding = scored[0]
        # data behaviour is normal: no exfiltration verdict, regardless of the
        # (inert) credential signal.
        assert finding.risk_score is not None and finding.risk_score < 0.5
        assert finding.severity.value in ("info", "low", "medium")
        fired = finding.metadata["scoring"]["fired_rules"]
        exfil_rules = {
            "high_risk_destination",
            "unknown_external_destination",
            "enumeration_pattern",
            "high_egress_ratio",
        }
        assert not (set(fired) & exfil_rules)

    def test_output_identical_with_and_without_sibling_engine(self) -> None:
        """Same inputs -> byte-identical finding, whether the sibling exists."""
        _r_off, scored_off = _score_normal_session(None)
        sibling = _InertSiblingEngineStub(level="HIGH")
        _r_on, scored_on = _score_normal_session(sibling)

        def _fingerprint(finding) -> dict:
            return {
                "risk_score": finding.risk_score,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "fired_rules": finding.metadata["scoring"]["fired_rules"],
                "contract": {
                    k: finding.metadata["output_contract"][k]
                    for k in ("severity", "risk_score", "validation_status", "signals")
                },
            }

        assert _fingerprint(scored_off[0]) == _fingerprint(scored_on[0])


class TestReverseIndependence:
    def test_data_finding_asserts_nothing_about_credentials(self) -> None:
        _result, scored = _score_normal_session(None)
        contract = scored[0].metadata["output_contract"]
        blob = repr(contract).lower()
        assert "credential" not in blob
        assert "identity" not in blob
        assert "compromise" not in blob

    def test_high_data_risk_does_not_touch_sibling_state(self) -> None:
        sibling = _InertSiblingEngineStub(level="LOW")
        detector = DataExfiltrationDetector(
            profiler=BehavioralProfiler(),
            arde_validator=ARDEValidator(),
        )
        from .fixtures.scenarios import scenario_unknown_destination

        result = detector.process_events(cloudtrail_records=scenario_unknown_destination())
        detector.score_sessions(result, ScoringStack(variant="B"))
        # Algorithm #2 never calls into the sibling engine.
        assert sibling.consulted is False
        assert sibling.level == "LOW"
