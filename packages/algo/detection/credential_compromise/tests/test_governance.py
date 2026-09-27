"""Governance tests: suppression, audit chain, ATT&CK mapping, explainability."""

from __future__ import annotations

from datetime import timedelta

import pytest

from detection.credential_compromise.attack_mapping import (
    RULE_ATTACK_MAPPING,
    map_signals_to_attack,
)
from detection.credential_compromise.audit import AuditLog
from detection.credential_compromise.explainability import (
    build_explanation,
    model_agreement,
)
from detection.credential_compromise.schemas import Severity, utcnow
from detection.credential_compromise.suppression import SuppressionEngine


# --------------------------------------------------------------------------- #
# Suppression engine
# --------------------------------------------------------------------------- #


class TestSuppression:
    def test_suppression_is_audited_and_reversible(self):
        log = AuditLog()
        engine = SuppressionEngine(audit_log=log)
        rule = engine.add(
            scope="identity",
            scope_value="aws:1:user:bob",
            reason="approved travel",
            created_by="analyst-1",
            duration_days=7,
        )
        assert len(log) == 1
        assert engine.revoke(rule.suppression_id, revoked_by="analyst-2")
        assert len(log) == 2
        actions = [entry.action for entry in log.entries()]
        assert actions == ["suppression.created", "suppression.revoked"]

    def test_suppression_is_time_bound(self):
        engine = SuppressionEngine()
        with pytest.raises(ValueError):
            engine.add(
                scope="rule",
                scope_value="R001",
                reason="too long",
                created_by="analyst-1",
                duration_days=3650,
            )

    def test_expired_suppressions_expire(self):
        log = AuditLog()
        engine = SuppressionEngine(audit_log=log)
        engine.add(
            scope="identity",
            scope_value="aws:1:user:carol",
            reason="temp",
            created_by="analyst-1",
            duration_days=1,
        )
        # Force expiry by rewriting the rule (test-only manipulation).
        rule = engine.active_rules()[0]
        object.__setattr__(
            rule, "expires_at", utcnow() - timedelta(days=1)
        )
        decision = engine.evaluate(
            identity_key="aws:1:user:carol", rule_ids=["R001"], severity=Severity.LOW
        )
        assert not decision.suppressed
        assert any(e.action == "suppression.expired" for e in log.entries())

    def test_high_severity_is_never_silently_dropped(self):
        engine = SuppressionEngine()
        engine.add(
            scope="identity",
            scope_value="aws:1:user:dave",
            reason="vpn resident",
            created_by="analyst-1",
        )
        decision = engine.evaluate(
            identity_key="aws:1:user:dave",
            rule_ids=["R001", "R010"],
            severity=Severity.CRITICAL,
        )
        assert not decision.suppressed
        assert decision.downgraded_to_review is True
        assert "never" in decision.explanation

    def test_low_severity_suppressed_with_match(self):
        engine = SuppressionEngine()
        engine.add(
            scope="rule",
            scope_value="R003",
            reason="corporate DHCP churn",
            created_by="analyst-1",
        )
        decision = engine.evaluate(
            identity_key="aws:1:user:erin", rule_ids=["R003"], severity=Severity.LOW
        )
        assert decision.suppressed is True

    def test_scope_must_be_valid(self):
        engine = SuppressionEngine()
        with pytest.raises(ValueError):
            engine.add(scope="global", scope_value="*", reason="x", created_by="a")


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #


class TestAuditLog:
    def test_chain_verifies_when_intact(self):
        log = AuditLog()
        for i in range(5):
            log.append(actor="t", action=f"a{i}", subject=f"s{i}")
        ok, broken = log.verify()
        assert ok and broken is None

    def test_tampering_is_detected(self):
        log = AuditLog()
        log.append(actor="t", action="a", subject="s")
        entry = log.entries()[0]
        # A tamperer edits the payload after the fact...
        tampered = object.__setattr__(entry, "payload", {"evil": True})
        _ = tampered
        ok, broken = log.verify()
        assert not ok
        assert broken == 0

    def test_deletion_breaks_chain(self):
        log = AuditLog()
        log.append(actor="t", action="a", subject="s1")
        log.append(actor="t", action="b", subject="s2")
        log._entries.pop(0)  # delete the first entry
        ok, broken = log.verify()
        assert not ok
        # The first surviving entry (seq 1) no longer chains to genesis.
        assert broken == 1


# --------------------------------------------------------------------------- #
# ATT&CK mapping
# --------------------------------------------------------------------------- #


class TestAttackMapping:
    def test_privilege_rules_map_to_account_manipulation(self):
        mappings = map_signals_to_attack(["R010", "R012"])
        ids = {m["technique_id"] for m in mappings}
        assert {"T1098", "T1098.001"} <= ids

    def test_no_signals_and_unknown_family_yields_empty(self):
        assert map_signals_to_attack([]) == []
        assert map_signals_to_attack([], api_family="TOTALLY_UNKNOWN") == []

    def test_detector_works_without_mapping(self):
        # The mapping is metadata: removing it must not break the function.
        import detection.credential_compromise.attack_mapping as am

        saved = dict(am.RULE_ATTACK_MAPPING)
        am.RULE_ATTACK_MAPPING.clear()
        try:
            assert map_signals_to_attack(["R010"]) == []
        finally:
            am.RULE_ATTACK_MAPPING.update(saved)

    def test_every_catalogued_rule_has_mapping_or_is_intentional(self):
        from detection.credential_compromise.rules import RULE_CATALOGUE

        mapped = {rule_id for rule_id, _ in RULE_ATTACK_MAPPING.items()}
        catalogue_ids = {rule.rule_id for rule in RULE_CATALOGUE}
        assert catalogue_ids <= mapped  # all 14 rules mapped


# --------------------------------------------------------------------------- #
# Explainability
# --------------------------------------------------------------------------- #


class TestExplainability:
    def _features(self):
        from detection.credential_compromise.features import BehavioralFeatures, FeatureValue

        def fv(name, value, conf=0.9):
            return FeatureValue(name=name, value=value, confidence=conf)

        return BehavioralFeatures(
            time_anomaly=fv("time_anomaly", 0.9),
            country_novelty=fv("country_novelty", 1.0),
            region_novelty=fv("region_novelty", 0.0, 0.8),
            location_anomaly=fv("location_anomaly", 1.0),
            ip_novelty=fv("ip_novelty", 1.0),
            asn_novelty=fv("asn_novelty", 1.0),
            network_reputation=fv("network_reputation", 0.4),
            network_anomaly=fv("network_anomaly", 1.0),
            client_novelty=fv("client_novelty", 0.2, 0.7),
            device_anomaly=fv("device_anomaly", 0.2, 0.7),
            api_novelty=fv("api_novelty", 0.8),
            service_novelty=fv("service_novelty", 0.1, 0.6),
            api_frequency_deviation=fv("api_frequency_deviation", 0.0, 0.5),
            read_write_deviation=fv("read_write_deviation", 0.6),
            api_sequence_deviation=fv("api_sequence_deviation", 0.5),
            api_anomaly=fv("api_anomaly", 0.8),
            privilege_anomaly=fv("privilege_anomaly", 0.85),
        )

    def test_structure_and_contributors(self):
        signals = [
            {"rule_id": "R001", "signal": "new_country", "severity": "MEDIUM", "value": 1.0},
            {"rule_id": "R010", "signal": "privilege_modification", "severity": "HIGH", "value": 1.0},
        ]
        explanation = build_explanation(self._features(), signals, None)
        payload = explanation.to_dict()
        assert payload["top_contributors"][0] == "Privilege modification"
        assert "New country" in payload["top_contributors"]
        assert payload["baseline_quality"] == "COLD_START"
        assert payload["model_agreement"] == "NOT_ASSESSED"
        labels = {e["label"] for e in payload["supporting_evidence"]}
        assert "New country" in labels
        contradicting = {e["feature"] for e in payload["contradicting_evidence"]}
        assert "region_novelty" in contradicting

    def test_model_agreement_bands(self):
        high_rules = [{"rule_id": "R010", "severity": "HIGH", "value": 1.0}]
        assert model_agreement(high_rules, 0.9, True) == "FULL"
        assert model_agreement(high_rules, 0.5, True) == "PARTIAL"
        assert model_agreement(high_rules, 0.05, True) == "NONE"
        assert model_agreement([], None, False) == "NOT_ASSESSED"
