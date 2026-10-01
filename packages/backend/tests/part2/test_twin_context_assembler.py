import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock
from security.engine.twin_context_assembler import TwinContextAssembler

def test_twin_context_assembler_graceful_degradation():
    assembler = TwinContextAssembler()
    
    # Passing None for digital_twin should degrade gracefully
    ctx = assembler.assemble("org1", "actor1", "target1", None)
    
    assert ctx["twin_context_fresh"] is False
    assert "twin_context_assembled_at" in ctx
    assert ctx["identity_type"] is None
    assert ctx["known_ips"] == []
    assert ctx["recent_failed_logins"] == 0
    assert ctx["asset_resource_id"] == "target1"
    assert ctx["asset_internet_exposed"] is False
    assert ctx["blast_radius_assets"] == []
    assert ctx["relationship_count"] == 0

def test_twin_context_assembler_with_twin_mock():
    assembler = TwinContextAssembler()
    
    # Mock SecurityDigitalTwin
    mock_twin = MagicMock()
    mock_twin._organization_id = "org1"
    
    # Mock persistence layer for identity
    mock_persistence = MagicMock()
    mock_persistence.get_identity.return_value = {
        "identity_type": "HUMAN",
        "status": "ACTIVE",
        "criticality": "HIGH",
        "metadata": {
            "known_ips": ["1.2.3.4"],
            "recent_failed_logins": 5,
            "baseline_deletions": 10,
            "baseline_modifications": 20,
            "historical_targets": ["target1", "target2"]
        }
    }
    mock_twin._persistence = mock_persistence
    
    # Mock asset methods
    mock_twin.get_asset_context.return_value = {
        "resource_id": "target1",
        "environment": "PROD",
        "business_criticality": "CRITICAL",
        "internet_exposed": True,
        "importance_score": 0.9,
        "relationships": [{"type": "owns", "target": "other"}]
    }
    
    mock_twin.query_blast_radius.return_value = [{"resource_id": "other"}]
    
    ctx = assembler.assemble("org1", "actor1", "target1", mock_twin)
    
    assert ctx["twin_context_fresh"] is True
    
    # Identity checks
    mock_persistence.get_identity.assert_called_once_with("org1", "actor1")
    assert ctx["identity_type"] == "HUMAN"
    assert ctx["known_ips"] == ["1.2.3.4"]
    assert ctx["recent_failed_logins"] == 5
    assert ctx["actor_baseline_deletions"] == 10
    assert ctx["actor_baseline_modifications"] == 20
    assert ctx["actor_historical_targets"] == ["target1", "target2"]
    
    # Asset checks
    mock_twin.get_asset_context.assert_called_once_with("target1")
    assert ctx["asset_environment"] == "PROD"
    assert ctx["asset_internet_exposed"] is True
    assert ctx["relationship_count"] == 1
    
    # Blast radius
    mock_twin.query_blast_radius.assert_called_once_with("target1", depth=1)
    assert ctx["blast_radius_assets"] == [{"resource_id": "other"}]

def test_twin_context_assembler_handles_exception_safely():
    assembler = TwinContextAssembler()
    
    mock_twin = MagicMock()
    mock_twin.get_asset_context.side_effect = Exception("DB Timeout")
    
    # Should not raise, should degrade to fresh=False
    ctx = assembler.assemble("org1", "actor1", "target1", mock_twin)
    
    assert ctx["twin_context_fresh"] is False
    assert ctx["asset_internet_exposed"] is False
