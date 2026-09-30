import os
import pytest
import asyncio
from unittest.mock import patch
from security.engine.config import get_persistence_config, get_persistence_components, PersistenceContainer
from security.engine.persistence.memory import InMemoryEventStore
from security.engine.agent_controller import AegivionAgentController

def test_config_memory_selection():
    with patch.dict(os.environ, {"ENVIRONMENT": "development", "PERSISTENCE_BACKEND": "memory"}):
        config = get_persistence_config()
        components = get_persistence_components(config)
        assert isinstance(components.event_store, InMemoryEventStore)

def test_config_production_fails_without_postgres():
    with patch.dict(os.environ, {"ENVIRONMENT": "production", "PERSISTENCE_BACKEND": "memory"}):
        config = get_persistence_config()
        with pytest.raises(ValueError, match="must explicitly select 'postgres'"):
            get_persistence_components(config)

def test_config_production_postgres_missing_url():
    with patch.dict(os.environ, {"ENVIRONMENT": "production", "PERSISTENCE_BACKEND": "postgres"}):
        if "DATABASE_URL" in os.environ:
            del os.environ["DATABASE_URL"]
        config = get_persistence_config()
        with pytest.raises(ValueError, match="DATABASE_URL is missing"):
            get_persistence_components(config)

def test_config_production_postgres_bad_url():
    with patch.dict(os.environ, {"ENVIRONMENT": "production", "PERSISTENCE_BACKEND": "postgres", "DATABASE_URL": "invalid://url"}):
        config = get_persistence_config()
        with pytest.raises(ValueError, match="fails clearly"):
            get_persistence_components(config)

def test_agent_controller_receives_injected_persistence():
    event_store = InMemoryEventStore()
    components = PersistenceContainer(event_store=event_store)
    controller = AegivionAgentController(
        max_queue_size=10, 
        organization_id="org1", 
        event_store=components.event_store,
        detection_context_repo=components.detection_context_repo,
        attack_state_repo=components.attack_state_repo
    )
    
    assert controller.event_store is event_store
    assert controller.detection_context_repo is None
    assert controller.attack_state_repo is None
