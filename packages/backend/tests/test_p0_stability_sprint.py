import pytest
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import get_current_user
from app.database import get_db
from app.models.cloud import CloudAsset
from app.models.cloud_account import CloudAccountV2
from app.models.incident import Incident
from security.models.finding import Finding

# --- Mock Entities & Fixtures ---

def mock_user_org_a():
    return {
        "user_id": "user-a",
        "organization_id": "org-a",
        "role": "admin"
    }

def mock_user_org_b():
    return {
        "user_id": "user-b",
        "organization_id": "org-b",
        "role": "admin"
    }

def mock_user_no_org():
    return {
        "user_id": "user-no-org",
        "organization_id": None,
        "role": "admin"
    }

class MockQuery:
    def __init__(self, items=None, filter_fn=None):
        self._items = items or []
        self._filter_fn = filter_fn

    def filter(self, *expressions):
        filtered = list(self._items)
        for expr in expressions:
            if isinstance(expr, tuple) and len(expr) == 2:
                field, expected_val = expr
                filtered = [
                    item for item in filtered
                    if str(getattr(item, field, None)) == str(expected_val)
                ]
            elif hasattr(expr, "left") and hasattr(expr, "right"):
                # Handle SQLAlchemy BinaryExpression
                field = getattr(expr.left, "name", None) or getattr(expr.left, "key", None)
                expected_val = getattr(expr.right, "value", expr.right)
                if field is not None:
                    filtered = [
                        item for item in filtered
                        if str(getattr(item, field, None)) == str(expected_val)
                    ]
        return MockQuery(filtered)

    def first(self):
        return self._items[0] if self._items else None

    def all(self):
        return self._items

class MockDB:
    def __init__(self):
        self.accounts = [
            CloudAccountV2(id="acc-a", organization_id="org-a", name="AWS Production Org A"),
            CloudAccountV2(id="acc-b", organization_id="org-b", name="AWS Production Org B"),
        ]
        self.assets = [
            CloudAsset(
                id="asset-a-1",
                resource_id="aws:s3:org-a-vault",
                account_id="acc-a",
                provider="aws",
                type="s3_bucket",
                region="us-east-1",
                name="org-a-vault"
            ),
            CloudAsset(
                id="asset-b-1",
                resource_id="aws:s3:org-b-vault",
                account_id="acc-b",
                provider="aws",
                type="s3_bucket",
                region="us-east-1",
                name="org-b-vault"
            )
        ]
        self.incidents = [
            Incident(
                id="inc-a-1",
                organization_id="org-a",
                title="S3 Bucket Exposed in Org A",
                severity="high",
                finding_ids=["finding-a-1"],
                asset_ids=["aws:s3:org-a-vault"]
            ),
            Incident(
                id="inc-b-1",
                organization_id="org-b",
                title="EC2 Port Open in Org B",
                severity="critical",
                finding_ids=["finding-b-1"],
                asset_ids=["aws:s3:org-b-vault"]
            )
        ]
        self.findings = [
            Finding(
                id="finding-a-1",
                title="Public Bucket ACL",
                severity="high",
                resource_id="aws:s3:org-a-vault",
                cloud_provider="aws"
            )
        ]

    def query(self, model, *args, **kwargs):
        model_name = getattr(model, "__name__", str(model))
        if "CloudAccount" in model_name:
            return MockQuery(self.accounts)
        elif "CloudAsset" in model_name:
            return MockQuery(self.assets)
        elif "Incident" in model_name:
            return MockQuery(self.incidents)
        elif "Finding" in model_name:
            return MockQuery(self.findings)
        elif "OrgSettings" in model_name:
            mock_settings = MagicMock()
            mock_settings.ai_features_enabled = True
            mock_settings.organization_id = "org-a"
            return MockQuery([mock_settings])
        return MockQuery([])

@pytest.fixture
def client():
    mock_db = MockDB()
    app.dependency_overrides[get_db] = lambda: mock_db
    yield TestClient(app)
    app.dependency_overrides.clear()


# ============================================================================
# 1. Regression Tests for Assets Endpoint (assets.py)
# ============================================================================

def test_get_asset_unauthenticated(client):
    """Unauthenticated request must be rejected with 401."""
    app.dependency_overrides.pop(get_current_user, None)
    response = client.get("/api/v1/assets/asset-a-1")
    assert response.status_code == 401

def test_get_asset_missing_org(client):
    """User without an organization must be denied with 403."""
    app.dependency_overrides[get_current_user] = mock_user_no_org
    response = client.get("/api/v1/assets/asset-a-1")
    assert response.status_code == 403
    assert "associated with an organization" in response.json()["detail"]

@patch("app.api.v1.assets.get_current_organization", return_value="org-a")
def test_get_asset_success_org_a(mock_org, client):
    """User in Org A can fetch Org A's asset."""
    app.dependency_overrides[get_current_user] = mock_user_org_a
    response = client.get("/api/v1/assets/asset-a-1")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "asset-a-1"
    assert data["name"] == "org-a-vault"

@patch("app.api.v1.assets.get_current_organization", return_value="org-b")
def test_get_asset_cross_tenant_denial(mock_org, client):
    """User in Org B cannot fetch Org A's asset (returns 404/denial)."""
    app.dependency_overrides[get_current_user] = mock_user_org_b
    response = client.get("/api/v1/assets/asset-a-1")
    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found"


# ============================================================================
# 2. Regression Tests for AI Chat Endpoint (chat.py)
# ============================================================================

def test_chat_unauthenticated(client):
    """Unauthenticated chat request must return 401."""
    app.dependency_overrides.pop(get_current_user, None)
    response = client.post("/api/v1/ai/chat", json={"message": "What is our threat posture?"})
    assert response.status_code == 401

def test_chat_missing_org(client):
    """Chat request without organization association must return 403."""
    app.dependency_overrides[get_current_user] = mock_user_no_org
    response = client.post("/api/v1/ai/chat", json={"message": "What is our threat posture?"})
    assert response.status_code == 403
    assert "organization" in response.json()["detail"].lower()

@patch("app.api.v1.chat.get_llm_provider")
def test_chat_dict_user_and_valid_json_response(mock_get_provider, client):
    """Ensures dict user (org_id access) works and structured JSON is properly parsed and returned."""
    mock_provider = MagicMock()
    mock_provider.generate.return_value = json.dumps({
        "response": "The S3 bucket acl is insecure.",
        "observed": ["Bucket has public ACL"],
        "inferred": ["Data exposure risk"],
        "unknown": ["Exact attacker IP"],
        "declined": False
    })
    mock_get_provider.return_value = mock_provider

    app.dependency_overrides[get_current_user] = mock_user_org_a
    response = client.post("/api/v1/ai/chat", json={"message": "Explain finding-a-1"})
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["response"] == "The S3 bucket acl is insecure."
    assert "Bucket has public ACL" in res_data["observed"]
    assert res_data["declined"] is False

@patch("app.api.v1.chat.get_llm_provider")
def test_chat_llm_malformed_json_returns_502(mock_get_provider, client):
    """If the LLM returns plain text or broken JSON, a structured 502 error is returned without fabricating answers."""
    mock_provider = MagicMock()
    mock_provider.generate.return_value = "OpenAI analysis complete - NOT VALID JSON"
    mock_get_provider.return_value = mock_provider

    app.dependency_overrides[get_current_user] = mock_user_org_a
    response = client.post("/api/v1/ai/chat", json={"message": "Explain risk"})
    assert response.status_code == 502
    err_detail = response.json()["detail"]
    assert err_detail["error"] == "LLM_INVALID_FORMAT"

@patch("app.api.v1.chat.get_llm_provider")
def test_chat_llm_provider_exception_returns_502(mock_get_provider, client):
    """If the provider fails or throws an exception, returns a clean 502 error."""
    mock_provider = MagicMock()
    mock_provider.generate.side_effect = RuntimeError("Connection timed out to LLM")
    mock_get_provider.return_value = mock_provider

    app.dependency_overrides[get_current_user] = mock_user_org_a
    response = client.post("/api/v1/ai/chat", json={"message": "Hello"})
    assert response.status_code == 502
    err_detail = response.json()["detail"]
    assert err_detail["error"] == "LLM_PROVIDER_ERROR"


# ============================================================================
# 3. Regression Tests for Missing Endpoints: /v1/correlations & /v1/memory
# ============================================================================

def test_correlations_unauthenticated(client):
    """Unauthenticated request to correlations must return 401."""
    app.dependency_overrides.pop(get_current_user, None)
    response = client.get("/api/v1/correlations")
    assert response.status_code == 401

@patch("app.api.v1.correlations.get_current_organization", return_value="org-a")
def test_correlations_authenticated_org_a(mock_org, client):
    """Authenticated request returns structured chains conforming to frontend threat-correlation page."""
    app.dependency_overrides[get_current_user] = mock_user_org_a
    response = client.get("/api/v1/correlations")
    assert response.status_code == 200
    data = response.json()
    assert "chains" in data
    assert "correlations" in data
    assert "total" in data
    assert isinstance(data["chains"], list)

def test_memory_unauthenticated(client):
    """Unauthenticated request to memory must return 401."""
    app.dependency_overrides.pop(get_current_user, None)
    response = client.get("/api/v1/memory")
    assert response.status_code == 401

@patch("app.api.v1.memory.get_current_organization", return_value="org-a")
def test_memory_authenticated_org_a(mock_org, client):
    """Authenticated request returns memory data matching frontend security-memory page requirements."""
    app.dependency_overrides[get_current_user] = mock_user_org_a
    response = client.get("/api/v1/memory")
    assert response.status_code == 200
    data = response.json()
    assert "incidents" in data
    assert "INCIDENTS" in data
    assert "LEARNED_PATTERNS" in data
    assert "REPEATED_MISTAKES" in data
    assert "MEMORY_TREND" in data
    assert len(data["INCIDENTS"]) >= 1
    assert data["INCIDENTS"][0]["title"] == "S3 Bucket Exposed in Org A"

@patch("app.api.v1.memory.get_current_organization", return_value="org-b")
def test_memory_tenant_isolation_org_b(mock_org, client):
    """Org B only sees Org B incidents in memory."""
    app.dependency_overrides[get_current_user] = mock_user_org_b
    response = client.get("/api/v1/memory")
    assert response.status_code == 200
    data = response.json()
    assert len(data["INCIDENTS"]) >= 1
    assert data["INCIDENTS"][0]["title"] == "EC2 Port Open in Org B"
