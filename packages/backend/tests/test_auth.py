import pytest
from app.core.security import SecurityService

class TestAuthentication:
    def test_jwt_create_and_verify(self):
        security = SecurityService()
        token = security.create_access_token(user_id="u-1234", org_id="org-5678", role="admin")
        
        payload = security.verify_token(token)
        assert payload["sub"] == "u-1234"
        assert payload["org"] == "org-5678"
        assert payload["role"] == "admin"
        
    def test_password_hash_and_check(self):
        security = SecurityService()
        hashed = security.hash_password("SuperSecret123!")
        
        assert security.verify_password("SuperSecret123!", hashed) is True
        assert security.verify_password("WrongPassword123!", hashed) is False
        
    def test_unauthenticated_health_ok(self, client):
        # Health check is open
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["success"] is True
