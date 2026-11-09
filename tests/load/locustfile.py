import os
from locust import HttpUser, task, between

class AegivionApiUser(HttpUser):
    """
    Locust load test suite for Aegivion API.
    Simulates concurrent users interacting with health check and protected security findings endpoints.
    """
    wait_time = between(1, 3)

    def on_start(self):
        """Setup user auth token before tasks begin"""
        self.auth_token = os.getenv("LOCUST_AUTH_TOKEN", "mock-test-jwt-token")
        self.headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    @task(3)
    def test_health_check(self):
        """Pings public health check (Liveness)"""
        with self.client.get("/health", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed with status code: {response.status_code}")

    @task(1)
    def test_readiness_check(self):
        """Pings readiness check (DB connectivity)"""
        self.client.get("/health/ready")

    @task(2)
    def test_findings_list(self):
        """Queries security findings endpoint to test database queries and rate limiter under load"""
        with self.client.get("/api/v1/findings", headers=self.headers, catch_response=True) as response:
            # 200 is success, 401 is expected if mock token, 429 is rate limit (which we want to measure)
            if response.status_code in (200, 401, 429):
                response.success()
            else:
                response.failure(f"Unexpected status code: {response.status_code}")

    @task(1)
    def test_risk_telemetry(self):
        """Tests telemetry query performance"""
        self.client.get("/api/v1/history/risk-telemetry/dataset", headers=self.headers)
