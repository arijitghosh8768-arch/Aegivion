from fastapi.testclient import TestClient
from .main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["success"] is True
    assert res_data["data"]["message"] == "Hello World from Aegivion Backend API"

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["success"] is True
    assert "status" in res_data["data"]
