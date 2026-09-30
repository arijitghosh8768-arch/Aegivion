"""REST API tests (Part 5): all five endpoints through the WSGI app."""

from __future__ import annotations

import io
import json

import pytest

from algo.data_exfiltration.data_exfiltration.api import create_app

from .fixtures.scenarios import scenario_unknown_destination

ANALYZE = "/api/v1/detections/data-exfiltration/analyze"
FINDINGS = "/api/v1/detections/data-exfiltration/findings"


class _Client:
    """Tiny WSGI test client (no server, no dependencies)."""

    def __init__(self) -> None:
        self.app = create_app()

    def call(self, method: str, path: str, body: dict | None = None, qs: str = ""):
        raw = json.dumps(body).encode("utf-8") if body is not None else b""
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": qs,
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw),
        }
        captured: dict = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        payload = b"".join(self.app(environ, start_response))
        return captured["status"], json.loads(payload.decode("utf-8"))


@pytest.fixture()
def client() -> _Client:
    return _Client()


def _analyze(client: _Client) -> dict:
    status, body = client.call(
        "POST", ANALYZE,
        {"cloudtrail_records": scenario_unknown_destination(), "vpc_flow_records": []},
    )
    assert status.startswith("200")
    return body


class TestRoutes:
    def test_all_five_endpoints_registered(self, client: _Client) -> None:
        routes = client.app.router.routes()
        assert len(routes) == 5
        assert "POST /api/v1/detections/data-exfiltration/analyze" in routes
        assert "GET /api/v1/detections/data-exfiltration/findings" in routes
        assert "GET /api/v1/data-sessions/{session_id}" in routes
        assert "GET /api/v1/findings/{finding_id}/explanation" in routes
        assert any("data-resources" in r for r in routes)

    def test_analyze_produces_findings_with_contracts(self, client: _Client) -> None:
        body = _analyze(client)
        assert body["findings"]
        finding = body["findings"][0]
        assert finding["metadata"]["output_contract"]["finding_type"] == "data_discovery"
        assert body["stats"]["events_normalized"] >= 1

    def test_list_findings_after_analyze(self, client: _Client) -> None:
        _analyze(client)
        status, body = client.call("GET", FINDINGS, qs="limit=10")
        assert status.startswith("200")
        assert body["count"] >= 1
        summary = body["findings"][0]
        assert "validation_status" in summary and "robustness_score" in summary

    def test_session_endpoint(self, client: _Client) -> None:
        analyzed = _analyze(client)
        session_id = analyzed["findings"][0]["session_id"]
        status, body = client.call("GET", f"/api/v1/data-sessions/{session_id}")
        assert status.startswith("200")
        assert body["session"]["session_id"] == session_id

    def test_resource_profile_endpoint_handles_slashed_ids(self, client: _Client) -> None:
        analyzed = _analyze(client)
        resource_id = analyzed["findings"][0]["resource_id"]
        assert "/" in resource_id  # e.g. s3://bucket
        status, body = client.call("GET", f"/api/v1/data-resources/{resource_id}/profile")
        assert status.startswith("200")
        assert body["resource"]["resource_id"] == resource_id

    def test_explanation_endpoint(self, client: _Client) -> None:
        analyzed = _analyze(client)
        finding_id = analyzed["findings"][0]["finding_id"]
        status, body = client.call("GET", f"/api/v1/findings/{finding_id}/explanation")
        assert status.startswith("200")
        assert body["output_contract"] is not None
        assert "report" in body

    def test_filters_applied(self, client: _Client) -> None:
        _analyze(client)
        status, body = client.call("GET", FINDINGS, qs="min_risk=2.0")
        assert status.startswith("200")
        assert body["count"] == 0


class TestErrors:
    def test_unknown_route_is_404(self, client: _Client) -> None:
        status, body = client.call("GET", "/api/v1/nope")
        assert status.startswith("404")
        assert body["error"]["code"] == "not_found"

    def test_unknown_finding_is_404(self, client: _Client) -> None:
        status, _ = client.call("GET", "/api/v1/findings/does-not-exist/explanation")
        assert status.startswith("404")

    def test_wrong_method_is_405(self, client: _Client) -> None:
        status, body = client.call("POST", "/api/v1/data-sessions/anything")
        assert status.startswith("405")
        assert body["error"]["allowed"] == ["GET"]

    def test_bad_body_is_400(self, client: _Client) -> None:
        status, body = client.call("POST", ANALYZE, {"cloudtrail_records": "not-a-list"})
        assert status.startswith("400")
        assert body["error"]["code"] == "bad_request"

    def test_invalid_json_is_400(self, client: _Client) -> None:
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": ANALYZE,
            "QUERY_STRING": "",
            "CONTENT_LENGTH": "5",
            "wsgi.input": io.BytesIO(b"{bad}"),
        }
        captured = {}
        payload = b"".join(client.app(environ, lambda s, h: captured.update(status=s)))
        assert captured["status"].startswith("400")
        assert json.loads(payload)["error"]["code"] == "bad_json"
