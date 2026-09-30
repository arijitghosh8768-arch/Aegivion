"""Live demo: run the acceptance kill chain through the detection API.

Shows the actual request/response payloads for:

    POST /api/v1/detections/credential-compromise/analyze
    GET  /api/v1/detections/credential-compromise/findings
    GET  /api/v1/identities/{id}/behavior
    GET  /api/v1/identities/{id}/timeline
    GET  /api/v1/findings/{id}/explanation

Run:  python scripts/demo_api.py
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from algo.api.server import DetectionApp, Request, Router  # noqa: E402
from algo.detection.credential_compromise.config import DetectorConfig  # noqa: E402
from tests.test_acceptance_final import (  # noqa: E402
    _attack_records,
    _normal_records,
    T0,
)
from algo.ingestion.aws.cloudtrail import CloudTrailNormalizer  # noqa: E402


def banner(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def show_response(payload: dict, *, drop: tuple[str, ...] = (), keep: int = 4000) -> None:
    trimmed = {k: v for k, v in payload.items() if k not in drop}
    text = json.dumps(trimmed, indent=2, default=str)
    if len(text) > keep:
        text = text[:keep] + "\n  ... (truncated)"
    print(text)


def main() -> int:
    # -- Setup: normalize the raw records and learn the baseline ------------
    events = CloudTrailNormalizer().normalize_batch(
        _normal_records() + _attack_records(), strict=True
    ).events
    benign = [e for e in events if e.timestamp < T0 + timedelta(days=45)]
    # Only the 4 true kill-chain events (recon -> AssumeRole -> PutUserPolicy
    # -> CreateAccessKey), identified by their distinct event names.
    attack_names = {
        "GetAccountAuthorizationDetails", "AssumeRole",
        "PutUserPolicy", "CreateAccessKey",
    }
    attack = [e for e in events if e.event_name in attack_names]

    router = Router(DetectionApp(config=DetectorConfig()))
    router.app.detector.learn(benign)
    identity = benign[0].identity_key

    ANALYZE = "/api/v1/detections/credential-compromise/analyze"
    FINDINGS = "/api/v1/detections/credential-compromise/findings"

    # -- 1. A quiet (benign) event ------------------------------------------
    banner("1) POST analyze - benign event (real-time)")
    quiet = benign[-1]
    print(f">>> POST {ANALYZE}")
    print(">>> request body (excerpt):")
    body = quiet.model_dump(mode="json")
    print(json.dumps({k: body[k] for k in (
        "event_id", "timestamp", "identity_key", "event_source", "event_name",
        "source_ip", "country", "user_agent", "mfa_authenticated")}, indent=2))
    response = router.handle(Request(method="POST", path=ANALYZE, body=body))
    print(f"<<< HTTP {response.status}")
    show_response(response.body)

    # -- 2. The kill chain ---------------------------------------------------
    banner("2) POST analyze - kill chain events (real-time)")
    finding_id = None
    for event in attack:
        body = event.model_dump(mode="json")
        print(f">>> POST {ANALYZE}  ({event.event_name} from {event.country} @ {event.timestamp.hour:02d}:00, MFA={event.mfa_authenticated})")
        response = router.handle(Request(method="POST", path=ANALYZE, body=body))
        print(f"<<< HTTP {response.status}")
        show_response(
            response.body,
            drop=("finding", "signals"),  # full finding shown via endpoints below
            keep=1600,
        )
        if response.body.get("finding_id"):
            finding_id = response.body["finding_id"]

    # -- 3. Findings list ----------------------------------------------------
    banner(f"3) GET {FINDINGS}")
    response = router.handle(Request(method="GET", path=FINDINGS))
    print(f"<<< HTTP {response.status}")
    show_response(response.body, keep=2500)

    # -- 4. Identity behavior -------------------------------------------------
    banner(f"4) GET /api/v1/identities/{identity.rsplit(':', 1)[-1]}/behavior")
    response = router.handle(
        Request(method="GET", path=f"/api/v1/identities/{identity}/behavior")
    )
    print(f"<<< HTTP {response.status}")
    show_response(response.body, keep=2500)

    # -- 5. Identity timeline ---------------------------------------------------
    banner(f"5) GET /api/v1/identities/{identity.rsplit(':', 1)[-1]}/timeline")
    response = router.handle(
        Request(method="GET", path=f"/api/v1/identities/{identity}/timeline")
    )
    print(f"<<< HTTP {response.status}")
    show_response(response.body, keep=3000)

    # -- 6. Finding explanation ------------------------------------------------
    banner(f"6) GET /api/v1/findings/{finding_id}/explanation")
    response = router.handle(
        Request(method="GET", path=f"/api/v1/findings/{finding_id}/explanation")
    )
    print(f"<<< HTTP {response.status}")
    show_response(response.body, keep=5500)

    # -- 7. Safety check ---------------------------------------------------------
    banner("7) Safety: destructive routes do not exist")
    for path, method in (
        ("/api/v1/users/disable", "POST"),
        ("/api/v1/credentials/revoke", "POST"),
    ):
        response = router.handle(Request(method=method, path=path))
        print(f"{method:6s} {path}  ->  HTTP {response.status}  {response.body}")

    print("\nDemo complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
