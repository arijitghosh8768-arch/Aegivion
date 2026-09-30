"""CloudTrail records exercising robustness to MISSING telemetry fields.

The detector must tolerate real-world sparsity: producers omit fields,
forwarders drop payloads, field extraction rules change. Every record here
normalizes successfully with the missing slots marked unavailable.
"""

from __future__ import annotations

from .cloudtrail_records import NORM

# Source IP missing (internal forwarded event).
MISSING_SOURCE_IP = {
    **NORM,
    "eventID": "cccccccc-0000-4000-8000-000000000001",
    "eventName": "GetObject",
    "requestParameters": {"bucketName": "prod-customer-data", "key": "x.csv"},
}
MISSING_SOURCE_IP["sourceIPAddress"] = None

# additionalEventData entirely absent -> bytes stay unavailable.
MISSING_BYTES = {
    **NORM,
    "eventID": "cccccccc-0000-4000-8000-000000000002",
    "eventName": "GetObject",
    "requestParameters": {"bucketName": "prod-customer-data", "key": "y.csv"},
    "additionalEventData": None,
}

# User agent missing.
MISSING_USER_AGENT = {
    **NORM,
    "eventID": "cccccccc-0000-4000-8000-000000000003",
    "eventName": "GetObject",
    "requestParameters": {"bucketName": "prod-customer-data", "key": "z.csv"},
}
MISSING_USER_AGENT["userAgent"] = None

# No additionalEventData AND no userAgent (sparse producer).
MISSING_SEVERAL = {
    **NORM,
    "eventID": "cccccccc-0000-4000-8000-000000000004",
    "eventName": "ListObjectsV2",
    "requestParameters": {"bucketName": "prod-customer-data", "prefix": "exports/"},
    "additionalEventData": None,
}
MISSING_SEVERAL["userAgent"] = None
MISSING_SEVERAL["sourceIPAddress"] = None

ALL: list[dict] = [
    MISSING_SOURCE_IP,
    MISSING_BYTES,
    MISSING_USER_AGENT,
    MISSING_SEVERAL,
]
