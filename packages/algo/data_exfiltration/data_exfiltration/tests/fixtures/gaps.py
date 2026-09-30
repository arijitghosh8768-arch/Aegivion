"""CloudTrail records documenting KNOWN capability gaps.

Each record here is *not* fully normalized today and why. These are not
failures — they are honest boundaries of the current foundation. The
normalizer accepts them, fills what it can, and marks the rest
unavailable so downstream analysis can reason about missing evidence.
"""

from __future__ import annotations

from .cloudtrail_records import NORM

# GAP-01: We do not yet resolve AWS account aliases, so account_id stays the
# 12-digit id and no human-friendly name is attached.
GAP_ACCOUNT_ALIAS = {
    **NORM,
    "eventID": "aaaaaaaa-0000-4000-8000-000000000001",
    "eventName": "GetObject",
    "requestParameters": {"bucketName": "prod-customer-data", "key": "a.csv"},
}

# GAP-02: Resource ARNs are derived from request parameters only. When the
# service encodes the resource elsewhere (e.g. Lambda invoke-arn) we do not
# reconstruct it and resource_arn stays unavailable.
GAP_RESOURCE_ARN = {
    **NORM,
    "eventID": "aaaaaaaa-0000-4000-8000-000000000002",
    "eventName": "GetObject",
    "requestParameters": {"bucketName": "prod-customer-data", "key": "b.csv"},
}

# GAP-03: We do not yet join awsAccountId -> organization business unit, so
# DataResourceProfile.owner/business_unit are not auto-populated.
GAP_BUSINESS_UNIT = {
    **NORM,
    "eventID": "aaaaaaaa-0000-4000-8000-000000000003",
    "eventName": "GetObject",
    "requestParameters": {"bucketName": "prod-customer-data", "key": "c.csv"},
}

# GAP-04: awsRegion is optional in CloudTrail records; when absent we keep
# region unavailable rather than guessing the partition default.
GAP_NO_REGION = {
    **NORM,
    "eventID": "aaaaaaaa-0000-4000-8000-000000000004",
    "eventName": "GetObject",
    "requestParameters": {"bucketName": "prod-customer-data", "key": "d.csv"},
}
GAP_NO_REGION.pop("awsRegion")

GAPS: dict[str, dict] = {
    "GAP-01 account aliases unresolved": GAP_ACCOUNT_ALIAS,
    "GAP-02 arn not reconstructed for all services": GAP_RESOURCE_ARN,
    "GAP-03 owner/business_unit not auto-populated": GAP_BUSINESS_UNIT,
    "GAP-04 missing awsRegion kept unavailable": GAP_NO_REGION,
}
