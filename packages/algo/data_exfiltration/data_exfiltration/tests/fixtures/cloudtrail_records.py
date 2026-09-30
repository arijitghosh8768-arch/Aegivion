"""Canonical AWS CloudTrail record fixtures for the exfiltration detector.

These are records we *accept* today. Records for capability gaps are kept
separately in gaps.py so the accepted-set is never polluted by aspirational
schema fields.
"""

from __future__ import annotations

BASE = "2010-08-01"
S3_HOST = "s3.us-east-1.amazonaws.com"

NORM = {
    "eventVersion": "1.09",
    "eventSource": "s3.amazonaws.com",
    "eventTime": "2024-11-14T03:00:00Z",
    "awsRegion": "us-east-1",
    "eventID": "11111111-1111-4111-8111-111111111111",
    "eventType": "AwsApiCall",
    "recipientAccountId": "111122223333",
    "sourceIPAddress": "203.0.113.10",
    "userAgent": "aws-sdk-python/1.34.0",
    "principalId": "AIDAAAAAAAAAAAAAAAAAA",
    "arn": "arn:aws:iam::111122223333:user/dev-user",
    "account": "111122223333",
    "type": "IAMUser",
    "invokedBy": None,
}

S3_GET = {
    **NORM,
    "eventName": "GetObject",
    "requestParameters": {"bucketName": "prod-customer-data", "key": "exports/customers-2024.csv"},
    "responseElements": None,
    "additionalEventData": {"bytesTransferredOut": 10485760, "AuthenticationMethod": "SigV4"},
}

S3_PUT = {
    **NORM,
    "eventName": "PutObject",
    "requestParameters": {
        "bucketName": "prod-customer-data",
        "key": "exports/customers-2024.csv",
        "User-Agent": None,
    },
    "additionalEventData": {"bytesTransferredIn": 2048},
}

S3_LIST = {
    **NORM,
    "eventName": "ListObjectsV2",
    "requestParameters": {"bucketName": "prod-customer-data", "maxResults": 1000, "prefix": "exports/"},
    "responseElements": {"isTruncated": "true"},
    "additionalEventData": None,
}

S3_COPY = {
    **NORM,
    "eventName": "CopyObject",
    "requestParameters": {
        "bucketName": "attacker-staging",
        "key": "stolen/customers-2024.csv",
        "x-amz-copy-source": "prod-customer-data/exports/customers-2024.csv",
    },
    "additionalEventData": {"bytesTransferredOut": 10485760},
}

ASSUMED_ROLE_NORM = {
    **NORM,
    "arn": "arn:aws:sts::111122223333:assumed-role/BackupOperator/backup-job-42",
    "type": "AssumedRole",
    "principalId": "AROAAAAAAAAAAAAAAAAA:backup-job-42",
}

S3_GET_ROLE = {
    **ASSUMED_ROLE_NORM,
    "eventName": "GetObject",
    "requestParameters": {"bucketName": "backups-prod", "key": "nightly/db-snapshot.tar.gz"},
    "additionalEventData": {"bytesTransferredOut": 5368709120},
}

S3_ERROR = {
    **NORM,
    "eventName": "GetObject",
    "errorCode": "AccessDenied",
    "errorMessage": "Access Denied",
    "requestParameters": {"bucketName": "hr-records", "key": "salaries.xlsx"},
    "additionalEventData": None,
}

S3_UNAUTH = {
    **NORM,
    "eventName": "GetObject",
    "userIdentity": {
        "type": "Unidentified",
        "principalId": None,
        "arn": None,
        "accountId": None,
    },
    "requestParameters": {"bucketName": "public-site", "key": "index.html"},
    "additionalEventData": {"bytesTransferredOut": 2048},
}

S3_DIFF_REGION = {
    **NORM,
    "awsRegion": "eu-west-1",
    "eventID": "22222222-2222-4222-8222-222222222222",
    "eventTime": "2024-11-14T03:05:00Z",
    "eventName": "GetObject",
    "requestParameters": {"bucketName": "eu-analytics", "key": "telemetry/2024-11-13.parquet"},
    "additionalEventData": {"bytesTransferredOut": 5242880},
}

DDB_QUERY = {
    **NORM,
    "eventSource": "dynamodb.amazonaws.com",
    "eventID": "33333333-3333-4333-8333-333333333333",
    "eventName": "GetItem",
    "requestParameters": {"tableName": "CustomerProfiles", "key": {"customerId": {"S": "C-1001"}}},
    "additionalEventData": {"bytesTransferredOut": 4096},
}
