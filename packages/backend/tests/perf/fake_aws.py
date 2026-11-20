"""Deterministic fake AWS clients for scan performance benchmarks and regression tests.

These fakes emulate the boto3 surface used by the Aegivion AWS collectors:

* paginated calls (``get_paginator(...).paginate()``)
* per-resource calls (S3 bucket config, IAM user metadata, VPC route tables)
* ``ClientError`` responses for unsupported / missing configuration

Every API request increments a counter (per service and operation) and can
optionally sleep to model network round-trip latency, which lets the benchmark
distinguish *simulated* AWS latency from real measurements.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

ACCOUNT_ID = "111122223333"


def _client_error(code: str, operation: str, message: str = "") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message or code}},
        operation,
    )


class FakeAWS:
    """Shared state: fixtures, latency injection and API call accounting."""

    def __init__(
        self,
        latency: float = 0.0,
        buckets: int = 120,
        iam_users: int = 40,
        iam_roles: int = 25,
        iam_groups: int = 10,
        iam_policies: int = 15,
        ec2_instances: int = 80,
        security_groups: int = 60,
        vpcs: int = 12,
        subnets: int = 40,
        rds_instances: int = 6,
        page_size: int = 50,
    ):
        self.latency = latency
        self.page_size = page_size
        self._lock = threading.Lock()
        self.calls: Dict[str, int] = defaultdict(int)
        self.call_log: List[str] = []

        self._build_fixtures(
            buckets=buckets,
            iam_users=iam_users,
            iam_roles=iam_roles,
            iam_groups=iam_groups,
            iam_policies=iam_policies,
            ec2_instances=ec2_instances,
            security_groups=security_groups,
            vpcs=vpcs,
            subnets=subnets,
            rds_instances=rds_instances,
        )

    # ------------------------------------------------------------------ utils
    def _build_fixtures(self, **sizes: int) -> None:
        self.buckets = [
            {
                "Name": f"bench-bucket-{i:03d}",
                "CreationDate": __import__("datetime").datetime(2024, 1, 1),
            }
            for i in range(sizes["buckets"])
        ]
        # Every 7th bucket keeps every hardening control, the rest are "soft".
        self.bucket_public = {b["Name"] for i, b in enumerate(self.buckets) if i % 7 == 0}

        self.iam_users = [
            {
                "UserName": f"bench-user-{i:02d}",
                "UserId": f"AIDA{i:012d}",
                "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/bench-user-{i:02d}",
                "CreateDate": __import__("datetime").datetime(2023, 1, 1),
                "PasswordLastUsed": None,
            }
            for i in range(sizes["iam_users"])
        ]
        self.iam_roles = [
            {
                "RoleName": f"bench-role-{i:02d}",
                "RoleId": f"AROA{i:012d}",
                "Arn": f"arn:aws:iam::{ACCOUNT_ID}:role/bench-role-{i:02d}",
                "CreateDate": __import__("datetime").datetime(2023, 1, 1),
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
            }
            for i in range(sizes["iam_roles"])
        ]
        self.iam_groups = [
            {
                "GroupName": f"bench-group-{i:02d}",
                "GroupId": f"AGPA{i:012d}",
                "Arn": f"arn:aws:iam::{ACCOUNT_ID}:group/bench-group-{i:02d}",
                "CreateDate": __import__("datetime").datetime(2023, 1, 1),
            }
            for i in range(sizes["iam_groups"])
        ]
        self.iam_policies = [
            {
                "PolicyName": f"bench-policy-{i:02d}",
                "PolicyId": f"ANPA{i:012d}",
                "Arn": f"arn:aws:iam::{ACCOUNT_ID}:policy/bench-policy-{i:02d}",
                "CreateDate": __import__("datetime").datetime(2023, 1, 1),
                "DefaultVersionId": "v1",
                "AttachmentCount": 1,
            }
            for i in range(sizes["iam_policies"])
        ]

        self.vpcs = [
            {"VpcId": f"vpc-{i:017d}", "CidrBlock": f"10.{i}.0.0/16", "State": "available", "IsDefault": i == 0}
            for i in range(sizes["vpcs"])
        ]
        self.subnets = [
            {
                "SubnetId": f"subnet-{i:017d}",
                "VpcId": self.vpcs[i % len(self.vpcs)]["VpcId"],
                "CidrBlock": f"10.{i % len(self.vpcs)}.{i}.0/24",
                "AvailableIpAddressCount": 240,
                "MapPublicIpOnLaunch": i % 3 == 0,
            }
            for i in range(sizes["subnets"])
        ]
        # Route tables: one explicit table per subnet (2/3 of them) plus one main
        # table per VPC. Public main tables route to an internet gateway.
        self.route_tables: List[Dict[str, Any]] = []
        for vpc in self.vpcs:
            self.route_tables.append(
                {
                    "RouteTableId": f"rtb-main-{vpc['VpcId'].split('-')[-1][-4:]}",
                    "VpcId": vpc["VpcId"],
                    "Associations": [{"Main": True, "AssociationState": {"State": "associated"}}],
                    "Routes": [{"GatewayId": "igw-bench" if vpc["IsDefault"] else "local"}],
                }
            )
        for idx, subnet in enumerate(self.subnets):
            if idx % 3 == 2:
                continue
            self.route_tables.append(
                {
                    "RouteTableId": f"rtb-sub-{idx:04d}",
                    "VpcId": subnet["VpcId"],
                    "Associations": [
                        {
                            "SubnetId": subnet["SubnetId"],
                            "Main": False,
                            "AssociationState": {"State": "associated"},
                        }
                    ],
                    "Routes": [{"GatewayId": "igw-bench" if idx % 2 == 0 else "local"}],
                }
            )

        self.security_groups = [
            {
                "GroupId": f"sg-{i:017d}",
                "GroupName": f"bench-sg-{i:02d}",
                "Description": "bench",
                "VpcId": self.vpcs[i % len(self.vpcs)]["VpcId"],
                "OwnerId": ACCOUNT_ID,
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22 if i % 4 == 0 else 443,
                        "ToPort": 22 if i % 4 == 0 else 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0" if i % 4 == 0 else "10.0.0.0/8"}],
                    }
                ],
                "IpPermissionsEgress": [
                    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            }
            for i in range(sizes["security_groups"])
        ]

        self.ec2_instances = [
            {
                "InstanceId": f"i-{i:017d}",
                "InstanceType": "t3.micro",
                "State": {"Name": "running"},
                "PublicIpAddress": f"203.0.113.{i % 250}" if i % 5 == 0 else None,
                "PrivateIpAddress": f"10.0.{i % 250}.10",
                "VpcId": self.vpcs[i % len(self.vpcs)]["VpcId"],
                "SubnetId": self.subnets[i % len(self.subnets)]["SubnetId"],
                "SecurityGroups": [
                    {"GroupId": self.security_groups[i % len(self.security_groups)]["GroupId"], "GroupName": "bench"}
                ],
                "Tags": [{"Key": "Name", "Value": f"bench-ec2-{i:03d}"}],
                "BlockDeviceMappings": [],
                "Placement": {"AvailabilityZone": "ap-south-1a"},
                "LaunchTime": __import__("datetime").datetime(2023, 6, 1),
            }
            for i in range(sizes["ec2_instances"])
        ]

        self.rds_instances = [
            {
                "DBInstanceIdentifier": f"bench-db-{i:02d}",
                "DBInstanceArn": f"arn:aws:rds:ap-south-1:{ACCOUNT_ID}:db:bench-db-{i:02d}",
                "Engine": "postgres",
                "EngineVersion": "15.4",
                "DBInstanceClass": "db.t3.micro",
                "DBInstanceStatus": "available",
                "MasterUsername": "aegivion",
                "AllocatedStorage": 20,
                "StorageType": "gp3",
                "StorageEncrypted": i % 2 == 0,
                "MultiAZ": False,
                "PubliclyAccessible": i % 5 == 0,
                "AutoMinorVersionUpgrade": True,
                "BackupRetentionPeriod": 7,
                "Endpoint": {"Address": f"bench-db-{i:02d}.example", "Port": 5432},
                "DBSubnetGroup": {
                    "VpcId": self.vpcs[i % len(self.vpcs)]["VpcId"],
                    "Subnets": [{"SubnetIdentifier": self.subnets[i % len(self.subnets)]["SubnetId"]}],
                },
                "VpcSecurityGroups": [
                    {"VpcSecurityGroupId": self.security_groups[i % len(self.security_groups)]["GroupId"], "Status": "active"}
                ],
                "DeletionProtection": True,
                "MonitoringInterval": 0,
                "TagList": [],
            }
            for i in range(sizes["rds_instances"])
        ]

    def record(self, service: str, operation: str) -> None:
        with self._lock:
            self.calls[f"{service}:{operation}"] += 1
            self.call_log.append(f"{service}:{operation}")
        if self.latency:
            time.sleep(self.latency)

    def calls_for(self, service: str) -> int:
        return sum(count for op, count in self.calls.items() if op.startswith(f"{service}:"))

    def calls_for_op(self, operation: str) -> int:
        return self.calls.get(operation, 0)

    @property
    def total_calls(self) -> int:
        return sum(self.calls.values())

    def reset_counters(self) -> None:
        with self._lock:
            self.calls.clear()
            self.call_log.clear()

    # boto3.Session surface used by the collectors
    def client(self, service: str, region_name: Optional[str] = None, **_: Any) -> "FakeClient":
        return FakeClient(self, service)

    @property
    def region_name(self) -> str:
        return "ap-south-1"


class FakePaginator:
    def __init__(self, aws: FakeAWS, service: str, operation: str, pages: List[Dict[str, Any]]):
        self.aws = aws
        self.service = service
        self.operation = operation
        self.pages = pages

    def paginate(self, **_: Any):
        for page in self.pages:
            self.aws.record(self.service, self.operation)
            yield page


class FakeClient:
    """Minimal boto3 client emulation for the services the scan touches."""

    def __init__(self, aws: FakeAWS, service: str):
        self.aws = aws
        self.service = service

    # ---------------------------------------------------------------- generic
    def get_paginator(self, operation: str) -> FakePaginator:
        return FakePaginator(self.aws, self.service, operation, self._pages(operation))

    def _pages(self, operation: str) -> List[Dict[str, Any]]:
        if operation == "describe_instances":
            chunks = _chunk(self.aws.ec2_instances, self.aws.page_size)
            return [{"Reservations": [{"Instances": chunk} for chunk in chunks]}]
        if operation == "describe_security_groups":
            return [{"SecurityGroups": chunk} for chunk in _chunk(self.aws.security_groups, self.aws.page_size)]
        if operation == "list_users":
            return [{"Users": chunk} for chunk in _chunk(self.aws.iam_users, self.aws.page_size)]
        if operation == "list_roles":
            return [{"Roles": chunk} for chunk in _chunk(self.aws.iam_roles, self.aws.page_size)]
        if operation == "list_groups":
            return [{"Groups": chunk} for chunk in _chunk(self.aws.iam_groups, self.aws.page_size)]
        if operation == "list_policies":
            return [{"Policies": chunk} for chunk in _chunk(self.aws.iam_policies, 10)]
        if operation == "describe_db_instances":
            return [{"DBInstances": chunk} for chunk in _chunk(self.aws.rds_instances, self.aws.page_size)]
        raise NotImplementedError(f"paginator {self.service}:{operation}")

    # --------------------------------------------------------------------- sts
    def get_caller_identity(self) -> Dict[str, Any]:
        self.aws.record("sts", "GetCallerIdentity")
        return {"Account": ACCOUNT_ID, "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/bench", "UserId": "AIDA"}

    # --------------------------------------------------------------------- s3
    def list_buckets(self) -> Dict[str, Any]:
        self.aws.record("s3", "ListBuckets")
        return {"Buckets": self.aws.buckets}

    def get_bucket_location(self, Bucket: str) -> Dict[str, Any]:
        self.aws.record("s3", "GetBucketLocation")
        return {"LocationConstraint": "ap-south-1"}

    def get_public_access_block(self, Bucket: str) -> Dict[str, Any]:
        self.aws.record("s3", "GetPublicAccessBlock")
        if Bucket in self.aws.bucket_public:
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            }
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_encryption(self, Bucket: str) -> Dict[str, Any]:
        self.aws.record("s3", "GetBucketEncryption")
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

    def get_bucket_versioning(self, Bucket: str) -> Dict[str, Any]:
        self.aws.record("s3", "GetBucketVersioning")
        return {"Status": "Enabled" if Bucket in self.aws.bucket_public else "Suspended"}

    def get_bucket_logging(self, Bucket: str) -> Dict[str, Any]:
        self.aws.record("s3", "GetBucketLogging")
        if Bucket in self.aws.bucket_public:
            return {}
        return {"LoggingEnabled": {"TargetBucket": "logs", "TargetPrefix": "s3/"}}

    def get_bucket_policy(self, Bucket: str) -> Dict[str, Any]:
        self.aws.record("s3", "GetBucketPolicy")
        if Bucket in self.aws.bucket_public:
            raise _client_error("NoSuchBucketPolicy", "GetBucketPolicy")
        return {
            "Policy": (
                '{"Version":"2012-10-17","Statement":[{"Effect":"Deny",'
                '"Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::x/*"}]}'
            )
        }

    def get_bucket_acl(self, Bucket: str) -> Dict[str, Any]:
        self.aws.record("s3", "GetBucketAcl")
        grants = [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]
        return {"Grants": grants if Bucket in self.aws.bucket_public else []}

    def get_bucket_tagging(self, Bucket: str) -> Dict[str, Any]:
        self.aws.record("s3", "GetBucketTagging")
        return {"TagSet": [{"Key": "Environment", "Value": "bench"}]}

    # -------------------------------------------------------------------- iam
    def list_mfa_devices(self, UserName: str) -> Dict[str, Any]:
        self.aws.record("iam", "ListMFADevices")
        return {"MFADevices": [] if UserName.endswith("0") else [{"SerialNumber": "arn:mfa"}]}

    def get_login_profile(self, UserName: str) -> Dict[str, Any]:
        self.aws.record("iam", "GetLoginProfile")
        if UserName.endswith("1"):
            raise _client_error("NoSuchEntity", "GetLoginProfile")
        return {"LoginProfile": {"UserName": UserName}}

    def list_groups_for_user(self, UserName: str) -> Dict[str, Any]:
        self.aws.record("iam", "ListGroupsForUser")
        return {"Groups": [{"GroupName": self.aws.iam_groups[0]["GroupName"]}]}

    def list_attached_user_policies(self, UserName: str) -> Dict[str, Any]:
        self.aws.record("iam", "ListAttachedUserPolicies")
        return {
            "AttachedPolicies": [
                {"PolicyArn": f"arn:aws:iam::aws:policy/AdministratorAccess", "PolicyName": "AdministratorAccess"}
            ]
        }

    def list_user_policies(self, UserName: str) -> Dict[str, Any]:
        self.aws.record("iam", "ListUserPolicies")
        return {"PolicyNames": []}

    def list_access_keys(self, UserName: str) -> Dict[str, Any]:
        self.aws.record("iam", "ListAccessKeys")
        return {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": f"AKIA{UserName[-4:]}0001",
                    "Status": "Active",
                    "CreateDate": __import__("datetime").datetime(2023, 1, 1),
                }
            ]
        }

    def get_access_key_last_used(self, AccessKeyId: str) -> Dict[str, Any]:
        self.aws.record("iam", "GetAccessKeyLastUsed")
        return {"AccessKeyLastUsed": {"LastUsedDate": __import__("datetime").datetime(2024, 1, 1), "ServiceName": "s3", "Region": "ap-south-1"}}

    def list_attached_role_policies(self, RoleName: str) -> Dict[str, Any]:
        self.aws.record("iam", "ListAttachedRolePolicies")
        return {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "PolicyName": "ReadOnlyAccess"}]}

    def list_role_policies(self, RoleName: str) -> Dict[str, Any]:
        self.aws.record("iam", "ListRolePolicies")
        return {"PolicyNames": []}

    def list_attached_group_policies(self, GroupName: str) -> Dict[str, Any]:
        self.aws.record("iam", "ListAttachedGroupPolicies")
        return {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "PolicyName": "ReadOnlyAccess"}]}

    def get_policy_version(self, PolicyArn: str, VersionId: str) -> Dict[str, Any]:
        self.aws.record("iam", "GetPolicyVersion")
        return {
            "PolicyVersion": {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bench-bucket-000/*"}
                    ],
                }
            }
        }

    # -------------------------------------------------------------------- ec2
    def describe_vpcs(self) -> Dict[str, Any]:
        self.aws.record("ec2", "DescribeVpcs")
        return {"Vpcs": self.aws.vpcs}

    def describe_subnets(self) -> Dict[str, Any]:
        self.aws.record("ec2", "DescribeSubnets")
        return {"Subnets": self.aws.subnets}

    def describe_route_tables(self, Filters: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        self.aws.record("ec2", "DescribeRouteTables")
        filters = {f["Name"]: f["Values"] for f in (Filters or [])}

        tables = self.aws.route_tables
        if "association.subnet-id" in filters:
            wanted = set(filters["association.subnet-id"])
            tables = [t for t in tables if any(a.get("SubnetId") in wanted for a in t.get("Associations", []))]
        if "vpc-id" in filters:
            wanted = set(filters["vpc-id"])
            tables = [t for t in tables if t["VpcId"] in wanted]
        if "association.main" in filters and "true" in filters["association.main"]:
            tables = [t for t in tables if any(a.get("Main") for a in t.get("Associations", []))]
        return {"RouteTables": tables}

    def describe_internet_gateways(self, Filters: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        self.aws.record("ec2", "DescribeInternetGateways")
        return {"InternetGateways": [{"InternetGatewayId": "igw-bench"}]}

    def describe_nat_gateways(self, Filters: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        self.aws.record("ec2", "DescribeNatGateways")
        return {"NatGateways": [{"NatGatewayId": "nat-bench"}]}


def _chunk(items: List[Any], size: int) -> List[List[Any]]:
    if size <= 0:
        return [items]
    return [items[i : i + size] for i in range(0, len(items), size)] or [[]]
