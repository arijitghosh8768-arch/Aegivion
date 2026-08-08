import enum
from datetime import datetime
from app.database.base import BaseModel

class CloudProvider(str, enum.Enum):
    AWS = "AWS"
    AZURE = "Azure"
    GCP = "GCP"

class CloudAccountStatus(str, enum.Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    FAILED = "failed"

class CloudAccount(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = kwargs.get("name")
        self.provider = kwargs.get("provider") or CloudProvider.AWS
        self.aws_access_key_id = kwargs.get("aws_access_key_id")
        self.aws_secret_access_key = kwargs.get("aws_secret_access_key")
        self.aws_region = kwargs.get("aws_region") or "ap-south-1"
        self.status = kwargs.get("status") or CloudAccountStatus.CONNECTED
        self.last_scan_at = kwargs.get("last_scan_at")
        self.organization_id = kwargs.get("organization_id")

    def dict(self):
        res = super().dict()
        res.update({
            "name": self.name,
            "provider": self.provider,
            "aws_access_key_id": self.aws_access_key_id,
            "aws_secret_access_key": self.aws_secret_access_key,
            "aws_region": self.aws_region,
            "status": self.status,
            "last_scan_at": self.last_scan_at.isoformat() if isinstance(self.last_scan_at, datetime) else self.last_scan_at,
            "organization_id": str(self.organization_id) if self.organization_id else None
        })
        return res

class CloudAsset(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.account_id = kwargs.get("account_id")
        self.resource_id = kwargs.get("resource_id")
        self.name = kwargs.get("name")
        self.type = kwargs.get("type")
        self.region = kwargs.get("region")
        self.provider = kwargs.get("provider") or CloudProvider.AWS
        self.metadata_json = kwargs.get("metadata_json") or {}
        
        # M1 Day 32 Criticality Context Fields
        self.environment = kwargs.get("environment") or "DEVELOPMENT"
        self.owner = kwargs.get("owner") or "UNKNOWN"
        self.department = kwargs.get("department") or "UNKNOWN"
        self.application = kwargs.get("application") or "UNKNOWN"
        self.data_sensitivity = kwargs.get("data_sensitivity") or "UNKNOWN"
        self.business_criticality = kwargs.get("business_criticality") or "UNKNOWN"

    def dict(self):
        res = super().dict()
        res.update({
            "account_id": str(self.account_id) if self.account_id else None,
            "resource_id": self.resource_id,
            "name": self.name,
            "type": self.type,
            "region": self.region,
            "provider": self.provider,
            "metadata_json": self.metadata_json,
            "environment": self.environment,
            "owner": self.owner,
            "department": self.department,
            "application": self.application,
            "data_sensitivity": self.data_sensitivity,
            "business_criticality": self.business_criticality
        })
        return res

class SecurityGroupAsset(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.asset_id = kwargs.get("asset_id")
        self.group_id = kwargs.get("group_id")
        self.group_name = kwargs.get("group_name")
        self.vpc_id = kwargs.get("vpc_id")
        self.ingress_rules = kwargs.get("ingress_rules") or []
        self.egress_rules = kwargs.get("egress_rules") or []

    def dict(self):
        res = super().dict()
        res.update({
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "group_id": self.group_id,
            "group_name": self.group_name,
            "vpc_id": self.vpc_id,
            "ingress_rules": self.ingress_rules,
            "egress_rules": self.egress_rules
        })
        return res

class IAMUserAsset(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.asset_id = kwargs.get("asset_id")
        self.username = kwargs.get("username")
        self.arn = kwargs.get("arn")
        self.mfa_enabled = kwargs.get("mfa_enabled", False)
        self.is_admin = kwargs.get("is_admin", False)
        self.access_keys_age_days = kwargs.get("access_keys_age_days")
        self.last_active = kwargs.get("last_active")

    def dict(self):
        res = super().dict()
        res.update({
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "username": self.username,
            "arn": self.arn,
            "mfa_enabled": self.mfa_enabled,
            "is_admin": self.is_admin,
            "access_keys_age_days": self.access_keys_age_days,
            "last_active": self.last_active.isoformat() if isinstance(self.last_active, datetime) else self.last_active
        })
        return res

class S3BucketAsset(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.asset_id = kwargs.get("asset_id")
        self.bucket_name = kwargs.get("bucket_name")
        self.arn = kwargs.get("arn")
        self.is_public = kwargs.get("is_public", False)
        self.encryption_enabled = kwargs.get("encryption_enabled", True)
        self.versioning_enabled = kwargs.get("versioning_enabled", False)

    def dict(self):
        res = super().dict()
        res.update({
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "bucket_name": self.bucket_name,
            "arn": self.arn,
            "is_public": self.is_public,
            "encryption_enabled": self.encryption_enabled,
            "versioning_enabled": self.versioning_enabled
        })
        return res

class EC2InstanceAsset(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.asset_id = kwargs.get("asset_id")
        self.instance_id = kwargs.get("instance_id")
        self.state = kwargs.get("state")
        self.public_ip = kwargs.get("public_ip")
        self.private_ip = kwargs.get("private_ip")
        self.instance_type = kwargs.get("instance_type")
        self.security_groups = kwargs.get("security_groups") or []
        self.has_public_ip = kwargs.get("has_public_ip", False)

    def dict(self):
        res = super().dict()
        res.update({
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "instance_id": self.instance_id,
            "state": self.state,
            "public_ip": self.public_ip,
            "private_ip": self.private_ip,
            "instance_type": self.instance_type,
            "security_groups": self.security_groups,
            "has_public_ip": self.has_public_ip
        })
        return res

class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanJob(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.organization_id = kwargs.get("organization_id")
        self.status = kwargs.get("status") or ScanStatus.QUEUED
        self.started_at = kwargs.get("started_at")
        self.completed_at = kwargs.get("completed_at")
        self.assets_discovered = kwargs.get("assets_discovered") or 0
        self.findings_generated = kwargs.get("findings_generated") or 0
        self.collector_status = kwargs.get("collector_status") or {}
        self.error_summary = kwargs.get("error_summary")
        self.region = kwargs.get("region")

    def dict(self):
        res = super().dict()
        res.update({
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "status": self.status,
            "started_at": self.started_at.isoformat() if isinstance(self.started_at, datetime) else self.started_at,
            "completed_at": self.completed_at.isoformat() if isinstance(self.completed_at, datetime) else self.completed_at,
            "assets_discovered": self.assets_discovered,
            "findings_generated": self.findings_generated,
            "collector_status": self.collector_status,
            "error_summary": self.error_summary,
            "region": self.region
        })
        return res

class Relationship(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.source_id = kwargs.get("source_id")
        self.target_id = kwargs.get("target_id")
        self.type = kwargs.get("type")
        self.target_type = kwargs.get("target_type")

    def dict(self):
        res = super().dict()
        res.update({
            "source_id": self.source_id,
            "target_id": self.target_id,
            "type": self.type,
            "target_type": self.target_type
        })
        return res

class AssetRelationship(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.source_asset_id = kwargs.get("source_asset_id")
        self.target_asset_id = kwargs.get("target_asset_id")
        self.relationship_type = kwargs.get("relationship_type")
        self.account_id = kwargs.get("account_id")
        self.region = kwargs.get("region")
        self.evidence = kwargs.get("evidence") or {}
        self.confidence = kwargs.get("confidence") or "UNKNOWN"
        self.first_seen_at = kwargs.get("first_seen_at") or datetime.utcnow()
        self.last_seen_at = kwargs.get("last_seen_at") or datetime.utcnow()

    def dict(self):
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "relationship_type": self.relationship_type,
            "account_id": self.account_id,
            "region": self.region,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "first_seen_at": self.first_seen_at.isoformat() if isinstance(self.first_seen_at, datetime) else self.first_seen_at,
            "last_seen_at": self.last_seen_at.isoformat() if isinstance(self.last_seen_at, datetime) else self.last_seen_at,
        })
        return res

