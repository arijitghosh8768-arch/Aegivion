import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, JSON, Integer, Float
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel
from app.core.database_types import EncryptedString

class CloudProvider(str, enum.Enum):
    AWS = "AWS"
    AZURE = "Azure"
    GCP = "GCP"

class CloudAccountStatus(str, enum.Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    FAILED = "failed"

class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class CloudAccount(BaseModel):
    __tablename__ = "cloud_accounts"

    name = Column(String(200), nullable=False)
    provider = Column(String(50), nullable=False, default="AWS")
    aws_access_key_id = Column(String(100), nullable=True)
    aws_secret_access_key = Column(EncryptedString(500), nullable=True)
    aws_region = Column(String(50), nullable=True, default="ap-south-1")
    role_arn = Column(String(300), nullable=True)
    external_id = Column(EncryptedString(500), nullable=True)
    status = Column(String(50), default="connected")
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = kwargs.get("name")
        self.provider = kwargs.get("provider") or CloudProvider.AWS.value
        self.aws_access_key_id = kwargs.get("aws_access_key_id")
        self.aws_secret_access_key = kwargs.get("aws_secret_access_key")
        self.aws_region = kwargs.get("aws_region") or "ap-south-1"
        self.role_arn = kwargs.get("role_arn")
        self.external_id = kwargs.get("external_id")
        self.status = kwargs.get("status") or CloudAccountStatus.CONNECTED.value
        self.last_scan_at = kwargs.get("last_scan_at")
        self.organization_id = kwargs.get("organization_id")

class CloudAsset(BaseModel):
    __tablename__ = "cloud_assets"

    account_id = Column(UUID(as_uuid=True), ForeignKey("cloud_accounts_v2.id", ondelete="CASCADE"), nullable=True, index=True)
    resource_id = Column(String(300), nullable=False, index=True)
    name = Column(String(300), nullable=False)
    type = Column(String(100), nullable=False, index=True)
    region = Column(String(100), nullable=True)
    provider = Column(String(50), nullable=False, default="AWS")
    metadata_json = Column(JSON, default=dict)

    # Criticality & Context
    environment = Column(String(50), default="DEVELOPMENT")
    owner = Column(String(100), default="UNKNOWN")
    department = Column(String(100), default="UNKNOWN")
    application = Column(String(100), default="UNKNOWN")
    data_classification = Column(String(50), default="UNKNOWN")
    business_criticality = Column(String(50), default="UNKNOWN")
    internet_exposed = Column(Boolean, default=False)
    importance_score = Column(Float, default=0.0)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    current_hash = Column(String(64), nullable=True)

    # Relationships
    security_group_details = relationship("SecurityGroupAsset", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    iam_user_details = relationship("IAMUserAsset", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    s3_bucket_details = relationship("S3BucketAsset", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    ec2_instance_details = relationship("EC2InstanceAsset", back_populates="asset", uselist=False, cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.account_id = kwargs.get("account_id")
        self.resource_id = kwargs.get("resource_id")
        self.name = kwargs.get("name")
        self.type = kwargs.get("type")
        self.region = kwargs.get("region")
        self.provider = kwargs.get("provider") or CloudProvider.AWS.value
        self.metadata_json = kwargs.get("metadata_json") or {}
        self.environment = kwargs.get("environment") or "DEVELOPMENT"
        self.owner = kwargs.get("owner") or "UNKNOWN"
        self.department = kwargs.get("department") or "UNKNOWN"
        self.application = kwargs.get("application") or "UNKNOWN"
        self.data_classification = kwargs.get("data_classification") or "UNKNOWN"
        self.business_criticality = kwargs.get("business_criticality") or "UNKNOWN"
        self.internet_exposed = kwargs.get("internet_exposed", False)
        self.importance_score = kwargs.get("importance_score", 0.0)

class SecurityGroupAsset(BaseModel):
    __tablename__ = "security_groups"

    asset_id = Column(UUID(as_uuid=True), ForeignKey("cloud_assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    group_id = Column(String(100), nullable=False)
    group_name = Column(String(200), nullable=False)
    vpc_id = Column(String(100), nullable=True)
    ingress_rules = Column(JSON, default=list)
    egress_rules = Column(JSON, default=list)

    asset = relationship("CloudAsset", back_populates="security_group_details")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.asset_id = kwargs.get("asset_id")
        self.group_id = kwargs.get("group_id")
        self.group_name = kwargs.get("group_name")
        self.vpc_id = kwargs.get("vpc_id")
        self.ingress_rules = kwargs.get("ingress_rules") or []
        self.egress_rules = kwargs.get("egress_rules") or []

class IAMUserAsset(BaseModel):
    __tablename__ = "iam_users"

    asset_id = Column(UUID(as_uuid=True), ForeignKey("cloud_assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    username = Column(String(200), nullable=False)
    arn = Column(String(300), nullable=False)
    mfa_enabled = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    access_keys_age_days = Column(Integer, default=0)
    last_active = Column(DateTime(timezone=True), nullable=True)

    asset = relationship("CloudAsset", back_populates="iam_user_details")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.asset_id = kwargs.get("asset_id")
        self.username = kwargs.get("username")
        self.arn = kwargs.get("arn")
        self.mfa_enabled = kwargs.get("mfa_enabled", False)
        self.is_admin = kwargs.get("is_admin", False)
        self.access_keys_age_days = kwargs.get("access_keys_age_days") or 0
        self.last_active = kwargs.get("last_active")

class S3BucketAsset(BaseModel):
    __tablename__ = "s3_buckets"

    asset_id = Column(UUID(as_uuid=True), ForeignKey("cloud_assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    bucket_name = Column(String(200), nullable=False)
    arn = Column(String(300), nullable=False)
    is_public = Column(Boolean, default=False)
    encryption_enabled = Column(Boolean, default=False)
    versioning_enabled = Column(Boolean, default=False)

    asset = relationship("CloudAsset", back_populates="s3_bucket_details")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.asset_id = kwargs.get("asset_id")
        self.bucket_name = kwargs.get("bucket_name")
        self.arn = kwargs.get("arn")
        self.is_public = kwargs.get("is_public", False)
        self.encryption_enabled = kwargs.get("encryption_enabled", False)
        self.versioning_enabled = kwargs.get("versioning_enabled", False)

class EC2InstanceAsset(BaseModel):
    __tablename__ = "ec2_instances"

    asset_id = Column(UUID(as_uuid=True), ForeignKey("cloud_assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    instance_id = Column(String(100), nullable=False)
    state = Column(String(50), nullable=False)
    public_ip = Column(String(50), nullable=True)
    private_ip = Column(String(50), nullable=True)
    instance_type = Column(String(50), nullable=False)
    security_groups = Column(JSON, default=list)
    has_public_ip = Column(Boolean, default=False)

    asset = relationship("CloudAsset", back_populates="ec2_instance_details")

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

class ScanJob(BaseModel):
    __tablename__ = "scan_jobs"

    cloud_account_id = Column(UUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(50), default="queued")
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    assets_discovered = Column(Integer, default=0)
    findings_generated = Column(Integer, default=0)
    collector_status = Column(JSON, default=dict)
    error_summary = Column(String(500), nullable=True)
    region = Column(String(50), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.organization_id = kwargs.get("organization_id")
        self.status = kwargs.get("status") or ScanStatus.QUEUED.value
        self.started_at = kwargs.get("started_at")
        self.completed_at = kwargs.get("completed_at")
        self.assets_discovered = kwargs.get("assets_discovered") or 0
        self.findings_generated = kwargs.get("findings_generated") or 0
        self.collector_status = kwargs.get("collector_status") or {}
        self.error_summary = kwargs.get("error_summary")
        self.region = kwargs.get("region")

class Relationship(BaseModel):
    __tablename__ = "legacy_relationships"

    source_id = Column(String(300), nullable=False)
    target_id = Column(String(300), nullable=False)
    type = Column(String(100), nullable=False)
    target_type = Column(String(100), nullable=True)

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
    __tablename__ = "asset_relationships"

    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    cloud_account_id = Column(UUID(as_uuid=True), nullable=True)
    source_asset_id = Column(String(300), nullable=False, index=True)
    target_asset_id = Column(String(300), nullable=False, index=True)
    relationship_type = Column(String(100), nullable=False)
    account_id = Column(String(100), nullable=True)
    region = Column(String(100), nullable=True)
    evidence = Column(JSON, default=dict)
    confidence = Column(String(50), default="UNKNOWN")
    first_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

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
        self.first_seen_at = kwargs.get("first_seen_at") or datetime.now(timezone.utc)
        self.last_seen_at = kwargs.get("last_seen_at") or datetime.now(timezone.utc)

class CloudIdentity(BaseModel):
    __tablename__ = "cloud_identities"

    identity_id = Column(String(200), nullable=True)
    organization_id = Column(String(200), nullable=True)
    account_id = Column(String(200), nullable=True)
    native_id = Column(String(500), nullable=True)
    identity_type = Column(String(100), nullable=True)
    name = Column(String(200), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.identity_id = kwargs.get("identity_id")
        self.organization_id = kwargs.get("organization_id")
        self.account_id = kwargs.get("account_id")
        self.native_id = kwargs.get("native_id")
        self.identity_type = kwargs.get("identity_type")
        self.name = kwargs.get("name")
