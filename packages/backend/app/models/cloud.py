import enum
from sqlalchemy import Column, String, Boolean, DateTime, Enum, ForeignKey, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
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
    __tablename__ = "cloud_accounts"

    name = Column(String(200), nullable=False)
    provider = Column(Enum(CloudProvider), nullable=False, default=CloudProvider.AWS)
    aws_access_key_id = Column(String(100), nullable=True)
    aws_secret_access_key = Column(String(100), nullable=True)
    aws_region = Column(String(50), nullable=True, default="ap-south-1")
    status = Column(Enum(CloudAccountStatus), default=CloudAccountStatus.CONNECTED)
    last_scan_at = Column(DateTime, nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)

    assets = relationship("CloudAsset", back_populates="account", cascade="all, delete-orphan")

class CloudAsset(BaseModel):
    __tablename__ = "cloud_assets"

    account_id = Column(UUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False)
    resource_id = Column(String(300), nullable=False, index=True)
    name = Column(String(300), nullable=False)
    type = Column(String(100), nullable=False, index=True)
    region = Column(String(100), nullable=True)
    provider = Column(Enum(CloudProvider), nullable=False, default=CloudProvider.AWS)
    metadata_json = Column(JSON, nullable=True)

    account = relationship("CloudAccount", back_populates="assets")
    security_group_details = relationship("SecurityGroupAsset", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    iam_user_details = relationship("IAMUserAsset", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    s3_bucket_details = relationship("S3BucketAsset", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    ec2_instance_details = relationship("EC2InstanceAsset", back_populates="asset", uselist=False, cascade="all, delete-orphan")

class SecurityGroupAsset(BaseModel):
    __tablename__ = "security_groups"

    asset_id = Column(UUID(as_uuid=True), ForeignKey("cloud_assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    group_id = Column(String(100), nullable=False)
    group_name = Column(String(200), nullable=False)
    vpc_id = Column(String(100), nullable=True)
    ingress_rules = Column(JSON, nullable=True)
    egress_rules = Column(JSON, nullable=True)

    asset = relationship("CloudAsset", back_populates="security_group_details")

class IAMUserAsset(BaseModel):
    __tablename__ = "iam_users"

    asset_id = Column(UUID(as_uuid=True), ForeignKey("cloud_assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    username = Column(String(200), nullable=False)
    arn = Column(String(300), nullable=False)
    mfa_enabled = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    access_keys_age_days = Column(Integer, nullable=True)
    last_active = Column(DateTime, nullable=True)

    asset = relationship("CloudAsset", back_populates="iam_user_details")

class S3BucketAsset(BaseModel):
    __tablename__ = "s3_buckets"

    asset_id = Column(UUID(as_uuid=True), ForeignKey("cloud_assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    bucket_name = Column(String(200), nullable=False)
    arn = Column(String(300), nullable=False)
    is_public = Column(Boolean, default=False)
    encryption_enabled = Column(Boolean, default=True)
    versioning_enabled = Column(Boolean, default=False)

    asset = relationship("CloudAsset", back_populates="s3_bucket_details")

class EC2InstanceAsset(BaseModel):
    __tablename__ = "ec2_instances"

    asset_id = Column(UUID(as_uuid=True), ForeignKey("cloud_assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    instance_id = Column(String(100), nullable=False)
    state = Column(String(50), nullable=False)
    public_ip = Column(String(50), nullable=True)
    private_ip = Column(String(50), nullable=True)
    instance_type = Column(String(50), nullable=False)
    security_groups = Column(JSON, nullable=True)
    has_public_ip = Column(Boolean, default=False)

    asset = relationship("CloudAsset", back_populates="ec2_instance_details")
