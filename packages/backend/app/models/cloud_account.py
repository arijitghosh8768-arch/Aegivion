from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel
from app.cloud.models import ConnectionStatus

class CloudAccountV2(BaseModel):
    __tablename__ = "cloud_accounts_v2"

    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(50), nullable=False, default="aws")
    account_id = Column(String(100), nullable=False)
    account_name = Column(String(200), nullable=True)
    name = Column(String(200), nullable=True)
    default_region = Column(String(50), default="ap-south-1")
    connection_status = Column(String(50), default="disconnected")
    role_arn = Column(String(300), nullable=True)
    external_id = Column(String(100), nullable=True)
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(String, nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.provider = kwargs.get("provider") or "aws"
        self.account_id = kwargs.get("account_id") or kwargs.get("id")
        self.account_name = kwargs.get("account_name") or kwargs.get("name")
        self.name = self.account_name
        self.default_region = kwargs.get("default_region") or "ap-south-1"
        self.connection_status = kwargs.get("connection_status") or ConnectionStatus.DISCONNECTED
        self.role_arn = kwargs.get("role_arn")
        self.external_id = kwargs.get("external_id")
        self.last_sync_at = kwargs.get("last_sync_at")
        self.last_error = kwargs.get("last_error")
