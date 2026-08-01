from sqlalchemy import Column, String, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel
from app.cloud.models import ConnectionStatus

class CloudAccountV2(BaseModel):
    __tablename__ = "cloud_accounts_v2"

    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False, default="aws")
    account_id = Column(String(100), nullable=False)
    account_name = Column(String(200), nullable=False)
    default_region = Column(String(50), nullable=False, default="ap-south-1")
    connection_status = Column(Enum(ConnectionStatus), default=ConnectionStatus.DISCONNECTED, nullable=False)
    last_sync_at = Column(DateTime, nullable=True)
    last_error = Column(String(1000), nullable=True)
