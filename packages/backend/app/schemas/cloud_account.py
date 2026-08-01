from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from uuid import UUID
from app.cloud.models import ConnectionStatus

class CloudAccountBase(BaseModel):
    provider: str
    account_id: str
    account_name: str
    default_region: str

class CloudAccountCreate(CloudAccountBase):
    pass

class CloudAccountUpdate(BaseModel):
    account_name: Optional[str] = None
    default_region: Optional[str] = None
    connection_status: Optional[ConnectionStatus] = None
    last_error: Optional[str] = None

class CloudAccountResponse(CloudAccountBase):
    id: UUID
    organization_id: UUID
    connection_status: ConnectionStatus
    last_sync_at: Optional[datetime] = None
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        from_attributes = True
