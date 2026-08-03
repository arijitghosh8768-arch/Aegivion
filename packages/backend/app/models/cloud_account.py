from datetime import datetime
from app.database.base import BaseModel
from app.cloud.models import ConnectionStatus

class CloudAccountV2(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.provider = kwargs.get("provider") or "aws"
        self.account_id = kwargs.get("account_id")
        self.account_name = kwargs.get("account_name")
        self.default_region = kwargs.get("default_region") or "ap-south-1"
        self.connection_status = kwargs.get("connection_status") or ConnectionStatus.DISCONNECTED
        self.last_sync_at = kwargs.get("last_sync_at")
        self.last_error = kwargs.get("last_error")

    def dict(self):
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "provider": self.provider,
            "account_id": self.account_id,
            "account_name": self.account_name,
            "default_region": self.default_region,
            "connection_status": self.connection_status,
            "last_sync_at": self.last_sync_at.isoformat() if isinstance(self.last_sync_at, datetime) else self.last_sync_at,
            "last_error": self.last_error
        })
        return res

