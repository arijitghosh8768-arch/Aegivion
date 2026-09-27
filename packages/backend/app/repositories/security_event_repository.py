from typing import Dict, Any, List, Optional
from app.models.security_event import SecurityEvent

class SecurityEventRepository:
    def __init__(self, db_client):
        self.db_client = db_client
        self.table = self.db_client.table("security_events")

    def create(self, event: SecurityEvent) -> SecurityEvent:
        insert_data = event.dict()
        self.table.insert(insert_data).execute()
        return event

    def get_by_fingerprint(self, organization_id: str, fingerprint: str) -> Optional[SecurityEvent]:
        res = self.table.select("*").eq("organization_id", organization_id).eq("event_fingerprint", fingerprint).execute()
        if res.data:
            return SecurityEvent(**res.data[0])
        return None

    def check_duplicate(self, organization_id: str, fingerprint: str) -> bool:
        return self.get_by_fingerprint(organization_id, fingerprint) is not None

    def get_recent_by_organization(self, organization_id: str, limit: int = 50) -> List[SecurityEvent]:
        res = self.table.select("*").eq("organization_id", organization_id).order('timestamp', desc=True).limit(limit).execute()
        return [SecurityEvent(**item) for item in res.data] if res.data else []
