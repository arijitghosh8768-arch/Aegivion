class SecurityEventRepository:
    def __init__(self, db_client):
        # Taking the supabase client instead of SQLAlchemy/MongoSQL db session
        # because there is no SecurityEvent model in SQLAlchemy/MongoSQL.
        self.db_client = db_client

    def get_recent_by_organization(self, organization_id: str, limit: int = 50):
        try:
            result = self.db_client.table("security_events").select("*").eq("organization_id", str(organization_id)).order('event_timestamp', desc=True).limit(limit).execute()
            return result.data if result.data else []
        except Exception as e:
            return []
