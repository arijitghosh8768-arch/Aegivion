from app.models.incident import Incident
from typing import List, Optional

class IncidentRepository:
    def __init__(self, db):
        self.db = db

    def get_by_organization(self, organization_id: str) -> List[Incident]:
        all_incidents = self.db.query(Incident).all()
        return [i for i in all_incidents if str(i.organization_id) == str(organization_id)]

    def get_by_id(self, incident_id: str) -> Optional[Incident]:
        inc = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not inc:
            inc = self.db.query(Incident).filter(Incident.correlation_fingerprint == incident_id).first()
            
        if not inc:
            all_inc = self.db.query(Incident).all()
            inc = next((x for x in all_inc if str(x.id) == incident_id or x.correlation_fingerprint == incident_id), None)
            
        return inc

    def get_by_organization_and_id(self, organization_id: str, incident_id: str) -> Optional[Incident]:
        inc = self.get_by_id(incident_id)
        if not inc:
            return None
            
        if str(inc.organization_id) != str(organization_id):
            return None
            
        return inc
