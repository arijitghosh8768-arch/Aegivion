from typing import List, Optional
from app.models.compliance import ComplianceControlResult

class ComplianceRepository:
    def __init__(self, db):
        self.db = db

    def get_by_organization(self, organization_id: str) -> List[ComplianceControlResult]:
        return self.db.query(ComplianceControlResult).filter(ComplianceControlResult.organization_id == organization_id).all()

    def get_by_control_code(self, organization_id: str, control_code: str) -> Optional[ComplianceControlResult]:
        return self.db.query(ComplianceControlResult).filter(
            ComplianceControlResult.control_code == control_code,
            ComplianceControlResult.organization_id == organization_id
        ).first()
