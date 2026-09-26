from typing import List, Optional
from app.models.invitation import Invitation

class InvitationRepository:
    def __init__(self, db):
        self.db = db

    def get_by_id(self, invitation_id: str) -> Optional[Invitation]:
        return self.db.query(Invitation).filter(Invitation.id == invitation_id).first()

    def get_by_organization(self, organization_id: str) -> List[Invitation]:
        return self.db.query(Invitation).filter(Invitation.org_id == organization_id).all()

    def get_by_organization_and_id(self, organization_id: str, invitation_id: str) -> Optional[Invitation]:
        invitation = self.get_by_id(invitation_id)
        if not invitation:
            return None
        if str(invitation.org_id) != str(organization_id):
            return None
        return invitation

    def get_by_token(self, token: str) -> Optional[Invitation]:
        return self.db.query(Invitation).filter(Invitation.token == token).first()
