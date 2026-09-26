from typing import Optional

from app.models.user import User
from app.models.role import Role
from app.models.organization_member import OrganizationMember
from app.models.auth_session import AuthSession
from app.models.invitation import Invitation


class AuthRepository:
    """
    Repository for authentication-related persistence.

    Keeps authentication API logic independent from the
    underlying database implementation.
    """

    def __init__(self, db):
        self.db = db

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        return (
            self.db
            .query(User)
            .filter(User.id == user_id)
            .first()
        )

    def get_user_by_email(self, email: str) -> Optional[User]:
        return (
            self.db
            .query(User)
            .filter(User.email == email)
            .first()
        )

    def get_membership_by_user_id(
        self,
        user_id: str,
    ) -> Optional[OrganizationMember]:
        return (
            self.db
            .query(OrganizationMember)
            .filter(
                OrganizationMember.user_id == user_id
            )
            .first()
        )

    def get_role_by_id(
        self,
        role_id: str,
    ) -> Optional[Role]:
        return (
            self.db
            .query(Role)
            .filter(Role.id == role_id)
            .first()
        )

    def get_session_by_token_hash(
        self,
        token_hash: str,
    ) -> Optional[AuthSession]:
        return (
            self.db
            .query(AuthSession)
            .filter(
                AuthSession.session_token_hash == token_hash
            )
            .first()
        )

    def save_user(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def save_session(self, session: AuthSession) -> AuthSession:
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def get_users(self):
        return self.db.query(User).all()

    def get_roles(self):
        return self.db.query(Role).all()

    def get_pending_invitation_by_email(
        self,
        email: str,
    ) -> Optional[Invitation]:
        invitations = self.db.query(Invitation).all()

        from datetime import datetime

        for invitation in invitations:
            if invitation.email.lower() != email.lower():
                continue

            if invitation.status != "PENDING":
                continue

            expires_at = invitation.expires_at

            try:
                if isinstance(expires_at, datetime):
                    if expires_at > datetime.utcnow():
                        return invitation

                elif isinstance(expires_at, str):
                    if datetime.fromisoformat(expires_at) > datetime.utcnow():
                        return invitation

            except (ValueError, TypeError):
                continue

        return None
