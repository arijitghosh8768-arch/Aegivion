from typing import Optional, List

from app.models.organization import Organization
from app.models.organization_member import OrganizationMember


class OrganizationRepository:
    """
    Repository for organization and membership persistence.
    """

    def __init__(self, db):
        self.db = db

    def get_organization_by_id(self, organization_id):
        return (
            self.db.query(Organization)
            .filter(Organization.id == organization_id)
            .first()
        )

    def get_organization_by_slug(self, slug):
        return (
            self.db.query(Organization)
            .filter(Organization.slug == slug)
            .first()
        )

    def get_membership(self, user_id, organization_id):
        return (
            self.db.query(OrganizationMember)
            .filter(
                OrganizationMember.user_id == user_id,
                OrganizationMember.organization_id == organization_id,
            )
            .first()
        )

    def get_memberships_by_user(self, user_id):
        return (
            self.db.query(OrganizationMember)
            .filter(OrganizationMember.user_id == user_id)
            .all()
        )

    def get_memberships_by_organization(self, organization_id):
        return (
            self.db.query(OrganizationMember)
            .filter(OrganizationMember.organization_id == organization_id)
            .all()
        )

    def get_first_organization(self):
        return self.db.query(Organization).first()

    def get_all_memberships(self):
        return self.db.query(OrganizationMember).all()

    def save(
        self,
        organization: Organization,
    ) -> Organization:
        self.db.add(organization)
        self.db.commit()
        self.db.refresh(organization)
        return organization

    def save_membership(
        self,
        membership: OrganizationMember,
    ) -> OrganizationMember:
        self.db.add(membership)
        self.db.commit()
        self.db.refresh(membership)
        return membership
