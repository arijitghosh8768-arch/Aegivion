from app.models.cloud_account import CloudAccountV2


class CloudAccountRepository:
    def __init__(self, db):
        self.db = db

    def get_by_id(self, account_id):
        return (
            self.db.query(CloudAccountV2)
            .filter(CloudAccountV2.id == account_id)
            .first()
        )

    def get_by_organization(self, organization_id):
        return (
            self.db.query(CloudAccountV2)
            .filter(
                CloudAccountV2.organization_id == organization_id
            )
            .all()
        )

    def get_by_organization_and_id(
        self,
        organization_id,
        account_id,
    ):
        return (
            self.db.query(CloudAccountV2)
            .filter(
                CloudAccountV2.id == account_id,
                CloudAccountV2.organization_id == organization_id,
            )
            .first()
        )
