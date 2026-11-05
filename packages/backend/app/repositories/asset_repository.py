from typing import List, Optional
from app.models.cloud import CloudAsset
from app.models.cloud_account import CloudAccountV2

class AssetRepository:
    def __init__(self, db):
        self.db = db

    def get_by_organization(self, organization_id: str) -> List[CloudAsset]:
        accounts = (
            self.db.query(CloudAccountV2)
            .filter(CloudAccountV2.organization_id == organization_id)
            .all()
        )
        if not accounts:
            return []
            
        account_ids = [acc.id for acc in accounts]
        return (
            self.db.query(CloudAsset)
            .filter(CloudAsset.account_id.in_(account_ids))
            .all()
        )

    def get_by_account(self, organization_id: str, account_id: str) -> List[CloudAsset]:
        account = (
            self.db.query(CloudAccountV2)
            .filter(
                CloudAccountV2.id == account_id,
                CloudAccountV2.organization_id == organization_id
            )
            .first()
        )
        if not account:
            return []
            
        return (
            self.db.query(CloudAsset)
            .filter(CloudAsset.account_id == account.id)
            .all()
        )

    def get_by_organization_and_id(self, organization_id: str, asset_id: str) -> Optional[CloudAsset]:
        asset = (
            self.db.query(CloudAsset)
            .filter(CloudAsset.id == asset_id)
            .first()
        )
        if not asset or not asset.account_id:
            return None
            
        account = (
            self.db.query(CloudAccountV2)
            .filter(
                CloudAccountV2.id == asset.account_id,
                CloudAccountV2.organization_id == organization_id
            )
            .first()
        )
        return asset if account else None
