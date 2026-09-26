from app.models.cloud import CloudAsset
from app.models.cloud_account import CloudAccountV2

class AssetRepository:
    def __init__(self, db):
        self.db = db

    def get_by_organization(self, organization_id):
        accounts = (
            self.db.query(CloudAccountV2)
            .filter(CloudAccountV2.organization_id == organization_id)
            .all()
        )
        if not accounts:
            return []
            
        account_ids = [str(acc.id) for acc in accounts]
        
        all_assets = self.db.query(CloudAsset).all()
        return [a for a in all_assets if str(a.account_id) in account_ids]

    def get_by_account(self, organization_id, account_id):
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
            
        all_assets = self.db.query(CloudAsset).all()
        return [a for a in all_assets if str(a.account_id) == str(account_id)]

    def get_by_organization_and_id(self, organization_id, asset_id):
        asset = (
            self.db.query(CloudAsset)
            .filter(CloudAsset.id == asset_id)
            .first()
        )
        if not asset:
            return None
            
        account = (
            self.db.query(CloudAccountV2)
            .filter(
                CloudAccountV2.id == str(asset.account_id),
                CloudAccountV2.organization_id == organization_id
            )
            .first()
        )
        if not account:
            return None
            
        return asset
