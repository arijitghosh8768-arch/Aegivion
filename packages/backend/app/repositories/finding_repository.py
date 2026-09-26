from security.models.finding import Finding
from app.models.cloud import CloudAsset
from app.models.cloud_account import CloudAccountV2
import uuid

class FindingRepository:
    def __init__(self, db):
        self.db = db

    def _get_org_resource_ids(self, organization_id):
        accounts = (
            self.db.query(CloudAccountV2)
            .filter(CloudAccountV2.organization_id == organization_id)
            .all()
        )
        if not accounts:
            return []
            
        account_ids = [str(acc.id) for acc in accounts]
        
        all_assets = self.db.query(CloudAsset).all()
        org_assets = [a for a in all_assets if str(a.account_id) in account_ids]
        
        return [a.resource_id for a in org_assets]

    def get_by_id(self, finding_id):
        try:
            uid = uuid.UUID(finding_id)
            f = self.db.query(Finding).filter(Finding.id == uid).first()
            if f: return f
        except Exception:
            pass
            
        f = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if f: return f
        
        all_f = self.db.query(Finding).all()
        return next((x for x in all_f if str(x.id) == finding_id), None)

    def get_by_organization(self, organization_id):
        resource_ids = self._get_org_resource_ids(organization_id)
        if not resource_ids:
            return []
            
        all_findings = self.db.query(Finding).all()
        
        # If finding object happens to have organization_id due to kwargs, we can use it as well
        return [
            f for f in all_findings 
            if f.resource_id in resource_ids or str(getattr(f, 'organization_id', '')) == str(organization_id)
        ]

    def get_by_organization_and_id(self, organization_id, finding_id):
        f = self.get_by_id(finding_id)
        if not f:
            return None
            
        if str(getattr(f, 'organization_id', '')) == str(organization_id):
            return f
            
        resource_ids = self._get_org_resource_ids(organization_id)
        if f.resource_id in resource_ids:
            return f
            
        return None

    def get_by_asset(self, organization_id, asset_id):
        # asset_id in finding context maps to resource_id
        resource_ids = self._get_org_resource_ids(organization_id)
        if asset_id not in resource_ids:
            return []
            
        all_findings = self.db.query(Finding).all()
        return [f for f in all_findings if f.resource_id == asset_id]
