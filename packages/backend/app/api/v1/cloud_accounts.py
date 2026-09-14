from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from uuid import UUID

from app.database import get_db
from app.models.cloud_account import CloudAccountV2 as CloudAccount
from app.cloud.models import ConnectionStatus
from app.cloud.aws.adapter import AWSProvider
from app.core.security import get_current_user
from app.api.deps import require_permission, log_audit_action

router = APIRouter()

class AWSTestRequest(BaseModel):
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: Optional[str] = "ap-south-1"

class AWSTestResponse(BaseModel):
    connected: bool
    provider: str
    account_id: Optional[str] = None
    region: Optional[str] = None
    status: str

class CloudAccountCreateRequest(BaseModel):
    account_name: str
    provider: str
    account_id: str
    default_region: str
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None

@router.post("/aws/test", response_model=AWSTestResponse)
@require_permission("manage_integrations")
def test_aws_connection(payload: AWSTestRequest, current_user: Dict[str, Any] = Depends(get_current_user)):

    provider = AWSProvider(
        access_key=payload.aws_access_key_id,
        secret_key=payload.aws_secret_access_key,
        default_region=payload.aws_region
    )
    

    org_id = current_user.get("organization_id")
    log_audit_action("test_aws_connection", "cloud_account", "aws", str(current_user.get("id", "system")), str(org_id), {})
    if provider.validate_connection():
        info = provider.get_account_info()
        return AWSTestResponse(
            connected=True,
            provider="aws",
            account_id=info.get("account_id"),
            region=payload.aws_region,
            status="connected"
        )
    else:
        return AWSTestResponse(
            connected=False,
            provider="aws",
            status="authentication_failed"
        )

@router.post("")
@router.post("/", status_code=status.HTTP_201_CREATED)
@require_permission("manage_integrations")
def create_cloud_account(
    payload: CloudAccountCreateRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    org_id = current_user.get("organization_id")
    # For MVP safety, verify connectivity first
    provider = AWSProvider(
        access_key=payload.aws_access_key_id,
        secret_key=payload.aws_secret_access_key,
        default_region=payload.default_region
    )
    
    conn_status = ConnectionStatus.CONNECTED if provider.validate_connection() else ConnectionStatus.FAILED
    
    new_account = CloudAccount(
        organization_id=UUID(org_id),
        provider=payload.provider,
        account_id=payload.account_id,
        account_name=payload.account_name,
        default_region=payload.default_region,
        connection_status=conn_status
    )
    

    db.add(new_account)
    db.commit()
    db.refresh(new_account)
    
    log_audit_action("create_cloud_account", "cloud_account", str(new_account.id), str(current_user.get("id", "system")), str(org_id), {"provider": payload.provider, "account_id": payload.account_id})
    
    return {
        "success": True,
        "data": {
            "id": str(new_account.id),
            "account_name": new_account.account_name,
            "provider": new_account.provider,
            "account_id": new_account.account_id,
            "connection_status": new_account.connection_status
        }
    }

@router.get("")
@router.get("/")
def list_cloud_accounts(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    org_id = current_user.get("organization_id")
    accounts = db.query(CloudAccount).filter(CloudAccount.organization_id == UUID(org_id)).all()
    
    return {
        "success": True,
        "data": [
            {
                "id": str(acc.id),
                "account_name": acc.account_name,
                "provider": acc.provider,
                "account_id": acc.account_id,
                "connection_status": acc.connection_status.value if hasattr(acc.connection_status, 'value') else str(acc.connection_status),
                "default_region": acc.default_region
            } for acc in accounts
        ]
    }
