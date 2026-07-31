from pydantic import BaseModel
from typing import Optional

class FindingType(BaseModel):
    finding_id: str
    title: str
    severity: str
    resource_id: str
    resource_type: str
    cloud_provider: str
    description: str
    remediation: Optional[str] = None
